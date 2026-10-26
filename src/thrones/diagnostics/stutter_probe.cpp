// src/thrones/stutter_probe.cpp
//
// DIAGNOSTIC ONLY, remove before release.
// Logs frame-time spikes together with how often the engine's shared heap lock was
// entered during that frame. Answers: "do HUD stutter frames come with allocation bursts?"
//
//  Frame timing : MinHook on IDXGISwapChain::Present (vtable slot 8, read from a dummy
//                 swapchain created once at install).
//  Heap counter : E8 call-site patches on the two hot callers of the heap lock spin loop
//                 (Very Sleepy, 26 Oct: loop at +A0B3, callers return to +B022 and +B672).
//                 The sites are found by scanning, so no base address is needed. Both
//                 calls must target the same function, which must start shortly before
//                 the loop, otherwise nothing is patched.
//  Sampler      : during frames longer than 18 ms, a background thread samples the Present
//                 thread (EIP + return addresses on its stack). Only spike frames are kept.
//  File I/O     : ntdll file syscalls made on the Present thread, per path, with time spent.
//  Exceptions   : vectored handler counting exceptions on the Present thread (C++ type, message,
//                 throw site). Never handles them.
//  Debug output : hooks OutputDebugStringA/W, counts messages per text; Pause key mutes them.
//  Restored in uninstall_stutter_probe() (the DLL unloads between campaigns).

#include "../common/log.h"
#include <windows.h>
#include <winternl.h>
#include <d3d11.h>
#include <dxgi.h>
#include <MinHook.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "d3d11.lib")

static constexpr uintptr_t GH = 0x10000000; // Ghidra image base

// Low 16 bits survive ASLR (DLLs load on 64 KB boundaries).
static constexpr uintptr_t LO_LOOP = 0xA0B3;          // spin loop
static constexpr uintptr_t LO_RET_A = 0xB022;         // return address after CALL lock (site A)
static constexpr uintptr_t LO_RET_B = 0xB672;         // return address after CALL lock (site B)
static constexpr uintptr_t MAX_ENTRY_TO_LOOP = 0x1000; // lock fn entry must be this close before loop

static constexpr double SPIKE_MIN_MS = 25.0; // a spike is > max(SPIKE_MIN_MS, SPIKE_FACTOR * avg)
static constexpr double SPIKE_FACTOR = 2.0;
static constexpr double WINDOW_S = 5.0; // summary interval
static constexpr int MAX_SPIKES_PER_WINDOW = 32;

// ---------------------------------------------------------------------------
// Heap lock call counters
// ---------------------------------------------------------------------------
struct ProbeSite {
    const char *name;
    uintptr_t call; // address of the E8 byte
    int32_t orig_rel;
    bool active;
};
static ProbeSite g_sites[2] = {{"A", 0, 0, false}, {"B", 0, 0, false}};
static uintptr_t g_base = 0;
static uintptr_t g_lock_fn = 0; // jump target of both thunks
static volatile LONG g_cnt_a = 0;
static volatile LONG g_cnt_b = 0;

// Count, then tail-jump into the original. Stack, registers and return address untouched,
// so the calling convention does not matter. (lock inc only changes EFLAGS.)
static __declspec(naked) void thunk_a() {
    __asm {
        lock inc dword ptr [g_cnt_a]
        jmp dword ptr [g_lock_fn]
    }
}
static __declspec(naked) void thunk_b() {
    __asm {
        lock inc dword ptr [g_cnt_b]
        jmp dword ptr [g_lock_fn]
    }
}

static bool read_e8(uintptr_t at, uintptr_t *target) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(at);
    if (p[0] != 0xE8)
        return false;
    *target = at + 5 + *reinterpret_cast<const int32_t *>(p + 1);
    return true;
}

static bool write_rel(uintptr_t call, int32_t rel) {
    void *p = reinterpret_cast<void *>(call + 1);
    DWORD old;
    if (!VirtualProtect(p, 4, PAGE_EXECUTE_READWRITE, &old))
        return false;
    *reinterpret_cast<volatile int32_t *>(p) = rel; // does not cross a cache line at these offsets
    VirtualProtect(p, 4, old, &old);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(call), 5);
    return true;
}

static unsigned gh(uintptr_t a) { return static_cast<unsigned>(a - g_base + GH); }

// Scan every 64 KB block of the executable sections for the A/B call pair.
static bool locate_sites() {
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(g_base);
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(g_base + dos->e_lfanew);
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    int found = 0;
    uintptr_t ca = 0, cb = 0, fn = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        const uintptr_t lo = g_base + sec->VirtualAddress;
        const uintptr_t hi = lo + sec->Misc.VirtualSize;
        for (uintptr_t blk = lo & ~uintptr_t(0xFFFF); blk < hi; blk += 0x10000) {
            const uintptr_t a = blk + LO_RET_A - 5;
            const uintptr_t b = blk + LO_RET_B - 5;
            const uintptr_t loop = blk + LO_LOOP;
            if (a < lo || b + 5 > hi)
                continue;
            uintptr_t ta, tb;
            if (!read_e8(a, &ta) || !read_e8(b, &tb) || ta != tb)
                continue;
            if (ta < lo || ta > loop || loop - ta > MAX_ENTRY_TO_LOOP)
                continue;
            ++found;
            ca = a;
            cb = b;
            fn = ta;
        }
    }
    if (found != 1) {
        Log("[twdll] [STUTTER_PROBE] heap lock call sites: %d matches (need exactly 1), counters off",
            found);
        return false;
    }
    g_lock_fn = fn;
    g_sites[0].call = ca;
    g_sites[1].call = cb;
    Log("[twdll] [STUTTER_PROBE] heap lock fn %08X (Ghidra), call A %08X, call B %08X, loop %08X",
        gh(fn), gh(ca), gh(cb), gh((ca & ~uintptr_t(0xFFFF)) + LO_LOOP));
    return true;
}

static void patch_sites() {
    void *thunks[2] = {reinterpret_cast<void *>(&thunk_a), reinterpret_cast<void *>(&thunk_b)};
    for (int i = 0; i < 2; ++i) {
        ProbeSite &s = g_sites[i];
        s.orig_rel = *reinterpret_cast<const int32_t *>(s.call + 1);
        const int32_t nrel =
            static_cast<int32_t>(reinterpret_cast<uintptr_t>(thunks[i]) - (s.call + 5));
        s.active = write_rel(s.call, nrel);
        Log("[twdll] [STUTTER_PROBE] site %s %s", s.name, s.active ? "patched" : "FAILED");
    }
}

// ---------------------------------------------------------------------------
// Frame timing (Present hook)
// ---------------------------------------------------------------------------
typedef HRESULT(__stdcall *Present_t)(IDXGISwapChain *, UINT, UINT);
static void *g_present_target = nullptr;
static Present_t g_orig_present = nullptr;

static LARGE_INTEGER g_freq = {};
static LONGLONG g_t0 = 0, g_last = 0, g_win_start = 0;
static bool g_first_present_logged = false;
static bool g_k_down = false;

struct Window {
    long frames, spikes;
    double sum_ms, max_ms;
    double ops_normal, ms_normal; // heap ops and time in non-spike frames
    double ops_spike, ms_spike;   // same for spike frames
};
static Window g_win = {};
static double g_avg_ms = 16.7;     // previous window's average frame time
static double g_base_rate = 0.0;   // previous window's ops per ms in normal frames

struct SpikeRec {
    double t, ms;
    long a, b;
};
static SpikeRec g_spk[MAX_SPIKES_PER_WINDOW];
static int g_nspk = 0;
static int g_nspk_dropped = 0;
static double g_k_times[16];
static int g_nk = 0;

static double ms_between(LONGLONG a, LONGLONG b) {
    return static_cast<double>(b - a) * 1000.0 / static_cast<double>(g_freq.QuadPart);
}

// ---------------------------------------------------------------------------
// File I/O probe
// MinHook on the ntdll file syscalls. Calls made on the Present thread are recorded
// per path (calls, failures, time spent). Other threads pass straight through.
// The Present thread is also the only reader/writer of the table (flush_window runs
// there), so no lock is needed and nothing is allocated inside the hooks.
// ---------------------------------------------------------------------------
static constexpr int IO_MAX = 96;
static constexpr int IO_PATH = 200;
static constexpr int IO_TOP = 6;

struct IoRec {
    char op; // C create, O open, A attributes, F full attributes, D directory query
    int len; // chars
    wchar_t path[IO_PATH];
    long calls, fails;
    LONGLONG ticks;
    LONG last_status;
};
static IoRec g_io[IO_MAX];
static int g_nio = 0;
static long g_io_dropped = 0;
static long g_read_calls = 0;
static LONGLONG g_read_bytes = 0, g_read_ticks = 0;
static volatile DWORD g_target_tid = 0;

static void io_record(char op, const UNICODE_STRING *name, bool relative, LONG status,
                      LONGLONG ticks) {
    int len = (name && name->Buffer) ? name->Length / 2 : 0;
    if (len > IO_PATH - 1)
        len = IO_PATH - 1;
    const wchar_t *src = len ? name->Buffer : L"";
    const char key = relative ? static_cast<char>(op + 32) : op; // lower case = relative to a handle
    for (int i = 0; i < g_nio; ++i) {
        IoRec &r = g_io[i];
        if (r.op == key && r.len == len && wmemcmp(r.path, src, len) == 0) {
            ++r.calls;
            if (status < 0)
                ++r.fails;
            r.ticks += ticks;
            r.last_status = status;
            return;
        }
    }
    if (g_nio >= IO_MAX) {
        ++g_io_dropped;
        return;
    }
    IoRec &r = g_io[g_nio++];
    r.op = key;
    r.len = len;
    wmemcpy(r.path, src, len);
    r.path[len] = 0;
    r.calls = 1;
    r.fails = status < 0 ? 1 : 0;
    r.ticks = ticks;
    r.last_status = status;
}

static inline bool on_target() { return GetCurrentThreadId() == g_target_tid; }
static inline LONGLONG qpc_now() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return t.QuadPart;
}

typedef LONG(NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef LONG(NTAPI *NtOpenFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                  ULONG, ULONG);
typedef LONG(NTAPI *NtQueryAttr_t)(POBJECT_ATTRIBUTES, PVOID);
typedef LONG(NTAPI *NtReadFile_t)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
                                  PLARGE_INTEGER, PULONG);
typedef LONG(NTAPI *NtQueryDir_t)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
                                  ULONG, BOOLEAN, PUNICODE_STRING, BOOLEAN);

static NtCreateFile_t o_create = nullptr;
static NtOpenFile_t o_open = nullptr;
static NtQueryAttr_t o_attr = nullptr;
static NtQueryAttr_t o_fattr = nullptr;
static NtReadFile_t o_read = nullptr;
static NtQueryDir_t o_dir = nullptr;

static LONG NTAPI hk_create(PHANDLE h, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK io,
                            PLARGE_INTEGER sz, ULONG fa, ULONG sh, ULONG disp, ULONG opt, PVOID ea,
                            ULONG eal) {
    if (!on_target())
        return o_create(h, a, oa, io, sz, fa, sh, disp, opt, ea, eal);
    const LONGLONG t = qpc_now();
    const LONG st = o_create(h, a, oa, io, sz, fa, sh, disp, opt, ea, eal);
    io_record('C', oa ? oa->ObjectName : nullptr, oa && oa->RootDirectory, st, qpc_now() - t);
    return st;
}
static LONG NTAPI hk_open(PHANDLE h, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK io,
                          ULONG sh, ULONG opt) {
    if (!on_target())
        return o_open(h, a, oa, io, sh, opt);
    const LONGLONG t = qpc_now();
    const LONG st = o_open(h, a, oa, io, sh, opt);
    io_record('O', oa ? oa->ObjectName : nullptr, oa && oa->RootDirectory, st, qpc_now() - t);
    return st;
}
static LONG NTAPI hk_attr(POBJECT_ATTRIBUTES oa, PVOID info) {
    if (!on_target())
        return o_attr(oa, info);
    const LONGLONG t = qpc_now();
    const LONG st = o_attr(oa, info);
    io_record('A', oa ? oa->ObjectName : nullptr, oa && oa->RootDirectory, st, qpc_now() - t);
    return st;
}
static LONG NTAPI hk_fattr(POBJECT_ATTRIBUTES oa, PVOID info) {
    if (!on_target())
        return o_fattr(oa, info);
    const LONGLONG t = qpc_now();
    const LONG st = o_fattr(oa, info);
    io_record('F', oa ? oa->ObjectName : nullptr, oa && oa->RootDirectory, st, qpc_now() - t);
    return st;
}
static LONG NTAPI hk_read(HANDLE h, HANDLE ev, PVOID apc, PVOID ctx, PIO_STATUS_BLOCK io, PVOID buf,
                          ULONG len, PLARGE_INTEGER off, PULONG key) {
    if (!on_target())
        return o_read(h, ev, apc, ctx, io, buf, len, off, key);
    const LONGLONG t = qpc_now();
    const LONG st = o_read(h, ev, apc, ctx, io, buf, len, off, key);
    ++g_read_calls;
    g_read_bytes += len;
    g_read_ticks += qpc_now() - t;
    return st;
}
static LONG NTAPI hk_dir(HANDLE h, HANDLE ev, PVOID apc, PVOID ctx, PIO_STATUS_BLOCK io, PVOID info,
                         ULONG len, ULONG cls, BOOLEAN single, PUNICODE_STRING name, BOOLEAN restart) {
    if (!on_target())
        return o_dir(h, ev, apc, ctx, io, info, len, cls, single, name, restart);
    const LONGLONG t = qpc_now();
    const LONG st = o_dir(h, ev, apc, ctx, io, info, len, cls, single, name, restart);
    io_record('D', name, false, st, qpc_now() - t);
    return st;
}

struct IoHook {
    const char *name;
    void *detour;
    void **orig;
    void *target;
};
static IoHook g_io_hooks[] = {
    {"NtCreateFile", reinterpret_cast<void *>(&hk_create), reinterpret_cast<void **>(&o_create), nullptr},
    {"NtOpenFile", reinterpret_cast<void *>(&hk_open), reinterpret_cast<void **>(&o_open), nullptr},
    {"NtQueryAttributesFile", reinterpret_cast<void *>(&hk_attr), reinterpret_cast<void **>(&o_attr), nullptr},
    {"NtQueryFullAttributesFile", reinterpret_cast<void *>(&hk_fattr), reinterpret_cast<void **>(&o_fattr), nullptr},
    {"NtReadFile", reinterpret_cast<void *>(&hk_read), reinterpret_cast<void **>(&o_read), nullptr},
    {"NtQueryDirectoryFile", reinterpret_cast<void *>(&hk_dir), reinterpret_cast<void **>(&o_dir), nullptr},
};

static void io_install() {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    g_nio = 0;
    g_io_dropped = 0;
    g_read_calls = 0;
    g_read_bytes = g_read_ticks = 0;
    int ok = 0;
    for (IoHook &h : g_io_hooks) {
        void *p = nt ? reinterpret_cast<void *>(GetProcAddress(nt, h.name)) : nullptr;
        MH_STATUS st = p ? MH_CreateHook(p, h.detour, h.orig) : MH_ERROR_FUNCTION_NOT_FOUND;
        if (st == MH_OK)
            st = MH_EnableHook(p);
        if (st == MH_OK) {
            h.target = p;
            ++ok;
        } else {
            Log("[twdll] [STUTTER_PROBE] io hook %s FAILED (%d)", h.name, st);
        }
    }
    Log("[twdll] [STUTTER_PROBE] io hooks %d/%d", ok, static_cast<int>(sizeof(g_io_hooks) / sizeof(g_io_hooks[0])));
}

static void io_uninstall() {
    for (IoHook &h : g_io_hooks) {
        if (!h.target)
            continue;
        MH_DisableHook(h.target);
        MH_RemoveHook(h.target);
        h.target = nullptr;
    }
}

// Called from flush_window on the Present thread.
static void io_report() {
    const double tick_ms = 1000.0 / static_cast<double>(g_freq.QuadPart);
    long total = 0;
    for (int i = 0; i < g_nio; ++i)
        total += g_io[i].calls;
    Log("[twdll] [STUTTER_PROBE]   IO on Present thread: %ld path calls (%d distinct%s), "
        "NtReadFile %ld calls %.1f KB %.1f ms",
        total, g_nio, g_io_dropped ? ", table full" : "", g_read_calls, g_read_bytes / 1024.0,
        g_read_ticks * tick_ms);
    for (int r = 0; r < IO_TOP; ++r) {
        int best = -1;
        for (int i = 0; i < g_nio; ++i)
            if (g_io[i].calls > 0 && (best < 0 || g_io[i].ticks > g_io[best].ticks))
                best = i;
        if (best < 0)
            break;
        IoRec &x = g_io[best];
        char path[IO_PATH * 3];
        const int n = WideCharToMultiByte(CP_UTF8, 0, x.path, x.len, path, sizeof(path) - 1, nullptr,
                                          nullptr);
        path[n > 0 ? n : 0] = 0;
        Log("[twdll] [STUTTER_PROBE]     %c %4ld calls %4ld fail %7.2f ms  st %08lX  %s", x.op,
            x.calls, x.fails, x.ticks * tick_ms, static_cast<unsigned long>(x.last_status), path);
        x.calls = -x.calls; // printed
    }
    g_nio = 0;
    g_io_dropped = 0;
    g_read_calls = 0;
    g_read_bytes = g_read_ticks = 0;
}

// Nearest exported name at or below a, for system DLL addresses in the sampler output.
static const char *nearest_export(HMODULE hm, uintptr_t a, unsigned *off) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(hm);
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY &dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd.VirtualAddress)
        return nullptr;
    const auto *ex = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(base + dd.VirtualAddress);
    const DWORD *names = reinterpret_cast<const DWORD *>(base + ex->AddressOfNames);
    const WORD *ords = reinterpret_cast<const WORD *>(base + ex->AddressOfNameOrdinals);
    const DWORD *funcs = reinterpret_cast<const DWORD *>(base + ex->AddressOfFunctions);
    const uintptr_t rva = a - base;
    const char *best = nullptr;
    DWORD best_rva = 0;
    for (DWORD i = 0; i < ex->NumberOfNames; ++i) {
        const DWORD f = funcs[ords[i]];
        if (f <= rva && f >= best_rva) {
            best_rva = f;
            best = reinterpret_cast<const char *>(base + names[i]);
        }
    }
    if (best)
        *off = static_cast<unsigned>(rva - best_rva);
    return best;
}

// ---------------------------------------------------------------------------
// Spike sampler
// A background thread watches the Present thread. Once the current frame has run
// longer than SAMPLE_AFTER_MS it suspends that thread about every 1 ms and records
// EIP plus the return addresses into empire.retail.dll found on its stack. Samples
// are kept only if the frame turns out to be a spike (>= COMMIT_MS).
// While the target is suspended the sampler takes no locks and allocates nothing.
// ---------------------------------------------------------------------------
static constexpr double SAMPLE_AFTER_MS = 18.0;
static constexpr LONG COMMIT_US = 40000; // frame must last >= 40 ms for its samples to count
static constexpr int MAX_RET = 16;       // return addresses kept per sample
static constexpr int MAX_PENDING = 256;  // samples per frame
static constexpr int HIST_SIZE = 2048;
static constexpr int TOP_N = 12;

struct Sample {
    uintptr_t eip;
    int n;
    uintptr_t ret[MAX_RET];
};
struct Hist {
    int n;
    uintptr_t addr[HIST_SIZE];
    long cnt[HIST_SIZE];
};

static uintptr_t g_size = 0;                 // SizeOfImage of empire.retail.dll
static uintptr_t g_text_lo = 0, g_text_hi = 0; // executable range of empire.retail.dll
static volatile LONG g_frame_no = 0;
static volatile LONG g_frame_start_lo = 0;   // low 32 bits of QPC at frame start
static volatile LONG g_last_frame_us = 0;    // duration of the frame that just ended
static HANDLE g_target = nullptr;            // Present thread
static HANDLE g_sampler = nullptr;
static volatile LONG g_sampler_run = 0;

static CRITICAL_SECTION g_cs;
static bool g_cs_init = false;
static Hist g_h_eip, g_h_ret;   // filled by sampler under g_cs
static Hist s_eip, s_ret;       // copies used by the report
static long g_smp_frames = 0, g_smp_samples = 0;
static Sample g_examples[2];
static int g_nexamples = 0;
static Sample s_pending[MAX_PENDING];
static int s_npending = 0;
static uint32_t s_stack[1024];

static void hist_add(Hist &h, uintptr_t a) {
    for (int i = 0; i < h.n; ++i) {
        if (h.addr[i] == a) {
            ++h.cnt[i];
            return;
        }
    }
    if (h.n < HIST_SIZE) {
        h.addr[h.n] = a;
        h.cnt[h.n] = 1;
        ++h.n;
    }
}

// v is a plausible return address if the bytes before it decode as a CALL.
static bool is_ret_addr(uintptr_t v) {
    if (v < g_text_lo + 8 || v >= g_text_hi)
        return false;
    const uint8_t *p = reinterpret_cast<const uint8_t *>(v);
    if (p[-5] == 0xE8)
        return true; // call rel32
    if (p[-2] == 0xFF && ((p[-1] >> 3) & 7) == 2)
        return true; // call reg / [reg]
    if (p[-3] == 0xFF && ((p[-2] >> 3) & 7) == 2)
        return true; // call [reg+disp8]
    if (p[-6] == 0xFF && ((p[-5] >> 3) & 7) == 2)
        return true; // call [disp32] / [reg+disp32]
    if (p[-7] == 0xFF && ((p[-6] >> 3) & 7) == 2)
        return true; // call [sib+disp32]
    if (p[-4] == 0xFF && ((p[-3] >> 3) & 7) == 2)
        return true; // call [sib+disp8]
    return false;
}

static bool take_sample(Sample &s) {
    if (SuspendThread(g_target) == static_cast<DWORD>(-1))
        return false;
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    const bool ok = GetThreadContext(g_target, &ctx) != 0;
    SIZE_T got = 0;
    if (ok) {
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void *>(ctx.Esp), s_stack,
                               sizeof(s_stack), &got))
            ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void *>(ctx.Esp), s_stack, 1024,
                              &got);
    }
    ResumeThread(g_target);
    if (!ok)
        return false;

    s.eip = ctx.Eip;
    s.n = 0;
    const size_t words = got / 4;
    for (size_t i = 0; i < words && s.n < MAX_RET; ++i) {
        const uintptr_t v = s_stack[i];
        if (is_ret_addr(v))
            s.ret[s.n++] = v;
    }
    return true;
}

static void commit_pending() {
    EnterCriticalSection(&g_cs);
    ++g_smp_frames;
    for (int i = 0; i < s_npending; ++i) {
        const Sample &s = s_pending[i];
        hist_add(g_h_eip, s.eip);
        for (int j = 0; j < s.n; ++j) {
            bool dup = false;
            for (int k = 0; k < j; ++k)
                dup = dup || (s.ret[k] == s.ret[j]);
            if (!dup)
                hist_add(g_h_ret, s.ret[j]); // counted once per sample (inclusive)
        }
        ++g_smp_samples;
    }
    if (g_nexamples < 2 && s_npending > 0)
        g_examples[g_nexamples++] = s_pending[s_npending / 2];
    LeaveCriticalSection(&g_cs);
}

static double qpc_ms_since_lo(LONG start_lo) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    const uint32_t d = static_cast<uint32_t>(now.QuadPart) - static_cast<uint32_t>(start_lo);
    return static_cast<double>(d) * 1000.0 / static_cast<double>(g_freq.QuadPart);
}

static DWORD WINAPI sampler_main(void *) {
    LONG cur = -1;
    while (g_sampler_run) {
        if (!g_target) {
            Sleep(5);
            continue;
        }
        const LONG f = g_frame_no;
        if (f != cur) {
            if (f == cur + 1 && s_npending > 0 && g_last_frame_us >= COMMIT_US)
                commit_pending();
            s_npending = 0;
            cur = f;
        }
        if (qpc_ms_since_lo(g_frame_start_lo) < SAMPLE_AFTER_MS) {
            Sleep(1);
            continue;
        }
        LARGE_INTEGER t0;
        QueryPerformanceCounter(&t0);
        Sample s;
        if (s_npending < MAX_PENDING && take_sample(s) && g_frame_no == f)
            s_pending[s_npending++] = s;
        // wait ~1 ms without sleeping (Sleep(1) can take 15 ms)
        for (;;) {
            LARGE_INTEGER t;
            QueryPerformanceCounter(&t);
            if ((t.QuadPart - t0.QuadPart) * 1000 >= g_freq.QuadPart || g_frame_no != f)
                break;
            SwitchToThread();
        }
    }
    return 0;
}

static void describe(uintptr_t a, char *out, size_t cap) {
    if (a >= g_base && a < g_base + g_size) {
        snprintf(out, cap, "empire %08X", gh(a));
        return;
    }
    HMODULE hm = nullptr;
    char path[MAX_PATH] = "";
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(a), &hm) &&
        GetModuleFileNameA(hm, path, MAX_PATH)) {
        const char *name = strrchr(path, '\\');
        unsigned off = 0;
        const char *exp = nearest_export(hm, a, &off);
        if (exp)
            snprintf(out, cap, "%s!%s+%X", name ? name + 1 : path, exp, off);
        else
            snprintf(out, cap, "%s+%X", name ? name + 1 : path,
                     static_cast<unsigned>(a - reinterpret_cast<uintptr_t>(hm)));
        return;
    }
    snprintf(out, cap, "%08X", static_cast<unsigned>(a));
}

static void log_top(const char *title, Hist &h, long total) {
    Log("[twdll] [STUTTER_PROBE]   %s", title);
    for (int r = 0; r < TOP_N; ++r) {
        int best = -1;
        for (int i = 0; i < h.n; ++i)
            if (h.cnt[i] > 0 && (best < 0 || h.cnt[i] > h.cnt[best]))
                best = i;
        if (best < 0)
            break;
        char d[128];
        describe(h.addr[best], d, sizeof(d));
        Log("[twdll] [STUTTER_PROBE]     %5.1f%%  %s", 100.0 * h.cnt[best] / total, d);
        h.cnt[best] = -h.cnt[best]; // mark as printed
    }
}

// Called from flush_window on the Present thread.
static void sampler_report() {
    if (!g_cs_init)
        return;
    long frames, samples;
    Sample ex[2];
    int nex;
    EnterCriticalSection(&g_cs);
    s_eip = g_h_eip;
    s_ret = g_h_ret;
    frames = g_smp_frames;
    samples = g_smp_samples;
    nex = g_nexamples;
    for (int i = 0; i < nex; ++i)
        ex[i] = g_examples[i];
    g_h_eip.n = g_h_ret.n = 0;
    g_smp_frames = g_smp_samples = 0;
    g_nexamples = 0;
    LeaveCriticalSection(&g_cs);

    if (samples == 0) {
        Log("[twdll] [STUTTER_PROBE]   SAMPLER no spike samples this window");
        return;
    }
    // where EIP was: empire code, or a system/driver module (usually a wait)
    long in_empire = 0;
    for (int i = 0; i < s_eip.n; ++i)
        if (s_eip.addr[i] >= g_base && s_eip.addr[i] < g_base + g_size)
            in_empire += s_eip.cnt[i];
    Log("[twdll] [STUTTER_PROBE]   SAMPLER spike frames %ld, samples %ld, EIP in empire %.0f%%",
        frames, samples, 100.0 * in_empire / samples);
    log_top("top EIP (where the thread is):", s_eip, samples);
    log_top("top stack return addresses (who called, % of samples):", s_ret, samples);
    for (int i = 0; i < nex; ++i) {
        char line[1024];
        char d[128];
        describe(ex[i].eip, d, sizeof(d));
        int len = snprintf(line, sizeof(line), "example %d: %s", i + 1, d);
        for (int j = 0; j < ex[i].n && len > 0 && len < static_cast<int>(sizeof(line)) - 16; ++j)
            len += snprintf(line + len, sizeof(line) - len, " < %08X", gh(ex[i].ret[j]));
        Log("[twdll] [STUTTER_PROBE]   %s", line);
    }
}

static void sampler_start() {
    if (!g_cs_init) {
        InitializeCriticalSection(&g_cs);
        g_cs_init = true;
    }
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(g_base);
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(g_base + dos->e_lfanew);
    g_size = nt->OptionalHeader.SizeOfImage;
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    g_text_lo = ~uintptr_t(0);
    g_text_hi = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        const uintptr_t lo = g_base + sec->VirtualAddress;
        const uintptr_t hi = lo + sec->Misc.VirtualSize;
        if (lo < g_text_lo)
            g_text_lo = lo;
        if (hi > g_text_hi)
            g_text_hi = hi;
    }
    g_h_eip.n = g_h_ret.n = 0;
    g_smp_frames = g_smp_samples = 0;
    g_nexamples = 0;
    s_npending = 0;
    g_sampler_run = 1;
    g_sampler = CreateThread(nullptr, 0, sampler_main, nullptr, 0, nullptr);
    Log("[twdll] [STUTTER_PROBE] sampler %s", g_sampler ? "started" : "FAILED");
}

static void sampler_stop() {
    g_sampler_run = 0;
    if (g_sampler) {
        WaitForSingleObject(g_sampler, 2000);
        CloseHandle(g_sampler);
        g_sampler = nullptr;
    }
    if (g_target) {
        CloseHandle(g_target);
        g_target = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Exception probe
// A vectored exception handler that only looks at exceptions raised on the Present
// thread. For MSVC C++ throws (0xE06D7363) it reads the thrown type name and, when
// one is there, the message string. Each distinct (code, type, throw site) is counted.
// It never handles anything: it always returns EXCEPTION_CONTINUE_SEARCH.
// ---------------------------------------------------------------------------
static constexpr int EXC_MAX = 48;
static constexpr int EXC_TOP = 4;
static constexpr int EXC_SITES = 4;

struct ExcRec {
    DWORD code;
    const char *type; // points into the thrower's TypeDescriptor (stable)
    uintptr_t site[EXC_SITES];
    long count;
    char what[128];
};
static ExcRec g_exc[EXC_MAX];
static int g_nexc = 0;
static long g_exc_total = 0, g_exc_dropped = 0;
static void *g_veh = nullptr;

static bool readable(const void *p, size_t n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!p || !VirtualQuery(p, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return false;
    const uintptr_t end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return reinterpret_cast<uintptr_t>(p) + n <= end;
}

// Copies a printable ASCII string of at least 4 chars, or returns false.
static bool grab_text(const char *s, char *out, size_t cap) {
    if (!readable(s, 4))
        return false;
    size_t i = 0;
    for (; i + 1 < cap; ++i) {
        if (!readable(s + i, 1))
            break;
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0)
            break;
        if (c < 0x20 || c > 0x7E)
            return false;
        out[i] = static_cast<char>(c);
    }
    out[i] = 0;
    return i >= 4;
}

static void cxx_info(const EXCEPTION_RECORD *er, const char **type, char *what, size_t cap) {
    *type = nullptr;
    what[0] = 0;
    if (er->NumberParameters < 3 || er->ExceptionInformation[0] != 0x19930520)
        return;
    const uintptr_t obj = er->ExceptionInformation[1];
    const uintptr_t ti = er->ExceptionInformation[2]; // ThrowInfo
    if (!readable(reinterpret_cast<void *>(ti), 16))
        return;
    const uintptr_t cta = *reinterpret_cast<const uintptr_t *>(ti + 12); // CatchableTypeArray
    if (!readable(reinterpret_cast<void *>(cta), 8))
        return;
    const int n = *reinterpret_cast<const int *>(cta);
    bool is_std = false;
    for (int i = 0; i < n && i < 16; ++i) {
        const uintptr_t ct = *reinterpret_cast<const uintptr_t *>(cta + 4 + 4 * i);
        if (!readable(reinterpret_cast<void *>(ct), 8))
            break;
        const uintptr_t td = *reinterpret_cast<const uintptr_t *>(ct + 4); // TypeDescriptor
        if (!readable(reinterpret_cast<void *>(td + 8), 4))
            break;
        const char *name = reinterpret_cast<const char *>(td + 8);
        if (i == 0)
            *type = name;
        if (strstr(name, "exception@std@@"))
            is_std = true;
    }
    if (!readable(reinterpret_cast<void *>(obj), 16))
        return;
    // std::exception keeps its message pointer right after the vtable.
    // For other classes, try the first few pointer-sized fields and an inline buffer.
    const uintptr_t offs[] = {4, 8, 12};
    for (uintptr_t o : offs) {
        const char *p = *reinterpret_cast<const char *const *>(obj + o);
        if (grab_text(p, what, cap))
            return;
        if (is_std)
            break;
    }
    if (!is_std)
        grab_text(reinterpret_cast<const char *>(obj + 4), what, cap);
}

static LONG CALLBACK exc_handler(EXCEPTION_POINTERS *ep) {
    if (GetCurrentThreadId() != g_target_tid)
        return EXCEPTION_CONTINUE_SEARCH;
    const EXCEPTION_RECORD *er = ep->ExceptionRecord;
    ++g_exc_total;

    const char *type = nullptr;
    char what[128];
    what[0] = 0;
    if (er->ExceptionCode == 0xE06D7363)
        cxx_info(er, &type, what, sizeof(what));

    // Throw site: the first return addresses into empire.retail.dll above the handler.
    uintptr_t site[EXC_SITES] = {};
    int ns = 0;
    const NT_TIB *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const uintptr_t top = reinterpret_cast<uintptr_t>(tib->StackBase);
    for (uintptr_t sp = ep->ContextRecord->Esp; sp + 4 <= top && sp < ep->ContextRecord->Esp + 4096 &&
                                                ns < EXC_SITES;
         sp += 4) {
        const uintptr_t v = *reinterpret_cast<const uintptr_t *>(sp);
        if (is_ret_addr(v))
            site[ns++] = v;
    }

    for (int i = 0; i < g_nexc; ++i) {
        ExcRec &r = g_exc[i];
        if (r.code == er->ExceptionCode && r.type == type && r.site[0] == site[0] &&
            r.site[1] == site[1]) {
            ++r.count;
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    if (g_nexc >= EXC_MAX) {
        ++g_exc_dropped;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ExcRec &r = g_exc[g_nexc++];
    r.code = er->ExceptionCode;
    r.type = type;
    for (int j = 0; j < EXC_SITES; ++j)
        r.site[j] = site[j];
    r.count = 1;
    memcpy(r.what, what, sizeof(r.what));
    return EXCEPTION_CONTINUE_SEARCH;
}

// Called from flush_window on the Present thread.
static void exc_report() {
    Log("[twdll] [STUTTER_PROBE]   EXCEPTIONS on Present thread: %ld (%d kinds%s)", g_exc_total,
        g_nexc, g_exc_dropped ? ", table full" : "");
    for (int r = 0; r < EXC_TOP; ++r) {
        int best = -1;
        for (int i = 0; i < g_nexc; ++i)
            if (g_exc[i].count > 0 && (best < 0 || g_exc[i].count > g_exc[best].count))
                best = i;
        if (best < 0)
            break;
        ExcRec &x = g_exc[best];
        char sites[96];
        int len = 0;
        sites[0] = 0;
        for (int j = 0; j < EXC_SITES && x.site[j]; ++j)
            len += snprintf(sites + len, sizeof(sites) - len, " %08X", gh(x.site[j]));
        Log("[twdll] [STUTTER_PROBE]     %5ld x  code %08lX  type %s  sites%s", x.count,
            static_cast<unsigned long>(x.code), x.type ? x.type : "-", sites);
        if (x.what[0])
            Log("[twdll] [STUTTER_PROBE]              what: \"%s\"", x.what);
        x.count = -x.count;
    }
    g_nexc = 0;
    g_exc_total = 0;
    g_exc_dropped = 0;
}

static void exc_install() {
    g_nexc = 0;
    g_exc_total = g_exc_dropped = 0;
    g_veh = AddVectoredExceptionHandler(1, exc_handler);
    Log("[twdll] [STUTTER_PROBE] exception handler %s", g_veh ? "OK" : "FAILED");
}

static void exc_uninstall() {
    if (g_veh) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Debug output probe
// MinHook on KernelBase OutputDebugStringA/W. Messages written on the Present thread
// are counted per distinct text. The Pause key toggles "mute": while muted the calls
// return at once on every thread (no exception, no kernel round trip).
// ---------------------------------------------------------------------------
static constexpr int MSG_MAX = 80;
static constexpr int MSG_LEN = 220;
static constexpr int MSG_TOP = 30;

struct MsgRec {
    long count;
    char text[MSG_LEN];
};
static MsgRec g_msg[MSG_MAX];
static int g_nmsg = 0;
static long g_msg_dropped = 0;
static long g_ods_calls = 0;
static volatile LONG g_mute = 0;
static volatile LONG g_in_w = 0; // target thread is inside OutputDebugStringW
static bool g_pause_down = false;
static double g_mute_times[16];
static int g_mute_states[16];
static int g_nmute = 0;

typedef void(WINAPI *ODSA_t)(LPCSTR);
typedef void(WINAPI *ODSW_t)(LPCWSTR);
static ODSA_t o_odsa = nullptr;
static ODSW_t o_odsw = nullptr;
static void *g_odsa_target = nullptr;
static void *g_odsw_target = nullptr;

static void msg_record(const char *s) {
    char buf[MSG_LEN];
    size_t n = 0;
    for (; s[n] && n + 1 < sizeof(buf); ++n)
        buf[n] = s[n];
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        --n;
    buf[n] = 0;
    for (int i = 0; i < g_nmsg; ++i) {
        if (strcmp(g_msg[i].text, buf) == 0) {
            ++g_msg[i].count;
            return;
        }
    }
    if (g_nmsg >= MSG_MAX) {
        ++g_msg_dropped;
        return;
    }
    MsgRec &r = g_msg[g_nmsg++];
    r.count = 1;
    memcpy(r.text, buf, n + 1);
}

static void WINAPI hk_odsw(LPCWSTR s) {
    const bool tgt = on_target();
    if (tgt && s) {
        ++g_ods_calls;
        char buf[MSG_LEN];
        const int len = static_cast<int>(wcsnlen(s, MSG_LEN - 1));
        const int n =
            WideCharToMultiByte(CP_UTF8, 0, s, len, buf, MSG_LEN - 1, nullptr, nullptr);
        buf[n > 0 ? n : 0] = 0;
        msg_record(buf);
    }
    if (g_mute)
        return;
    if (tgt)
        g_in_w = 1; // W forwards to A; don't count that twice
    o_odsw(s);
    if (tgt)
        g_in_w = 0;
}

static void WINAPI hk_odsa(LPCSTR s) {
    if (on_target() && !g_in_w && s) {
        ++g_ods_calls;
        msg_record(s);
    }
    if (g_mute)
        return;
    o_odsa(s);
}

// Called from hk_present every frame.
static void ods_poll_key(double t) {
    const bool p = (GetAsyncKeyState(VK_PAUSE) & 0x8000) != 0;
    if (p && !g_pause_down) {
        g_mute = !g_mute;
        if (g_nmute < 16) {
            g_mute_times[g_nmute] = t;
            g_mute_states[g_nmute] = g_mute ? 1 : 0;
            ++g_nmute;
        }
    }
    g_pause_down = p;
}

// Called from flush_window on the Present thread.
static void ods_report() {
    for (int i = 0; i < g_nmute; ++i)
        Log("[twdll] [STUTTER_PROBE] t=%7.2fs  Pause pressed: debug output %s", g_mute_times[i],
            g_mute_states[i] ? "MUTED" : "UNMUTED");
    g_nmute = 0;
    Log("[twdll] [STUTTER_PROBE]   DEBUG OUTPUT on Present thread: %ld calls, %d distinct%s, "
        "currently %s",
        g_ods_calls, g_nmsg, g_msg_dropped ? " (table full)" : "", g_mute ? "MUTED" : "on");
    for (int r = 0; r < MSG_TOP; ++r) {
        int best = -1;
        for (int i = 0; i < g_nmsg; ++i)
            if (g_msg[i].count > 0 && (best < 0 || g_msg[i].count > g_msg[best].count))
                best = i;
        if (best < 0)
            break;
        Log("[twdll] [STUTTER_PROBE]     %5ld x  %s", g_msg[best].count, g_msg[best].text);
        g_msg[best].count = -g_msg[best].count;
    }
    g_nmsg = 0;
    g_msg_dropped = 0;
    g_ods_calls = 0;
}

static void ods_install() {
    HMODULE kb = GetModuleHandleA("KernelBase.dll");
    if (!kb)
        kb = GetModuleHandleA("kernel32.dll");
    g_nmsg = 0;
    g_msg_dropped = 0;
    g_ods_calls = 0;
    g_mute = 0;
    void *a = kb ? reinterpret_cast<void *>(GetProcAddress(kb, "OutputDebugStringA")) : nullptr;
    void *w = kb ? reinterpret_cast<void *>(GetProcAddress(kb, "OutputDebugStringW")) : nullptr;
    MH_STATUS sa = a ? MH_CreateHook(a, reinterpret_cast<void *>(&hk_odsa),
                                     reinterpret_cast<void **>(&o_odsa))
                     : MH_ERROR_FUNCTION_NOT_FOUND;
    if (sa == MH_OK)
        sa = MH_EnableHook(a);
    if (sa == MH_OK)
        g_odsa_target = a;
    MH_STATUS sw = w ? MH_CreateHook(w, reinterpret_cast<void *>(&hk_odsw),
                                     reinterpret_cast<void **>(&o_odsw))
                     : MH_ERROR_FUNCTION_NOT_FOUND;
    if (sw == MH_OK)
        sw = MH_EnableHook(w);
    if (sw == MH_OK)
        g_odsw_target = w;
    Log("[twdll] [STUTTER_PROBE] OutputDebugString hooks: A %s, W %s (Pause key = mute)",
        sa == MH_OK ? "OK" : "FAILED", sw == MH_OK ? "OK" : "FAILED");
}

static void ods_uninstall() {
    g_mute = 0;
    void *t[2] = {g_odsa_target, g_odsw_target};
    for (void *p : t) {
        if (!p)
            continue;
        MH_DisableHook(p);
        MH_RemoveHook(p);
    }
    g_odsa_target = g_odsw_target = nullptr;
}

void dbkey_cache_report(); // dbkey_cache.cpp

// All file writes happen here, once per window, and the clock is reset afterwards
// so the logging stall itself is not measured as a spike.
static void flush_window(LONGLONG now) {
    for (int i = 0; i < g_nk; ++i)
        Log("[twdll] [STUTTER_PROBE] t=%7.2fs  K pressed", g_k_times[i]);
    for (int i = 0; i < g_nspk; ++i) {
        const SpikeRec &s = g_spk[i];
        const double rate = (s.a + s.b) / s.ms;
        Log("[twdll] [STUTTER_PROBE] t=%7.2fs  SPIKE %6.1f ms  heapA %6ld  heapB %6ld  "
            "rate %6.1f/ms (normal %6.1f/ms)",
            s.t, s.ms, s.a, s.b, rate, g_base_rate);
    }
    if (g_nspk_dropped)
        Log("[twdll] [STUTTER_PROBE] (%d more spikes not listed)", g_nspk_dropped);

    const Window &w = g_win;
    const double avg = w.frames ? w.sum_ms / w.frames : 0.0;
    const double rate_n = w.ms_normal > 0 ? w.ops_normal / w.ms_normal : 0.0;
    const double rate_s = w.ms_spike > 0 ? w.ops_spike / w.ms_spike : 0.0;
    const double t = ms_between(g_t0, now) / 1000.0;
    Log("[twdll] [STUTTER_PROBE] t=%7.2fs  WINDOW frames %ld  avg %.1f ms (%.0f fps)  max %.1f ms  "
        "spikes %ld  heap ops/frame %.0f  rate normal %.1f/ms  rate spike %.1f/ms",
        t, w.frames, avg, avg > 0 ? 1000.0 / avg : 0.0, w.max_ms, w.spikes,
        w.frames ? (w.ops_normal + w.ops_spike) / w.frames : 0.0, rate_n, rate_s);
    sampler_report();
    exc_report();
    ods_report();
    dbkey_cache_report();
    io_report();

    if (w.frames)
        g_avg_ms = avg;
    if (rate_n > 0)
        g_base_rate = rate_n;
    g_win = {};
    g_nspk = 0;
    g_nspk_dropped = 0;
    g_nk = 0;
}

static HRESULT __stdcall hk_present(IDXGISwapChain *sc, UINT sync, UINT flags) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    if (!g_first_present_logged) {
        g_first_present_logged = true;
        g_t0 = g_last = g_win_start = now.QuadPart;
        InterlockedExchange(&g_cnt_a, 0);
        InterlockedExchange(&g_cnt_b, 0);
        g_frame_start_lo = static_cast<LONG>(now.QuadPart);
        g_target_tid = GetCurrentThreadId();
        g_target = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                              FALSE, GetCurrentThreadId());
        Log("[twdll] [STUTTER_PROBE] first Present on thread %lu (sampler target %s)",
            GetCurrentThreadId(), g_target ? "OK" : "FAILED");
    } else {
        const double ms = ms_between(g_last, now.QuadPart);
        const long a = InterlockedExchange(&g_cnt_a, 0);
        const long b = InterlockedExchange(&g_cnt_b, 0);
        const double t = ms_between(g_t0, now.QuadPart) / 1000.0;

        Window &w = g_win;
        ++w.frames;
        w.sum_ms += ms;
        if (ms > w.max_ms)
            w.max_ms = ms;

        const double thresh = (SPIKE_FACTOR * g_avg_ms > SPIKE_MIN_MS) ? SPIKE_FACTOR * g_avg_ms
                                                                        : SPIKE_MIN_MS;
        if (ms > thresh) {
            ++w.spikes;
            w.ops_spike += a + b;
            w.ms_spike += ms;
            if (g_nspk < MAX_SPIKES_PER_WINDOW)
                g_spk[g_nspk++] = {t, ms, a, b};
            else
                ++g_nspk_dropped;
        } else {
            w.ops_normal += a + b;
            w.ms_normal += ms;
        }

        // Mark UI toggles in the log (edge on K).
        const bool k = (GetAsyncKeyState('K') & 0x8000) != 0;
        if (k && !g_k_down && g_nk < 16)
            g_k_times[g_nk++] = t;
        g_k_down = k;
        ods_poll_key(t);

        g_last = now.QuadPart;
        g_last_frame_us = static_cast<LONG>(ms * 1000.0);
        g_frame_start_lo = static_cast<LONG>(now.QuadPart);
        InterlockedIncrement(&g_frame_no); // sampler: previous frame is finished
        if (ms_between(g_win_start, now.QuadPart) >= WINDOW_S * 1000.0) {
            flush_window(now.QuadPart);
            LARGE_INTEGER after;
            QueryPerformanceCounter(&after);
            g_last = g_win_start = after.QuadPart;
            g_last_frame_us = 0; // drop anything sampled during our own logging
            g_frame_start_lo = static_cast<LONG>(after.QuadPart);
            InterlockedIncrement(&g_frame_no);
            InterlockedExchange(&g_cnt_a, 0);
            InterlockedExchange(&g_cnt_b, 0);
        }
    }
    return g_orig_present(sc, sync, flags);
}

static void *find_present() {
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "twdll_stutter_probe";
    RegisterClassExA(&wc);
    HWND hwnd = CreateWindowExA(0, wc.lpszClassName, "", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64,
                                nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) {
        UnregisterClassA(wc.lpszClassName, wc.hInstance);
        return nullptr;
    }

    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 1;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    IDXGISwapChain *sc = nullptr;
    ID3D11Device *dev = nullptr;
    ID3D11DeviceContext *ctx = nullptr;
    void *present = nullptr;
    const HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                                     nullptr, 0, D3D11_SDK_VERSION, &sd, &sc, &dev,
                                                     nullptr, &ctx);
    if (SUCCEEDED(hr) && sc)
        present = (*reinterpret_cast<void ***>(sc))[8];
    else
        Log("[twdll] [STUTTER_PROBE] dummy swapchain failed (0x%08lX)", static_cast<unsigned long>(hr));

    if (ctx)
        ctx->Release();
    if (dev)
        dev->Release();
    if (sc)
        sc->Release();
    DestroyWindow(hwnd);
    UnregisterClassA(wc.lpszClassName, wc.hInstance);
    return present;
}

// ---------------------------------------------------------------------------
// Install / uninstall (called from campaign_hooks.cpp)
// ---------------------------------------------------------------------------
void install_stutter_probe() {
    if (g_present_target || g_sites[0].active || g_sites[1].active)
        return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleA("empire.retail.dll"));
    if (!g_base) {
        Log("[twdll] [STUTTER_PROBE] empire.retail.dll not found");
        return;
    }
    QueryPerformanceFrequency(&g_freq);
    g_first_present_logged = false;
    g_win = {};
    g_nspk = g_nspk_dropped = g_nk = 0;

    if (locate_sites())
        patch_sites();
    sampler_start();
    io_install();
    exc_install();
    ods_install();

    void *present = find_present();
    if (!present) {
        Log("[twdll] [STUTTER_PROBE] Present not found, frame timing off");
        return;
    }
    MH_STATUS st = MH_CreateHook(present, reinterpret_cast<void *>(&hk_present),
                                 reinterpret_cast<void **>(&g_orig_present));
    if (st == MH_OK)
        st = MH_EnableHook(present);
    if (st == MH_OK)
        g_present_target = present;
    Log("[twdll] [STUTTER_PROBE] Present hook %s (%d)", st == MH_OK ? "OK" : "FAILED", st);
}

void uninstall_stutter_probe() {
    ods_uninstall();
    exc_uninstall();
    io_uninstall();
    g_target_tid = 0;
    sampler_stop();
    for (int i = 1; i >= 0; --i) {
        ProbeSite &s = g_sites[i];
        if (s.active && write_rel(s.call, s.orig_rel))
            s.active = false;
    }
    if (g_present_target) {
        MH_DisableHook(g_present_target);
        MH_RemoveHook(g_present_target);
        g_present_target = nullptr;
    }
    Log("[twdll] [STUTTER_PROBE] removed");
}
