// src/thrones/overlay_fix.cpp
// Movement-range overlay job fixes (job runs on a worker thread when an army is selected;
// exit waits for it). All fixes are E8 call-site patches, verified before writing and
// restored on uninstall (the DLL unloads between campaigns).
//
//  A  FUN_1158db60 : linear find per neighbour over the reachable set  -> hash lookup
//  B  FUN_11591fc0 : border tessellation                                -> skipped for huge zones
//  C  FUN_11622340 / FUN_11621fd0 / FUN_11622190 : linear finds         -> hash lookup

#include <windows.h>
#include <cstdint>
#include <unordered_map>
#include <cstring>

#include "../common/log.h"

static constexpr uintptr_t GH = 0x10000000; // Ghidra image base

static constexpr uintptr_t FN_BUILD = 0x11622340;           // overlay mesh build
static constexpr uintptr_t FN_FIND = 0x11589C60;            // linear find, compare via FUN_10a2d320
static constexpr uintptr_t FN_FIND2 = 0x106BB3F0;           // linear find, inline 2x short compare
static constexpr uintptr_t FN_REACH = 0x1158DB60;           // reachable-set edge scan
static constexpr uintptr_t FN_BORDER = 0x11591FC0;          // border tessellation, __stdcall(1 arg)
static constexpr uintptr_t DAT_INTERIOR_COUNT = 0x1251A604; // element count of DAT_1251a600
static constexpr uintptr_t FN_CAN_REACH =
    0x10A0DF00; // bool can_reach(pf, army, cell*, ctx*), __thiscall, ret 0xC
static constexpr DWORD kHoverMaxAgeMs = 1000;
volatile LONG g_hover_gen = 0; // bumped by pathfinder.cpp on every move order (slots 0-7)
static uintptr_t g_orig_can_reach = 0;
static volatile DWORD g_heurThread =
    0; // thread id of a search that may use the fast heuristic, 0 = off
// Zones with more interior cells than this skip border tessellation (FUN_11591fc0).
static DWORD g_border_threshold = 20000;

static uintptr_t g_base = 0;
static bool g_installed = false;
static volatile LONG g_generation = 0;
static uintptr_t g_orig_build = 0;
static uintptr_t g_orig_reach = 0;
static uintptr_t g_orig_border = 0;
static const volatile DWORD *g_interior_count = nullptr;
static volatile LONG g_border_runs = 0;
static volatile LONG g_border_skips = 0;
static volatile LONG g_rebuilds = 0;

// ---------------------------------------------------------------------------
// Hash-backed replacement for both linear finds.
// Contract (same as FUN_11589c60 and FUN_106bb3f0): pointer to the FIRST element equal to
// *key, or end. Elements are 4 bytes (two ushorts); both originals compare both halves.
// The overlay job is single-threaded (it uses non-thread-safe statics itself).
// ---------------------------------------------------------------------------
static const uint32_t *s_begin = nullptr;
static size_t s_count = 0;
static LONG s_gen = -1;
static std::unordered_map<uint32_t, uint32_t> s_idx;

static void *__cdecl fast_find(const uint32_t *begin, const uint32_t *end, const uint32_t *key) {
    const size_t count = static_cast<size_t>(end - begin);
    if (s_gen != g_generation || s_begin != begin || s_count != count) {
        s_idx.clear();
        s_idx.reserve(count);
        for (size_t i = 0; i < count; ++i)
            s_idx.emplace(begin[i], static_cast<uint32_t>(i)); // emplace keeps the first match
        s_begin = begin;
        s_count = count;
        s_gen = g_generation;
        InterlockedIncrement(&g_rebuilds);
    }
    auto it = s_idx.find(*key);
    return it == s_idx.end() ? (void *)end : (void *)(begin + it->second);
}

// Bump generation, tail-jump into the original. Args and return address untouched.
static __declspec(naked) void build_wrapper() {
    __asm {
        lock inc dword ptr [g_generation]
        jmp dword ptr [g_orig_build]
    }
}

static __declspec(naked) void reach_wrapper() {
    __asm {
        lock inc dword ptr [g_generation]
        jmp dword ptr [g_orig_reach]
    }
}

// FUN_11591fc0 is __stdcall with one argument: skipping it means "ret 4".
static __declspec(naked) void border_guard() {
    __asm {
        mov  eax, g_interior_count
        mov  eax, dword ptr [eax]
        cmp  eax, g_border_threshold
        ja   skip
        lock inc dword ptr [g_border_runs]
        jmp  dword ptr [g_orig_border]
    skip:
        lock inc dword ptr [g_border_skips]
        ret  4
    }
}
// ---------------------------------------------------------------------------
// Hover "can reach" cache. FUN_114578a0 (cursor evaluator, every frame) asks
// FUN_10a0df00 whether the selected army can reach the hovered cell. That runs a full
// path search (FUN_10a17090 -> FUN_106c0b30) every frame even with the mouse still.
// Only the bool survives FUN_10a0df00, so same inputs -> same answer.
// ---------------------------------------------------------------------------
typedef bool(__thiscall *CanReach_t)(void *pf, int army, uint32_t *cell, long ctx);

struct HoverEntry {
    bool valid;
    void *pf;
    int army;
    uint32_t cell;
    int ctx;
    LONG hgen;
    LONG ogen;
    DWORD tick;
    bool result;
    bool restoreF;
    float f[4];
};
static HoverEntry s_hover = {};

static LONG s_hCalls = 0, s_hHits = 0;
static double s_hOrigMs = 0.0, s_hMaxMs = 0.0;
static DWORD s_hLastReport = 0;

static double hover_qpc_ms(LONGLONG ticks) {
    static const LONGLONG freq = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return f.QuadPart;
    }();
    return static_cast<double>(ticks) * 1000.0 / static_cast<double>(freq);
}

// __fastcall with a dummy EDX == __thiscall layout; callee pops the 3 stack args (ret 0xC).
static bool __fastcall hover_can_reach(
    void *pf, void * /*edx*/, int army, uint32_t *cell, long ctx) {
    const DWORD now = GetTickCount();

    if (s_hLastReport == 0)
        s_hLastReport = now;
    if (now - s_hLastReport >= 5000) {
        if constexpr (TWDLL_DEBUG_STATS != 0) Log("[twdll] [HOVER] last 5s: calls %ld, hits %ld, original %.0f ms total (max %.0f ms)",
            s_hCalls,
            s_hHits,
            s_hOrigMs,
            s_hMaxMs);
        s_hCalls = s_hHits = 0;
        s_hOrigMs = s_hMaxMs = 0.0;
        s_hLastReport = now;
    }
    ++s_hCalls;

    const uint32_t c = cell ? *cell : 0;
    const int x = ctx ? *reinterpret_cast<int *>(ctx) : 0;
    float *pff = reinterpret_cast<float *>(reinterpret_cast<char *>(pf) + 0xEC);

    if (s_hover.valid && s_hover.pf == pf && s_hover.army == army && s_hover.cell == c &&
        s_hover.ctx == x && s_hover.hgen == g_hover_gen && s_hover.ogen == g_generation &&
        (now - s_hover.tick) < kHoverMaxAgeMs) {
        ++s_hHits;
        if (s_hover.restoreF)
            std::memcpy(pff, s_hover.f, sizeof(s_hover.f));
        return s_hover.result;
    }

    float before[4];
    std::memcpy(before, pff, sizeof(before));

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    // While RMB-dragging, the hover check may use the fast heuristic too: it only needs
    // reachable yes/no, and weighted A* without re-expansion still finds a path if one exists.
    const bool hoverFast = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
    if (hoverFast)
        g_heurThread = GetCurrentThreadId();
    const bool r = reinterpret_cast<CanReach_t>(g_orig_can_reach)(pf, army, cell, ctx);
    if (hoverFast)
        g_heurThread = 0;
    QueryPerformanceCounter(&t1);
    const double ms = hover_qpc_ms(t1.QuadPart - t0.QuadPart);
    s_hOrigMs += ms;
    if (ms > s_hMaxMs)
        s_hMaxMs = ms;

    s_hover.valid = true;
    s_hover.pf = pf;
    s_hover.army = army;
    s_hover.cell = c;
    s_hover.ctx = x;
    s_hover.hgen = g_hover_gen;
    s_hover.ogen = g_generation;
    s_hover.tick = now;
    s_hover.result = r;
    std::memcpy(s_hover.f, pff, sizeof(s_hover.f));
    s_hover.restoreF = r || (std::memcmp(before, pff, sizeof(before)) != 0);
    return r;
}

// ---------------------------------------------------------------------------
// Distance-aware A* heuristic for the drag-arrow preview.
// Node priority = g + FUN_10b97020(graph, nodeIdx, targetIdx) (called from FUN_10b97000 at
// 10B9700A and from FUN_106b7ca0 at 106B7CAE). Log showed: original h is never 0 and never
// below minStep * hexDistance, yet x2/x3 weighting changed nothing -> h is a huge, flat value
// (zone table), so the search orders by g only and floods like Dijkstra.
// While dragging we REPLACE h with minStep * hexDistanceLowerBound(node, target). That is
// admissible (never overestimates normal steps), so the route cost stays optimal.
//   graph+0x6c = grid width (808), node index = y * width + x.
//   minStep = cheapest neighbour step seen at 106BACC6 (70).
// Active only on the drag thread while RMB is held.
// ---------------------------------------------------------------------------
static constexpr uintptr_t FN_HEUR = 0x10B97020; // __thiscall(graph, int idx, int target), ret 8
static constexpr uintptr_t FN_RELAX =
    0x106E4710; // __thiscall(search, uint idx, int stepCost), ret 8
static uintptr_t g_orig_heur = 0;
static uintptr_t g_orig_relax = 0;
static volatile LONG g_minStep = 0x7FFFFFFF; // cheapest neighbour step cost observed
static LONG s_heurCalls = 0, s_geoUsed = 0, s_heurA = 0, s_heurB = 0;
static long long s_stepSum = 0;
static LONG s_stepCnt = 0;
// Weight on the distance estimate (percent). 100 = exact-cost routes (admissible),
// >100 = faster but the preview route may be slightly longer than optimal.
static constexpr int kGeoWeightPct = 500;
static LONG s_skipClosed = 0;
static unsigned s_hMin = 0xFFFFFFFF, s_hMax = 0, s_lastWidth = 0;
typedef int(__thiscall *Heur_t)(void *graph, int idx, int target);
typedef void(__thiscall *Relax_t)(void *search, uint32_t idx, int cost);

// Neighbour step relax (106BACC6). The cheapest step is learned ONLY from searches on the
// fast (drag) thread, so AI / other unit types can't drag g_minStep down (seen: 70 -> 25).
static void __fastcall relax_observe(void *search, void * /*edx*/, uint32_t idx, int cost) {
    if (g_heurThread != 0 && g_heurThread == GetCurrentThreadId()) {
        if (cost > 0 && cost < g_minStep)
            InterlockedExchange(&g_minStep, cost);
        s_stepSum += cost;
        ++s_stepCnt;
        // Weighted A* without re-expansion: never reopen a CLOSED hex during the preview.
        // search = FUN_106c4d90 state: +0xC -> object whose +8 is the per-hex stamp array
        // (ushort), +0x18 = this search's stamp. Closed = stamp | 2 (set in FUN_10b331b0).
        const char *so = static_cast<const char *>(search);
        const char *stampObj = *reinterpret_cast<const char *const *>(so + 0xC);
        if (stampObj) {
            const uint16_t *stamps = *reinterpret_cast<const uint16_t *const *>(stampObj + 8);
            const uint16_t mine = *reinterpret_cast<const uint16_t *>(so + 0x18);
            if (stamps) {
                const uint16_t st = stamps[idx];
                if ((st & 0xFFFC) == mine && (st & 3) == 2) {
                    ++s_skipClosed;
                    return;
                }
            }
        }
    }
    reinterpret_cast<Relax_t>(g_orig_relax)(search, idx, cost);
}

static int hex_lower_bound(unsigned a, unsigned b, unsigned w) {
    const int x1 = static_cast<int>(a % w), y1 = static_cast<int>(a / w);
    const int x2 = static_cast<int>(b % w), y2 = static_cast<int>(b / w);
    const int dx = x1 > x2 ? x1 - x2 : x2 - x1;
    const int dy = y1 > y2 ? y1 - y2 : y2 - y1;
    // Valid for both column-offset and row-offset hex layouts (take the weaker bound).
    int bq = dy - (dx + 1) / 2;
    if (bq < dx)
        bq = dx;
    int br = dx - (dy + 1) / 2;
    if (br < dy)
        br = dy;
    const int d = bq < br ? bq : br;
    return d > 0 ? d : 0;
}

static int heur_geo(int site, void *graph, int idx, int target) {
    const int h = reinterpret_cast<Heur_t>(g_orig_heur)(graph, idx, target);
    if (g_heurThread == 0 || g_heurThread != GetCurrentThreadId())
        return h;
    ++s_heurCalls;
    if (site == 0)
        ++s_heurA;
    else
        ++s_heurB;
    if (static_cast<unsigned>(h) < s_hMin)
        s_hMin = static_cast<unsigned>(h);
    if (static_cast<unsigned>(h) > s_hMax)
        s_hMax = static_cast<unsigned>(h);
    const LONG cmin = g_minStep;
    if (cmin == 0x7FFFFFFF || !graph)
        return h;
    const unsigned w = *reinterpret_cast<const unsigned *>(static_cast<const char *>(graph) + 0x6C);
    s_lastWidth = w;
    if (w == 0 || w > 65535)
        return h;
    long long g = static_cast<long long>(cmin) * kGeoWeightPct / 100 *
                  hex_lower_bound(static_cast<unsigned>(idx), static_cast<unsigned>(target), w);
    if (g > 0x0FFFFFFF)
        g = 0x0FFFFFFF;
    ++s_geoUsed;
    return static_cast<int>(g);
}

// __fastcall with a dummy EDX == __thiscall layout; callee pops the 2 stack args (ret 8).
static int __fastcall heur_geo_a(void *graph, void * /*edx*/, int idx, int target) {
    return heur_geo(0, graph, idx, target);
}
static int __fastcall heur_geo_b(void *graph, void * /*edx*/, int idx, int target) {
    return heur_geo(1, graph, idx, target);
}

// ---------------------------------------------------------------------------
// Drag-arrow path measurement (temporary, no behaviour change).
// FUN_11462e80 -> FUN_11416990 -> FUN_10a19080 (site B) runs while RMB-dragging.
// Site A (FUN_10a0c5c0) measured for comparison.
// ---------------------------------------------------------------------------
static constexpr uintptr_t FN_DRAG_PATH = 0x10A19080;
static uintptr_t g_orig_drag_path = 0;
typedef uint32_t(__thiscall *DragPath_t)(void *pf, int army, uint32_t *cell, void *out, long ctx);

struct DragStats {
    LONG calls;
    double ms;
    double maxMs;
};
static DragStats s_drag[2] = {};
static DWORD s_dragLastReport = 0;

static uint32_t drag_measure(int site, void *pf, int army, uint32_t *cell, void *out, long ctx) {
    const DWORD now = GetTickCount();
    if (s_dragLastReport == 0)
        s_dragLastReport = now;
    if (now - s_dragLastReport >= 5000) {
        if constexpr (TWDLL_DEBUG_STATS != 0)
        if (s_drag[0].calls || s_drag[1].calls)
            Log("[twdll] [DRAG] last 5s: A(10a0c5c0) calls %ld, %.0f ms (max %.0f) | "
                "B(11416990) calls %ld, %.0f ms (max %.0f), %.1f ms/call | nodes/call %.0f (a %ld "
                "b %ld), "
                "geo %ld, skipped closed %ld, avg step %.0f, minstep %ld, weight %d%%, width %u",
                s_drag[0].calls,
                s_drag[0].ms,
                s_drag[0].maxMs,
                s_drag[1].calls,
                s_drag[1].ms,
                s_drag[1].maxMs,
                s_drag[1].calls ? s_drag[1].ms / s_drag[1].calls : 0.0,
                s_drag[1].calls ? static_cast<double>(s_heurCalls) / s_drag[1].calls : 0.0,
                s_heurA,
                s_heurB,
                s_geoUsed,
                s_skipClosed,
                s_stepCnt ? static_cast<double>(s_stepSum) / s_stepCnt : 0.0,
                g_minStep,
                kGeoWeightPct,
                s_lastWidth);
        s_heurCalls = s_geoUsed = s_heurA = s_heurB = s_stepCnt = s_skipClosed = 0;
        s_stepSum = 0;
        s_hMin = 0xFFFFFFFF;
        s_hMax = 0;
        s_drag[0] = DragStats{};
        s_drag[1] = DragStats{};
        s_dragLastReport = now;
    }

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    const uint32_t r = reinterpret_cast<DragPath_t>(g_orig_drag_path)(pf, army, cell, out, ctx);
    QueryPerformanceCounter(&t1);
    const double ms = hover_qpc_ms(t1.QuadPart - t0.QuadPart);
    ++s_drag[site].calls;
    s_drag[site].ms += ms;
    if (ms > s_drag[site].maxMs)
        s_drag[site].maxMs = ms;
    return r;
}

static uint32_t __fastcall drag_site_a(
    void *pf, void *, int army, uint32_t *cell, void *out, long ctx) {
    return drag_measure(0, pf, army, cell, out, ctx);
}

// Arrow preview. Weighted heuristic only while RMB is held; the release frame searches normally.
static uint32_t __fastcall drag_site_b(
    void *pf, void *, int army, uint32_t *cell, void *out, long ctx) {
    const bool rmbDown = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
    if (rmbDown)
        g_heurThread = GetCurrentThreadId();
    const uint32_t r = drag_measure(1, pf, army, cell, out, ctx);
    g_heurThread = 0;
    return r;
}

// ---------------------------------------------------------------------------
// Call-site patch table
// ---------------------------------------------------------------------------
struct Patch {
    const char *name;
    uintptr_t site;     // Ghidra address of the E8 CALL
    uintptr_t expected; // Ghidra address of the original callee
    void *target;       // replacement
    int depends;        // index of a patch that must be active first, or -1
    int32_t orig_rel;
    bool active;
};

static Patch g_patches[] = {
    {"build_wrapper", 0x116214F7, FN_BUILD, (void *)&build_wrapper, -1, 0, false},     // 0
    {"find_phase2", 0x11622E43, FN_FIND, (void *)&fast_find, 0, 0, false},             // 1  (C)
    {"find_fd0", 0x1162206B, FN_FIND2, (void *)&fast_find, 0, 0, false},               // 2  (C)
    {"find_2190", 0x1162228C, FN_FIND2, (void *)&fast_find, 0, 0, false},              // 3  (C)
    {"reach_wrapper", 0x1158DB4C, FN_REACH, (void *)&reach_wrapper, -1, 0, false},     // 4
    {"find_reach", 0x1158DC5D, FN_FIND2, (void *)&fast_find, 4, 0, false},             // 5  (A)
    {"border_guard", 0x11622F89, FN_BORDER, (void *)&border_guard, -1, 0, false},      // 6  (B)
    {"hover_cache", 0x114581E5, FN_CAN_REACH, (void *)&hover_can_reach, -1, 0, false}, // 7  hover
    {"find_dcb0", 0x1158DD39, FN_FIND2, (void *)&fast_find, 4, 0, false}, // 8  drag: FUN_1158dcb0
    {"find_de80", 0x1158DF6A, FN_FIND2, (void *)&fast_find, 4, 0, false}, // 9  drag: FUN_1158de80
    {"drag_a", 0x10A0C5E7, FN_DRAG_PATH, (void *)&drag_site_a, -1, 0, false}, // 10 measure only
    {"drag_b", 0x114169A2, FN_DRAG_PATH, (void *)&drag_site_b, -1, 0, false}, // 11 measure + heur
                                                                              // flag
    {"heur_geo_a", 0x10B9700A, FN_HEUR, (void *)&heur_geo_a, 11, 0, false},   // 12 in FUN_10b97000
    {"heur_geo_b", 0x106B7CAE, FN_HEUR, (void *)&heur_geo_b, 11, 0, false},   // 13 in FUN_106b7ca0
    {"relax_observe", 0x106BACC6, FN_RELAX, (void *)&relax_observe, 11, 0, false}, // 14 min step
                                                                                   // cost
};
static constexpr int PATCH_COUNT = sizeof(g_patches) / sizeof(g_patches[0]);

static bool write_rel(uint8_t *site, int32_t rel) {
    DWORD old;
    if (!VirtualProtect(site + 1, 4, PAGE_EXECUTE_READWRITE, &old))
        return false;
    *reinterpret_cast<int32_t *>(site + 1) = rel;
    VirtualProtect(site + 1, 4, old, &old);
    FlushInstructionCache(GetCurrentProcess(), site, 5);
    return true;
}

static bool patch_one(Patch &p) {
    uint8_t *s = reinterpret_cast<uint8_t *>(g_base + (p.site - GH));
    if (s[0] != 0xE8) {
        Log("[twdll] [OVERLAY_FIX] %s: no CALL opcode at 0x%08X",
            p.name,
            static_cast<unsigned int>(p.site));
        return false;
    }
    const int32_t rel = *reinterpret_cast<int32_t *>(s + 1);
    const uintptr_t cur = reinterpret_cast<uintptr_t>(s) + 5 + rel;
    const uintptr_t exp = g_base + (p.expected - GH);
    if (cur != exp) {
        Log("[twdll] [OVERLAY_FIX] %s: CALL at 0x%08X targets 0x%08X, expected 0x%08X",
            p.name,
            static_cast<unsigned int>(p.site),
            static_cast<unsigned int>(cur - g_base + GH),
            static_cast<unsigned int>(p.expected));
        return false;
    }
    const int32_t nrel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(p.target) -
                                              (reinterpret_cast<uintptr_t>(s) + 5));
    if (!write_rel(s, nrel)) {
        Log("[twdll] [OVERLAY_FIX] %s: VirtualProtect failed", p.name);
        return false;
    }
    p.orig_rel = rel;
    p.active = true;
    return true;
}

void install_overlay_fix() {
    if (g_installed)
        return;

    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA("empire.retail.dll"));
    if (!base) {
        Log("[twdll] [OVERLAY_FIX] empire.retail.dll not found");
        return;
    }
    g_base = base;
    Log("[twdll] [OVERLAY_FIX] empire.retail.dll base 0x%08X", static_cast<unsigned int>(base));

    g_orig_build = base + (FN_BUILD - GH);
    g_orig_reach = base + (FN_REACH - GH);
    g_orig_border = base + (FN_BORDER - GH);
    g_orig_can_reach = base + (FN_CAN_REACH - GH);
    g_orig_drag_path = base + (FN_DRAG_PATH - GH);
    g_orig_heur = base + (FN_HEUR - GH);
    g_orig_relax = base + (FN_RELAX - GH);
    g_interior_count = reinterpret_cast<const volatile DWORD *>(base + (DAT_INTERIOR_COUNT - GH));

    int ok = 0;
    for (int i = 0; i < PATCH_COUNT; ++i) {
        Patch &p = g_patches[i];
        if (p.depends >= 0 && !g_patches[p.depends].active) {
            Log("[twdll] [OVERLAY_FIX] %s: skipped (needs %s)", p.name, g_patches[p.depends].name);
            continue;
        }
        if (patch_one(p)) {
            ++ok;
            Log("[twdll] [OVERLAY_FIX] %s: OK", p.name);
        }
    }
    Log("[twdll] [OVERLAY_FIX] %d/%d patches active (border threshold %u cells)",
        ok,
        PATCH_COUNT,
        static_cast<unsigned int>(g_border_threshold));
    g_installed = true; // even if partial: uninstall restores whatever is active
}

// Called from uninstall_campaign_hooks(): the DLL unloads after this, so nothing in
// empire.retail.dll may keep pointing at our code.
void uninstall_overlay_fix() {
    if (!g_installed)
        return;
    Log("[twdll] [OVERLAY_FIX] stats: border runs %ld, border skips %ld, hash rebuilds %ld",
        g_border_runs,
        g_border_skips,
        g_rebuilds);
    for (int i = PATCH_COUNT - 1; i >= 0; --i) {
        Patch &p = g_patches[i];
        if (!p.active)
            continue;
        uint8_t *s = reinterpret_cast<uint8_t *>(g_base + (p.site - GH));
        if (write_rel(s, p.orig_rel))
            p.active = false;
    }
    s_idx.clear();
    s_begin = nullptr;
    s_count = 0;
    s_gen = -1;
    s_hover.valid = false;
    g_heurThread = 0;
    g_installed = false;
    Log("[twdll] [OVERLAY_FIX] restored original code");
}