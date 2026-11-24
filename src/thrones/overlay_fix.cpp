// src/thrones/overlay_fix.cpp
// Movement-range overlay job fixes (job runs on a worker thread when an army is selected;
// exit waits for it). All fixes are E8 call-site patches, verified before writing and
// restored on uninstall (the DLL unloads between campaigns).
//
//  A  FUN_1158db60 : linear find per neighbour over the reachable set  -> hash lookup
//  B  FUN_11591fc0 : border tessellation                                -> skipped for huge zones
//  C  FUN_11622340 / FUN_11621fd0 / FUN_11622190 : linear finds         -> hash lookup
//
// Route arrows and "can reach" checks always use the game's own exact search (the earlier
// drag-preview shortcut, a weighted estimate, could turn reachable arrows red).

#include <windows.h>
#include <cstdint>
#include <unordered_map>
#include <cstring>
#include <cstdio>
#include <cstdlib>

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

static LONG s_hCalls = 0, s_hHits = 0, s_hvRuns = 0;
static double s_hvMs = 0.0;
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

// ---------------------------------------------------------------------------
// [SEARCH] diagnostics (log only, behaviour unchanged): which of the game's 12 route-search loops
// run while the arrow is dragged, and how many hexes each takes off its open list. Each loop has
// exactly one caller and one heap pop (FUN_106c0cd0); both CALLs are counted, then the original
// runs as before. Counts only while the arrow route (drag_b) is being computed.
// ---------------------------------------------------------------------------
static constexpr uintptr_t FN_HEAP_POP = 0x106C0CD0;
static constexpr int kLoops = 12;
static const uintptr_t kLoopFn[kLoops] = {0x106B8010, 0x106B8260, 0x106B84B0, 0x106B8700, 0x10A0E0F0, 0x10A0E360, 0x10AA3590, 0x10AA3800, 0x10B331B0, 0x10B33440, 0x10B336D0, 0x10B33920};
static volatile LONG g_inArrow = 0;   // 1 while the arrow route search runs
static LONG g_loopRuns[kLoops] = {};  // loop entries during the arrow
static LONG g_loopPops[kLoops] = {};  // hexes popped during the arrow
static uintptr_t g_loopOrig[kLoops] = {};
static uintptr_t g_popOrig = 0;

static __declspec(naked) void loop_run_0() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 0], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 0]
    }
}
static __declspec(naked) void loop_pop_0() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 0], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_run_1() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 4], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 4]
    }
}
static __declspec(naked) void loop_pop_1() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 4], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_run_2() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 8], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 8]
    }
}
static __declspec(naked) void loop_pop_2() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 8], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_run_3() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 12], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 12]
    }
}
static __declspec(naked) void loop_pop_3() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 12], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_pop_4() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 16], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_pop_5() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 20], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_run_6() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 24], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 24]
    }
}
static __declspec(naked) void loop_pop_6() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 24], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_run_7() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 28], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 28]
    }
}
static __declspec(naked) void loop_pop_7() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 28], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_pop_8() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 32], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_run_9() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 36], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 36]
    }
}
static __declspec(naked) void loop_pop_9() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 36], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_run_10() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 40], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 40]
    }
}
static __declspec(naked) void loop_pop_10() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 40], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

static __declspec(naked) void loop_run_11() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopRuns + 44], eax
        pop  eax
        jmp  dword ptr [g_loopOrig + 44]
    }
}
static __declspec(naked) void loop_pop_11() {
    __asm {
        push eax
        mov  eax, g_inArrow
        add  dword ptr [g_loopPops + 44], eax
        pop  eax
        jmp  dword ptr [g_popOrig]
    }
}

// ---------------------------------------------------------------------------
// Exact A* guide for the arrow route and the hover "can reach" check.
// The [SEARCH] log showed where an arrow route spends its time: one main search FUN_10a0e0f0
// (30-55k hexes) and ~50 short searches FUN_10b331b0 while the route is refined (~3k hexes
// each). The hover check uses FUN_10a0e0f0 / FUN_10a0e360. In all three loops (verified):
//   - the loop stops when it pops the one goal hex (FUN_10a0e0f0 / 10a0e360: node == *arg3;
//     FUN_10b331b0: FUN_10b670d0, node == *(goal object) = *arg3)
//   - the heuristic (FUN_10b97020, called at 106B7CAE or 10B9700A) gets that same hex as target
//   - the only expansions are FUN_106ba9f0 / 106bab30 / 106bac70 and the relax steps
//     FUN_106e4450 / 106e45b0 / 106e4710 add the step to the parent's cost (budget check aside)
//     and reopen a hex when it is reached cheaper.
// The game's heuristic is a landmass-to-landmass table (word +6 of the hex record, low 12 bits),
// the same for every hex of one landmass, so inside a landmass these searches flood in every
// direction like Dijkstra. Every step cost those expansions can add:
//   - neighbour step: stepCost[b] (graph+0x37C, 256 dwords), b = byte s of the hex record,
//     taken only if (b & mask) == mask (mask = byte at graph+0x7BC)
//   - crossing between two type-5 hexes (word +6, top nibble 5): 0x1F4 = 500
// So from a hex on the goal's landmass the remaining cost is at least
//   min( minStep * hexDistance(hex, goal),  500 + minStep * hexDistance(nearest type-5, goal) )
// That is added to the game's own value. It never overestimates and it is 0 at the goal, so A*
// still returns the cheapest route: the same cost as vanilla, so the same red/yellow
// (equal-cost alternatives may be drawn along a different line).
// The map layout is checked at runtime; if anything does not match, the guide stays off.
// Switches (game folder): twdll_arrow_exact_off.txt = vanilla search,
//                         twdll_arrow_verify.txt   = run every hover check both ways, log diffs.
// ---------------------------------------------------------------------------
static constexpr uintptr_t FN_HEUR = 0x10B97020; // __thiscall(graph, int idx, int target), ret 8
typedef int(__thiscall *Heur_t)(void *graph, int idx, int target);
static uintptr_t g_orig_heur = 0;
static constexpr uintptr_t FN_HEX_DIST = 0x10B97320; // __cdecl int(coordA, coordB), coord = y<<16 | x
typedef int(__cdecl *HexDist_t)(uint32_t a, uint32_t b);
static uintptr_t g_hex_dist = 0;
static volatile DWORD g_guideThread = 0; // thread inside one of the three verified loops
static volatile DWORD g_guideWant = 0;   // thread of an arrow / hover check that wants it
static bool g_guideOn = true;
static bool g_guideVerify = false;
static LONG s_searchSerial = 0;

struct GuideGraph {
    const char *graph;
    const uint8_t *recs;
    uint32_t width, count;
    uint8_t mask;
    uint32_t tableSum;
    int layout;  // 0 = odd columns shifted down, 1 = even columns shifted down
    int minStep;
    bool ok;
    LONG serial; // search this state was checked for
    int *portalQ;
    int *portalR;
    uint32_t portals;
    char info[200];  // step classes for the log
    int target;      // cached per target:
    int targetQ, targetR, targetZone, portalBound;
};
static GuideGraph s_ggs[4] = {}; // one per graph (unit / movement type), reused
static GuideGraph *s_cur = &s_ggs[0];
static unsigned s_ggNext = 0;
static LONG s_guideLogs = 0;
static LONG s_guideUsed = 0, s_guideCalls = 0, s_guideSample = 0, s_guideRaw = 0;
static LONG s_verifyRuns = 0, s_verifyDiffs = 0, s_verifyFloatDiffs = 0;

static inline int iabs(int v) {
    return v < 0 ? -v : v;
}

static inline void to_cube(int layout, uint32_t idx, uint32_t w, int &q, int &r) {
    const int x = static_cast<int>(idx % w), y = static_cast<int>(idx / w);
    q = x;
    r = layout == 0 ? y - (x - (x & 1)) / 2 : y - (x + (x & 1)) / 2;
}

static inline int cube_dist(int q1, int r1, int q2, int r2) {
    const int dq = q1 - q2, dr = r1 - r2;
    return (iabs(dq) + iabs(dr) + iabs(dq + dr)) / 2;
}

static bool same_set(const int *got, const int *want) {
    bool used[6] = {};
    for (int i = 0; i < 6; ++i) {
        bool found = false;
        for (int j = 0; j < 6; ++j)
            if (!used[j] && got[j] == want[i]) {
                used[j] = true;
                found = true;
                break;
            }
        if (!found)
            return false;
    }
    return true;
}

static uint32_t table_sum(const char *g) {
    const uint32_t *t = reinterpret_cast<const uint32_t *>(g + 0x37C);
    uint32_t s = 0;
    for (int i = 0; i < 256; ++i)
        s = s * 31 + t[i];
    return s;
}

// Full check of one graph. Plain data only (SEH). Returns a reason string, or nullptr if usable.
static const char *guide_setup_inner(GuideGraph &e, const char *g) {
    __try {
        free(e.portalQ);
        free(e.portalR);
        e = GuideGraph{};
        e.graph = g;
        const uint32_t w = *reinterpret_cast<const uint32_t *>(g + 0x6C);
        const uint32_t cap = *reinterpret_cast<const uint32_t *>(g + 0xA4);
        const uint32_t size = *reinterpret_cast<const uint32_t *>(g + 0xA8);
        const uint8_t *recs = *reinterpret_cast<const uint8_t *const *>(g + 0xAC);
        const uint8_t mask = *reinterpret_cast<const uint8_t *>(g + 0x7BC);
        const int *step = reinterpret_cast<const int *>(g + 0x37C);
        const int *off = reinterpret_cast<const int *>(g + 0x77C); // [parity * 6 + dir]
        e.width = w;
        e.count = size;
        e.recs = recs;
        e.mask = mask;
        e.tableSum = table_sum(g);
        if (w < 2 || w > 65535 || (w & 1))
            return "grid width";
        if (!recs || size < w || size % w || size > 16000000 || cap < size)
            return "hex array";
        const int iw = static_cast<int>(w);
        const int oddEven[6] = {-iw, iw, -iw - 1, -iw + 1, -1, 1};
        const int oddOdd[6] = {-iw, iw, -1, 1, iw - 1, iw + 1};
        if (same_set(off, oddEven) && same_set(off + 6, oddOdd))
            e.layout = 0;
        else if (same_set(off, oddOdd) && same_set(off + 6, oddEven))
            e.layout = 1;
        else
            return "neighbour layout";
        // Only step classes that occur in the hex records can ever be taken.
        uint32_t uses[256] = {};
        for (uint32_t i = 0; i < size; ++i) {
            const uint8_t *rec = recs + static_cast<size_t>(i) * 8;
            for (int d = 0; d < 6; ++d)
                ++uses[rec[d]];
        }
        int minStep = 0x7FFFFFFF;
        {
            // Log line: passable classes, cheapest first: class=cost(steps on the map)
            bool shown[256] = {};
            int len = 0;
            for (int k = 0; k < 12; ++k) {
                int best = -1;
                for (int b = 0; b < 256; ++b)
                    if (!shown[b] && uses[b] && (b & mask) == mask && (best < 0 || step[b] < step[best]))
                        best = b;
                if (best < 0)
                    break;
                shown[best] = true;
                const int n = snprintf(e.info + len,
                                       sizeof(e.info) - len,
                                       "%s%02X=%d(%u)",
                                       len ? " " : "",
                                       best,
                                       step[best],
                                       uses[best]);
                if (n < 0 || len + n >= static_cast<int>(sizeof(e.info)) - 1)
                    break;
                len += n;
            }
        }
        for (int b = 0; b < 256; ++b) {
            if (!uses[b] || (b & mask) != mask)
                continue;
            if (step[b] < 0)
                return "negative step cost";
            if (step[b] < minStep)
                minStep = step[b];
        }
        if (minStep == 0x7FFFFFFF || minStep <= 0)
            return "zero step cost";
        e.minStep = minStep;
        // Our hex distance must equal the game's own (FUN_10b97320) on a spread of hex pairs.
        if (!g_hex_dist)
            return "no distance function";
        {
            uint32_t seed = 12345;
            for (int t = 0; t < 4000; ++t) {
                seed = seed * 1103515245u + 12345u;
                const uint32_t i = (seed >> 4) % size;
                seed = seed * 1103515245u + 12345u;
                uint32_t j = (seed >> 4) % size;
                if (t % 4 == 0)
                    j = i + (static_cast<uint32_t>(t / 4) % 7) - 3 + w * ((static_cast<uint32_t>(t / 4) / 7) % 7 - 3);
                if (j >= size)
                    continue;
                int q1, r1, q2, r2;
                to_cube(e.layout, i, w, q1, r1);
                to_cube(e.layout, j, w, q2, r2);
                const uint32_t ci = ((i / w) << 16) | (i % w), cj = ((j / w) << 16) | (j % w);
                const int mine = cube_dist(q1, r1, q2, r2);
                const int game = reinterpret_cast<HexDist_t>(g_hex_dist)(ci, cj);
                if (mine != game)
                    return "hex distance differs from the game's";
            }
        }
        // Type-5 hexes, and no passable step that wraps around a map edge.
        const uint32_t rows = size / w;
        uint32_t portals = 0;
        for (uint32_t i = 0; i < size; ++i) {
            const uint8_t *rec = recs + static_cast<size_t>(i) * 8;
            if ((*reinterpret_cast<const uint16_t *>(rec + 6) & 0xF000) == 0x5000)
                ++portals;
            const uint32_t x = i % w, y = i / w;
            if (x != 0 && x != w - 1 && y != 0 && y != rows - 1)
                continue;
            const int *o = off + (i & 1) * 6;
            for (int s = 0; s < 6; ++s) {
                if ((rec[s] & mask) != mask)
                    continue;
                const int d = o[s];
                const bool left = d == -1 || d == -iw - 1 || d == iw - 1;
                const bool right = d == 1 || d == -iw + 1 || d == iw + 1;
                const bool up = d == -iw || d == -iw - 1 || d == -iw + 1;
                const bool down = d == iw || d == iw - 1 || d == iw + 1;
                if ((x == 0 && left) || (x == w - 1 && right) || (y == 0 && up) ||
                    (y == rows - 1 && down))
                    return "passable map edge";
            }
        }
        if (portals) {
            e.portalQ = static_cast<int *>(malloc(sizeof(int) * portals));
            e.portalR = static_cast<int *>(malloc(sizeof(int) * portals));
            if (!e.portalQ || !e.portalR)
                return "out of memory";
            uint32_t k = 0;
            for (uint32_t i = 0; i < size && k < portals; ++i) {
                const uint8_t *rec = recs + static_cast<size_t>(i) * 8;
                if ((*reinterpret_cast<const uint16_t *>(rec + 6) & 0xF000) == 0x5000) {
                    to_cube(e.layout, i, w, e.portalQ[k], e.portalR[k]);
                    ++k;
                }
            }
        }
        e.portals = portals;
        e.target = -1;
        e.ok = true;
        return nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        e.ok = false;
        return "memory fault";
    }
}

// Once per search: re-check the cheap parts, redo the full check if the graph changed.
static bool guide_check_same(const GuideGraph &e, const char *g) {
    __try {
        return e.graph == g && e.mask == *reinterpret_cast<const uint8_t *>(g + 0x7BC) &&
               e.width == *reinterpret_cast<const uint32_t *>(g + 0x6C) &&
               e.count == *reinterpret_cast<const uint32_t *>(g + 0xA8) &&
               e.recs == *reinterpret_cast<const uint8_t *const *>(g + 0xAC) &&
               e.tableSum == table_sum(g);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool guide_ready(const char *g) {
    const LONG serial = s_searchSerial;
    if (s_cur->serial == serial && s_cur->graph == g)
        return s_cur->ok;
    GuideGraph *e = nullptr;
    for (GuideGraph &c : s_ggs)
        if (c.graph == g) {
            e = &c;
            break;
        }
    if (!e) {
        e = &s_ggs[s_ggNext++ % 4];
        e->graph = nullptr;
    }
    if (!guide_check_same(*e, g)) {
        LARGE_INTEGER t0, t1;
        QueryPerformanceCounter(&t0);
        const char *why = guide_setup_inner(*e, g);
        QueryPerformanceCounter(&t1);
        e->graph = g;
        if (InterlockedIncrement(&s_guideLogs) <= 20) {
            if (why)
                Log("[twdll] [ARROW] exact guide OFF for graph %p: %s (vanilla search used) | step classes: %s",
                    g,
                    why,
                    e->info);
            else
                Log("[twdll] [ARROW] exact guide ON: graph %p, %u x %u hexes, mask %02X, cheapest step %d, "
                    "layout %s, %u crossing hexes, checked in %.1f ms | step classes: %s",
                    g,
                    e->width,
                    e->count / e->width,
                    static_cast<unsigned int>(e->mask),
                    e->minStep,
                    e->layout == 0 ? "odd-q" : "even-q",
                    e->portals,
                    hover_qpc_ms(t1.QuadPart - t0.QuadPart),
                    e->info);
        }
    }
    e->serial = serial;
    e->target = -1;
    s_cur = e;
    return e->ok;
}

static int guide_h(void *graph, int idx, int target) {
    const int h = reinterpret_cast<Heur_t>(g_orig_heur)(graph, idx, target);
    if (g_guideThread == 0 || g_guideThread != GetCurrentThreadId())
        return h;
    ++s_guideCalls;
    if (s_guideRaw < 6) {
        ++s_guideRaw;
        Log("[twdll] [ARROW] game heuristic value: hex %d -> target %d = %d (0x%08X)",
            idx, target, h, static_cast<unsigned int>(h));
    }
    const char *g = static_cast<const char *>(graph);
    if (!g || !guide_ready(g))
        return h;
    const uint32_t ui = static_cast<uint32_t>(idx), ut = static_cast<uint32_t>(target);
    if (ui >= s_cur->count || ut >= s_cur->count)
        return h;
    if (s_cur->target != target) {
        s_cur->target = target;
        to_cube(s_cur->layout, ut, s_cur->width, s_cur->targetQ, s_cur->targetR);
        s_cur->targetZone =
            *reinterpret_cast<const uint16_t *>(s_cur->recs + static_cast<size_t>(ut) * 8 + 6) & 0xFFF;
        int best = 0x7FFFFFFF;
        for (uint32_t k = 0; k < s_cur->portals; ++k) {
            const int d = cube_dist(s_cur->portalQ[k], s_cur->portalR[k], s_cur->targetQ, s_cur->targetR);
            if (d < best)
                best = d;
        }
        long long pb = s_cur->portals ? 500LL + static_cast<long long>(s_cur->minStep) * best : 0x3FFFFFFFLL;
        s_cur->portalBound = pb > 0x3FFFFFFF ? 0x3FFFFFFF : static_cast<int>(pb);
    }
    const int zone =
        *reinterpret_cast<const uint16_t *>(s_cur->recs + static_cast<size_t>(ui) * 8 + 6) & 0xFFF;
    if (zone != s_cur->targetZone)
        return h; // other landmass: the game's own value only
    int q, r;
    to_cube(s_cur->layout, ui, s_cur->width, q, r);
    long long add = static_cast<long long>(s_cur->minStep) * cube_dist(q, r, s_cur->targetQ, s_cur->targetR);
    if (add > s_cur->portalBound)
        add = s_cur->portalBound;
    ++s_guideUsed;
    if (s_guideSample < 8) {
        ++s_guideSample;
        Log("[twdll] [ARROW] guide sample: hex %d -> target %d, game value %d, added %lld",
            idx, target, h, add);
    }
    // The heap compares priority = cost + heuristic as UNSIGNED 32-bit (FUN_106b7e50 / 106b7e60),
    // and the game's own value is the same for every hex of the landmass. Adding our bound keeps
    // the order exact as long as cost + value + bound never wraps past 2^32 for one hex but not
    // another:
    //  - value small enough that value + bound + 0x10000000 (cost headroom) stays below 2^32, or
    //  - value = -k with k <= cheapest step and <= 500: every hex but the start has cost >= k, so
    //    all of them wrap the same way (vanilla's start hex already sits at -k).
    // Anything else: the game's value alone.
    const unsigned long long H = static_cast<uint32_t>(h);
    const unsigned long long A = static_cast<unsigned long long>(add);
    const unsigned long long k = 0x100000000ULL - H;
    if (H + A + 0x10000000ULL <= 0xFFFFFFFFULL ||
        (H > 0xFFFF0000ULL && k <= static_cast<unsigned long long>(s_cur->minStep) && k <= 500ULL))
        return static_cast<int>(static_cast<uint32_t>(H + A));
    --s_guideUsed;
    return h;
}

// __fastcall with a dummy EDX == __thiscall layout; callee pops the 2 stack args (ret 8).
static int __fastcall guide_site_a(void *graph, void * /*edx*/, int idx, int target) {
    return guide_h(graph, idx, target); // 10B9700A, FUN_10b97000 (relax FUN_106e4710)
}
static int __fastcall guide_site_b(void *graph, void * /*edx*/, int idx, int target) {
    return guide_h(graph, idx, target); // 106B7CAE, FUN_106b7ca0 (relax FUN_106e4450 / 45b0)
}

// The verified loops (all __thiscall, 6 stack args, ret 0x18). Guided only when an arrow / hover
// check on this thread asked for it; every other search (AI, orders, zone) runs as before.
typedef void *(__thiscall *Loop_t)(
    void *s, void *res, uint32_t a1, uint32_t a2, void *goal, uint32_t a4, void *a5);

static void *guided_loop(int slot,
                         void *s,
                         void *res,
                         uint32_t a1,
                         uint32_t a2,
                         void *goal,
                         uint32_t a4,
                         void *a5) {
    g_loopRuns[slot] += g_inArrow;
    const DWORD tid = GetCurrentThreadId();
    const bool guided = g_guideOn && g_guideWant == tid;
    const DWORD prev = g_guideThread;
    if (guided) {
        InterlockedIncrement(&s_searchSerial); // re-check the graph once per search
        g_guideThread = tid;
    }
    void *r = reinterpret_cast<Loop_t>(g_loopOrig[slot])(s, res, a1, a2, goal, a4, a5);
    if (guided)
        g_guideThread = prev;
    return r;
}

// __fastcall with a dummy EDX == __thiscall layout.
static void *__fastcall loop_run_4(
    void *s, void *, void *res, uint32_t a1, uint32_t a2, void *goal, uint32_t a4, void *a5) {
    return guided_loop(4, s, res, a1, a2, goal, a4, a5); // FUN_10a0e0f0
}
static void *__fastcall loop_run_5(
    void *s, void *, void *res, uint32_t a1, uint32_t a2, void *goal, uint32_t a4, void *a5) {
    return guided_loop(5, s, res, a1, a2, goal, a4, a5); // FUN_10a0e360
}
static void *__fastcall loop_run_8(
    void *s, void *, void *res, uint32_t a1, uint32_t a2, void *goal, uint32_t a4, void *a5) {
    return guided_loop(8, s, res, a1, a2, goal, a4, a5); // FUN_10b331b0
}

// Arrow / hover check scope: searches started inside it may be guided.
struct GuideScope {
    DWORD prev;
    bool on;
    explicit GuideScope(bool enable) : prev(g_guideWant), on(enable && g_guideOn) {
        if (on)
            g_guideWant = GetCurrentThreadId();
    }
    ~GuideScope() {
        if (on)
            g_guideWant = prev;
    }
};

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
    bool r;
    if (g_guideVerify && g_guideOn) {
        // Verify mode: vanilla first, then guided from the same state; compare.
        const bool rv = reinterpret_cast<CanReach_t>(g_orig_can_reach)(pf, army, cell, ctx);
        float fv[4];
        std::memcpy(fv, pff, sizeof(fv));
        std::memcpy(pff, before, sizeof(before));
        {
            GuideScope gs(true);
            r = reinterpret_cast<CanReach_t>(g_orig_can_reach)(pf, army, cell, ctx);
        }
        ++s_verifyRuns;
        if (rv != r) {
            ++s_verifyDiffs;
            if (s_verifyDiffs <= 50)
                Log("[twdll] [VERIFY] DIFFERENT: army %d hex %08X vanilla says %s, guided says %s",
                    army,
                    static_cast<unsigned int>(c),
                    rv ? "reachable" : "not reachable",
                    r ? "reachable" : "not reachable");
        } else if (std::memcmp(fv, pff, sizeof(fv)) != 0) {
            ++s_verifyFloatDiffs;
        }
        if (s_verifyRuns % 100 == 0)
            Log("[twdll] [VERIFY] %ld hover checks compared: %ld different answers, %ld other differences",
                s_verifyRuns,
                s_verifyDiffs,
                s_verifyFloatDiffs);
    } else {
        GuideScope gs(true);
        r = reinterpret_cast<CanReach_t>(g_orig_can_reach)(pf, army, cell, ctx);
    }
    QueryPerformanceCounter(&t1);
    const double ms = hover_qpc_ms(t1.QuadPart - t0.QuadPart);
    s_hOrigMs += ms;
    if (ms > s_hMaxMs)
        s_hMaxMs = ms;
    ++s_hvRuns;
    s_hvMs += ms;

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
// Route refinement memo (arrow only). After the main search, FUN_10b415d0 refines the arrow route
// with ~50 short searches FUN_10b37080(res, path, from, to, arg) (call at 10B41788). Each one
// starts fresh (FUN_10b37110: new stamp, empty open list) and leaves only res = {found, cost}
// and the hexes in the path vector {cap, size, data}; FUN_10b415d0 reads nothing else. Moving the
// cursor by a hex repeats most (from, to) pairs, and the same inputs on an unchanged map give the
// same answer, so a repeated pair gets the saved answer. Saved answers are dropped when a drag
// starts, after any move order (g_hover_gen) and after 2 s. twdll_arrow_memo_off.txt turns it
// off; in verify mode every saved answer is also searched for real and compared ([MEMO] lines).
// ---------------------------------------------------------------------------
static constexpr uintptr_t FN_REFINE_SEARCH = 0x10B37080; // __thiscall, 5 stack args, ret 0x14
static uintptr_t g_orig_refine = 0;
typedef void *(__thiscall *Refine_t)(
    void *s, void *res, uint32_t *vec, uint32_t from, uint32_t to, uint32_t arg);
static bool g_memoOn = true;

struct MemoEntry {
    bool used;
    void *s;
    uint32_t *vec;
    uint32_t from, to, arg;
    uint32_t pos[4]; // graph+0xEC..0xF8 (start / goal position floats), as bits
    uint32_t res[2];
    uint32_t n;
    uint32_t *hexes;
};
static constexpr int kMemo = 512;
static MemoEntry s_memo[kMemo] = {};
static unsigned s_memoNext = 0;
static LONG s_memoGen = 0;
static DWORD s_memoTick = 0;
static LONG s_memoHits = 0, s_memoMiss = 0, s_memoNoRoom = 0, s_memoChecked = 0, s_memoDiffs = 0;

static void memo_clear() {
    for (MemoEntry &m : s_memo) {
        free(m.hexes);
        m = MemoEntry{};
    }
    s_memoNext = 0;
}

static bool memo_read_pos(void *s, uint32_t out[4]) {
    __try {
        const char *graph = *static_cast<const char *const *>(s);
        std::memcpy(out, graph + 0xEC, 16);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static void *__fastcall refine_site(
    void *s, void * /*edx*/, void *res, uint32_t *vec, uint32_t from, uint32_t to, uint32_t arg) {
    Refine_t orig = reinterpret_cast<Refine_t>(g_orig_refine);
    uint32_t pos[4];
    if (!g_inArrow || !g_memoOn || !vec || !memo_read_pos(s, pos))
        return orig(s, res, vec, from, to, arg);

    MemoEntry *hit = nullptr;
    for (MemoEntry &m : s_memo)
        if (m.used && m.s == s && m.vec == vec && m.from == from && m.to == to && m.arg == arg &&
            std::memcmp(m.pos, pos, sizeof(pos)) == 0) {
            hit = &m;
            break;
        }
    if (hit && vec[0] >= hit->n && (hit->n == 0 || vec[2] != 0)) {
        if (g_guideVerify) {
            // Verify: search for real and compare with the saved answer.
            void *r = orig(s, res, vec, from, to, arg);
            const uint32_t *rr = static_cast<const uint32_t *>(res);
            const bool same = (rr[0] & 0xFF) == (hit->res[0] & 0xFF) && rr[1] == hit->res[1] && vec[1] == hit->n &&
                              (hit->n == 0 ||
                               std::memcmp(reinterpret_cast<const void *>(vec[2]), hit->hexes, hit->n * 4) == 0);
            ++s_memoChecked;
            if (!same && ++s_memoDiffs <= 30)
                Log("[twdll] [MEMO] DIFFERENT: %08X -> %08X saved found %u cost %u (%u hexes), real found %u cost %u (%u hexes)",
                    from,
                    to,
                    hit->res[0] & 0xFF,
                    hit->res[1],
                    hit->n,
                    rr[0] & 0xFF,
                    rr[1],
                    vec[1]);
            if (s_memoChecked % 200 == 0)
                Log("[twdll] [MEMO] %ld saved answers checked against a real search: %ld different",
                    s_memoChecked,
                    s_memoDiffs);
            return r;
        }
        uint32_t *r = static_cast<uint32_t *>(res);
        r[0] = (r[0] & 0xFFFFFF00u) | (hit->res[0] & 0xFF);
        r[1] = hit->res[1];
        if (hit->n)
            std::memcpy(reinterpret_cast<void *>(vec[2]), hit->hexes, hit->n * 4);
        vec[1] = hit->n;
        ++s_memoHits;
        return res;
    }
    if (hit)
        ++s_memoNoRoom;
    void *r = orig(s, res, vec, from, to, arg);
    ++s_memoMiss;
    const uint32_t n = vec[1];
    if (n > 100000 || (n && !vec[2]))
        return r;
    MemoEntry &m = hit ? *hit : s_memo[s_memoNext++ % kMemo];
    free(m.hexes);
    m = MemoEntry{};
    if (n) {
        m.hexes = static_cast<uint32_t *>(malloc(n * 4));
        if (!m.hexes)
            return r;
        std::memcpy(m.hexes, reinterpret_cast<const void *>(vec[2]), n * 4);
    }
    const uint32_t *rr = static_cast<const uint32_t *>(res);
    m.used = true;
    m.s = s;
    m.vec = vec;
    m.from = from;
    m.to = to;
    m.arg = arg;
    std::memcpy(m.pos, pos, sizeof(pos));
    m.res[0] = rr[0];
    m.res[1] = rr[1];
    m.n = n;
    return r;
}

// ---------------------------------------------------------------------------
// Arrow route timing (measure only, the game's search runs unchanged).
// FUN_11416990 -> FUN_10a19080 (site B) builds the route arrow; site A (FUN_10a0c5c0) is the
// other caller. One [ARROW] line per 5 s while either runs (first 60 lines).
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
static LONG s_dragReports = 0;

static uint32_t drag_measure(int site, void *pf, int army, uint32_t *cell, void *out, long ctx) {
    const DWORD now = GetTickCount();
    if (s_dragLastReport == 0)
        s_dragLastReport = now;
    if (now - s_dragLastReport >= 5000) {
        if ((s_drag[0].calls || s_drag[1].calls) && s_dragReports < 60) {
            ++s_dragReports;
            Log("[twdll] [ARROW] last 5s: arrow route calls %ld, %.0f ms total, %.2f ms/call, max %.1f ms | "
                "hover checks %ld, %.0f ms total | other calls %ld, %.0f ms | guide %s, used on %ld of %ld hexes",
                s_drag[1].calls,
                s_drag[1].ms,
                s_drag[1].calls ? s_drag[1].ms / s_drag[1].calls : 0.0,
                s_drag[1].maxMs,
                s_hvRuns,
                s_hvMs,
                s_drag[0].calls,
                s_drag[0].ms,
                g_guideOn ? "on" : "off",
                s_guideUsed,
                s_guideCalls);
        }
        if (s_drag[1].calls && s_dragReports <= 60) {
            char line[1024];
            int len = 0;
            for (int i = 0; i < kLoops; ++i) {
                if (!g_loopRuns[i] && !g_loopPops[i])
                    continue;
                const int n = snprintf(line + len,
                                   sizeof(line) - len,
                                   " | %08X: %ld runs, %ld hexes (%.0f per run)",
                                   static_cast<unsigned int>(kLoopFn[i]),
                                   g_loopRuns[i],
                                   g_loopPops[i],
                                   g_loopRuns[i] ? static_cast<double>(g_loopPops[i]) / g_loopRuns[i] : 0.0);
                if (n < 0 || len + n >= static_cast<int>(sizeof(line)) - 1)
                    break;
                len += n;
            }
            Log("[twdll] [SEARCH] during %ld arrow routes:%s", s_drag[1].calls, len > 0 ? line : " no search loop ran");
        }
        for (int i = 0; i < kLoops; ++i)
            g_loopRuns[i] = g_loopPops[i] = 0;
        s_drag[0] = DragStats{};
        s_drag[1] = DragStats{};
        s_hvRuns = 0;
        s_hvMs = 0.0;
        s_guideUsed = s_guideCalls = 0;
        if ((s_memoHits || s_memoMiss) && s_dragReports <= 60)
            Log("[twdll] [MEMO] refine searches: %ld reused, %ld searched%s",
                s_memoHits,
                s_memoMiss,
                s_memoNoRoom ? " (some saved answers did not fit the path buffer)" : "");
        s_memoHits = s_memoMiss = s_memoNoRoom = 0;
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

// Arrow route: the game's own search, guided by the exact lower bound above.
static uint32_t __fastcall drag_site_b(
    void *pf, void *, int army, uint32_t *cell, void *out, long ctx) {
    GuideScope gs(true);
    const DWORD now = GetTickCount();
    static DWORD s_memoStart = 0;
    if (now - s_memoTick > 300 || s_memoGen != g_hover_gen || now - s_memoStart > 2000) {
        s_memoStart = now;
        memo_clear(); // new drag, or something moved since the saved answers
        s_memoGen = g_hover_gen;
    }
    s_memoTick = now;
    g_inArrow = 1;
    const uint32_t r = drag_measure(1, pf, army, cell, out, ctx);
    g_inArrow = 0;
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
    {"drag_b", 0x114169A2, FN_DRAG_PATH, (void *)&drag_site_b, -1, 0, false}, // 11 arrow + guide
    // [SEARCH] diagnostics: one counter at each search loop's caller and heap pop
    {"loop_106b8010", 0x106B7FEA, 0x106B8010, (void *)&loop_run_0, -1, 0, false},
    {"pop_106b8010", 0x106B8052, FN_HEAP_POP, (void *)&loop_pop_0, -1, 0, false},
    {"loop_106b8260", 0x106B823A, 0x106B8260, (void *)&loop_run_1, -1, 0, false},
    {"pop_106b8260", 0x106B82A2, FN_HEAP_POP, (void *)&loop_pop_1, -1, 0, false},
    {"loop_106b84b0", 0x106B848A, 0x106B84B0, (void *)&loop_run_2, -1, 0, false},
    {"pop_106b84b0", 0x106B84F2, FN_HEAP_POP, (void *)&loop_pop_2, -1, 0, false},
    {"loop_106b8700", 0x106B86DA, 0x106B8700, (void *)&loop_run_3, -1, 0, false},
    {"pop_106b8700", 0x106B8742, FN_HEAP_POP, (void *)&loop_pop_3, -1, 0, false},
    {"loop_10a0e0f0", 0x10A0E0CA, 0x10A0E0F0, (void *)&loop_run_4, -1, 0, false},
    {"pop_10a0e0f0", 0x10A0E132, FN_HEAP_POP, (void *)&loop_pop_4, -1, 0, false},
    {"loop_10a0e360", 0x10A0E33A, 0x10A0E360, (void *)&loop_run_5, -1, 0, false},
    {"pop_10a0e360", 0x10A0E3A2, FN_HEAP_POP, (void *)&loop_pop_5, -1, 0, false},
    {"loop_10aa3590", 0x10AA356A, 0x10AA3590, (void *)&loop_run_6, -1, 0, false},
    {"pop_10aa3590", 0x10AA35D2, FN_HEAP_POP, (void *)&loop_pop_6, -1, 0, false},
    {"loop_10aa3800", 0x10AA37DA, 0x10AA3800, (void *)&loop_run_7, -1, 0, false},
    {"pop_10aa3800", 0x10AA3842, FN_HEAP_POP, (void *)&loop_pop_7, -1, 0, false},
    {"loop_10b331b0", 0x10B3318A, 0x10B331B0, (void *)&loop_run_8, -1, 0, false},
    {"pop_10b331b0", 0x10B331F4, FN_HEAP_POP, (void *)&loop_pop_8, -1, 0, false},
    {"loop_10b33440", 0x10B3341A, 0x10B33440, (void *)&loop_run_9, -1, 0, false},
    {"pop_10b33440", 0x10B33484, FN_HEAP_POP, (void *)&loop_pop_9, -1, 0, false},
    {"loop_10b336d0", 0x10B336AA, 0x10B336D0, (void *)&loop_run_10, -1, 0, false},
    {"pop_10b336d0", 0x10B33712, FN_HEAP_POP, (void *)&loop_pop_10, -1, 0, false},
    {"loop_10b33920", 0x10B338FA, 0x10B33920, (void *)&loop_run_11, -1, 0, false},
    {"pop_10b33920", 0x10B33962, FN_HEAP_POP, (void *)&loop_pop_11, -1, 0, false},
    {"guide_heur_a", 0x10B9700A, FN_HEUR, (void *)&guide_site_a, -1, 0, false}, // in FUN_10b97000
    {"guide_heur_b", 0x106B7CAE, FN_HEUR, (void *)&guide_site_b, -1, 0, false}, // in FUN_106b7ca0
    {"route_memo", 0x10B41788, FN_REFINE_SEARCH, (void *)&refine_site, -1, 0, false}, // in FUN_10b415d0
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
    for (int i = 0; i < kLoops; ++i)
        g_loopOrig[i] = base + (kLoopFn[i] - GH);
    g_popOrig = base + (FN_HEAP_POP - GH);
    g_hex_dist = base + (FN_HEX_DIST - GH);
    g_orig_refine = base + (FN_REFINE_SEARCH - GH);
    {
        char path[MAX_PATH];
        const DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
        char *slash = (n > 0 && n < MAX_PATH) ? strrchr(path, '\\') : nullptr;
        if (slash && static_cast<size_t>(slash - path) + 32 < MAX_PATH) {
            strcpy(slash + 1, "twdll_arrow_exact_off.txt");
            g_guideOn = GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
            strcpy(slash + 1, "twdll_arrow_verify.txt");
            g_guideVerify = GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
            strcpy(slash + 1, "twdll_arrow_memo_off.txt");
            g_memoOn = GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
        }
        Log("[twdll] [ARROW] exact guide %s, route memo %s%s",
            g_guideOn ? "enabled" : "disabled (twdll_arrow_exact_off.txt)",
            g_memoOn ? "enabled" : "disabled (twdll_arrow_memo_off.txt)",
            g_guideVerify ? ", verify mode (twdll_arrow_verify.txt)" : "");
    }
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
    g_guideThread = 0;
    g_guideWant = 0;
    memo_clear();
    for (GuideGraph &c : s_ggs) {
        free(c.portalQ);
        free(c.portalR);
        c = GuideGraph{};
    }
    s_cur = &s_ggs[0];
    g_installed = false;
    Log("[twdll] [OVERLAY_FIX] restored original code");
}