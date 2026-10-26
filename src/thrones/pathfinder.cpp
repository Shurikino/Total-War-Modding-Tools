// src/thrones/pathfinder.cpp
//
// Skip-cache for the campaign pathfinder dispatchers (8 confirmed via Ghidra,
// one per unit/movement subtype). Each dispatcher recomputes a full flood-fill
// search on every call, even when nothing changed since the last call for the
// same object. This hook skips the recompute when position + destination are
// unchanged, which is what causes the campaign map stutter on reselect.
//
// Confirmed via Ghidra (empire.retail.dll):
//   - 8 dispatchers at fixed RVA offsets, 0x250 bytes apart, starting at 0xC96900
//   - Each dispatcher: this+0xec/0xf0 = current pos (x,y), this+0xf4/0xf8 = dest (x,y)
//   - Hardcoded addresses used instead of a byte-pattern scan, because the
//     candidate signature's first 6 bytes are common x86 prologue bytes and
//     risked a false-positive match elsewhere in a 10+MB binary.

#include "common/tw.h"
#include "common/campaign_hooks.h"
#include <MinHook.h>
#include <windows.h>
#include <unordered_map>
#include <mutex>
#include <cstdint>
extern volatile LONG g_hover_gen; // overlay_fix.cpp: invalidates the hover cache on move orders

namespace {

// RVA = address - 0x10000000 (assumed module load base, per earlier analysis)
constexpr uintptr_t kDispatcherRVAs[9] = {
    0xC96900,
    0xC96B50,
    0xC96DA0,
    0xC96FF0,
    0xC97240,
    0xC97490,
    0xC976E0,
    0xC97930,
    0xB35F10 // FUN_10b35f10, the 9th dispatcher, movement-range overlay path
};

typedef char *(__thiscall *Dispatch_t)(void *thisPtr,
                                       char *param_1,
                                       uint32_t param_2,
                                       uint32_t param_3,
                                       void *param_4,
                                       uint32_t param_5,
                                       uint32_t param_6);

void *g_origDispatch[9] = {};

struct PosKey {
    float cx, cy, dx, dy;
    bool operator==(const PosKey &o) const {
        return cx == o.cx && cy == o.cy && dx == o.dx && dy == o.dy;
    }
};

struct CacheEntry {
    PosKey pos;
    char resultFlag;
    int resultValue;
    DWORD timestamp;
};

std::unordered_map<void *, CacheEntry> g_lastSeen;
std::mutex g_lastSeenMutex;

// Shared logic for all 8 hooks. `slot` identifies which original to call.
// --- slot-8 diagnostics (temporary) ---
struct Pf8Stats {
    LONG calls = 0, hits = 0, missNew = 0, missPos = 0, missAge = 0;
    double origMs = 0.0, origMaxMs = 0.0;
    DWORD lastReport = 0;
};
Pf8Stats g_pf8;

double QpcToMs(LONGLONG ticks) {
    static const LONGLONG freq = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return f.QuadPart;
    }();
    return static_cast<double>(ticks) * 1000.0 / static_cast<double>(freq);
}

// Shared logic for all 9 hooks. `slot` identifies which original to call.
char *DispatchCommon(int slot,
                     void *thisPtr,
                     char *param_1,
                     uint32_t param_2,
                     uint32_t param_3,
                     void *param_4,
                     uint32_t param_5,
                     uint32_t param_6) {
    // Only slot 8 (FUN_10b35f10, the movement-range overlay dispatcher) is cached.
    // Slots 0-7 are the "issue move order" dispatchers used during AI End Turn;
    // caching their side effects was confirmed to cause a crash.
    if (slot != 8) {
        InterlockedIncrement(&g_hover_gen);
        return reinterpret_cast<Dispatch_t>(g_origDispatch[slot])(
            thisPtr, param_1, param_2, param_3, param_4, param_5, param_6);
    }

    float *f = reinterpret_cast<float *>(thisPtr);
    PosKey now{f[0xec / 4], f[0xf0 / 4], f[0xf4 / 4], f[0xf8 / 4]};
    DWORD nowTick = GetTickCount();

    constexpr DWORD kCacheMaxAgeMs = 500;
    constexpr DWORD kFullClearIntervalMs = 30000;

    {
        std::lock_guard<std::mutex> lock(g_lastSeenMutex);

        static DWORD s_lastFullClear = nowTick;
        if (nowTick - s_lastFullClear > kFullClearIntervalMs) {
            g_lastSeen.clear();
            s_lastFullClear = nowTick;
        }

        if (g_pf8.lastReport == 0)
            g_pf8.lastReport = nowTick;
        if (nowTick - g_pf8.lastReport >= 5000) {
            if constexpr (TWDLL_DEBUG_STATS != 0) Log("[twdll] [PF8] last 5s: calls %ld, hits %ld, miss new %ld / pos %ld / age %ld, "
                "original %.0f ms total (max %.0f ms)",
                g_pf8.calls,
                g_pf8.hits,
                g_pf8.missNew,
                g_pf8.missPos,
                g_pf8.missAge,
                g_pf8.origMs,
                g_pf8.origMaxMs);
            g_pf8 = Pf8Stats{};
            g_pf8.lastReport = nowTick;
        }
        ++g_pf8.calls;

        auto it = g_lastSeen.find(thisPtr);
        if (it == g_lastSeen.end()) {
            ++g_pf8.missNew;
        } else if (!(it->second.pos == now)) {
            ++g_pf8.missPos;
        } else if ((nowTick - it->second.timestamp) >= kCacheMaxAgeMs) {
            ++g_pf8.missAge;
        } else {
            ++g_pf8.hits;
            *param_1 = it->second.resultFlag;
            *reinterpret_cast<int *>(param_1 + 4) = it->second.resultValue;
            return param_1;
        }
    }

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    char *ret = reinterpret_cast<Dispatch_t>(g_origDispatch[slot])(
        thisPtr, param_1, param_2, param_3, param_4, param_5, param_6);
    QueryPerformanceCounter(&t1);
    const double ms = QpcToMs(t1.QuadPart - t0.QuadPart);

    CacheEntry entry;
    entry.pos = now;
    entry.resultFlag = *param_1;
    entry.resultValue = *reinterpret_cast<int *>(param_1 + 4);
    entry.timestamp = nowTick;

    {
        std::lock_guard<std::mutex> lock(g_lastSeenMutex);
        g_lastSeen[thisPtr] = entry;
        g_pf8.origMs += ms;
        if (ms > g_pf8.origMaxMs)
            g_pf8.origMaxMs = ms;
    }
    return ret;
}

// MinHook needs a distinct function pointer per installed hook (each stores
// its own "original" to call onward), so this macro generates 8 thin shims
// that all forward into the one shared DispatchCommon above.
#define DEFINE_DISPATCH_HOOK(N)                                                                    \
    char *__fastcall HookedDispatch##N(void *thisPtr,                                              \
                                       void * /*edx, unused*/,                                     \
                                       char *param_1,                                              \
                                       uint32_t param_2,                                           \
                                       uint32_t param_3,                                           \
                                       void *param_4,                                              \
                                       uint32_t param_5,                                           \
                                       uint32_t param_6) {                                         \
        return DispatchCommon(N, thisPtr, param_1, param_2, param_3, param_4, param_5, param_6);   \
    }

DEFINE_DISPATCH_HOOK(0)
DEFINE_DISPATCH_HOOK(1)
DEFINE_DISPATCH_HOOK(2)
DEFINE_DISPATCH_HOOK(3)
DEFINE_DISPATCH_HOOK(4)
DEFINE_DISPATCH_HOOK(5)
DEFINE_DISPATCH_HOOK(6)
DEFINE_DISPATCH_HOOK(7)
DEFINE_DISPATCH_HOOK(8)

typedef char *(__fastcall *HookFn_t)(
    void *, void *, char *, uint32_t, uint32_t, void *, uint32_t, uint32_t);
const HookFn_t kHookFns[9] = {&HookedDispatch0,
                              &HookedDispatch1,
                              &HookedDispatch2,
                              &HookedDispatch3,
                              &HookedDispatch4,
                              &HookedDispatch5,
                              &HookedDispatch6,
                              &HookedDispatch7,
                              &HookedDispatch8};
uintptr_t g_installedAddr[9] = {};
} // namespace

void install_thrones_pathfinder_hook(uintptr_t base, size_t /*size*/) {
    for (int i = 0; i < 9; ++i) {
        uintptr_t addr = base + kDispatcherRVAs[i];
        MH_STATUS mhs = MH_CreateHook(reinterpret_cast<void *>(addr),
                                      reinterpret_cast<void *>(kHookFns[i]),
                                      &g_origDispatch[i]);
        if (mhs != MH_OK) {
            Log("[twdll] [PATHFINDER_DISPATCH_%d] MH_CreateHook failed (%d)", i, mhs);
            continue;
        }
        mhs = MH_EnableHook(reinterpret_cast<void *>(addr));
        if (mhs != MH_OK) {
            Log("[twdll] [PATHFINDER_DISPATCH_%d] MH_EnableHook failed (%d)", i, mhs);
            continue;
        }
        g_installedAddr[i] = addr;
        Log("[twdll] [PATHFINDER_DISPATCH_%d] hook installed OK at 0x%08X",
            i,
            static_cast<unsigned int>(addr));
    }
}

void uninstall_thrones_pathfinder_hook() {
    // Deliberately not calling MH_DisableHook/MH_RemoveHook here. Removing
    // these specific hooks during scene teardown (main menu / exit) was
    // causing a silent hang; simply leaving them installed for the life of
    // the process is safe, since DispatchCommon has no per-scene state that
    // needs resetting other than the cache map itself.
    std::lock_guard<std::mutex> lock(g_lastSeenMutex);
    g_lastSeen.clear();
}