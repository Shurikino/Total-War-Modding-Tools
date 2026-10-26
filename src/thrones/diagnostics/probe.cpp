// src/thrones/probe.cpp
//
// Diagnostic-only: counts calls into the two shared pathfinding primitives
// (heap pop and edge relaxation) and logs the caller's return address, so we
// can confirm whether army reselection actually triggers a flood-fill and,
// if so, identify the real top-level function responsible (via the logged
// caller addresses). Not meant to stay in the build long-term.

#include "common/tw.h"
#include "common/campaign_hooks.h"
#include <MinHook.h>
#include <windows.h>
#include <intrin.h>
#include <atomic>
#include <cstdint>

namespace {

constexpr uintptr_t kHeapPopRVA = 0x6c0f70; // FUN_106c0f70
constexpr uintptr_t kRelaxRVA = 0xcc8a90;   // FUN_10cc8a90

typedef int(__fastcall *HeapPop_t)(int param_1);
typedef void(__thiscall *Relax_t)(void *thisPtr, int param_1, unsigned int param_2);

void *g_origHeapPop = nullptr;
void *g_origRelax = nullptr;

std::atomic<long> g_heapPopCount{0};
std::atomic<long> g_relaxCount{0};

int __fastcall HookedHeapPop(int param_1) {
    long n = ++g_heapPopCount;
    if (n <= 30 || n % 1000 == 0) {
        Log("[twdll][PROBE] heap-pop call #%ld caller=0x%08X",
            n,
            reinterpret_cast<unsigned int>(_ReturnAddress()));
    }
    return reinterpret_cast<HeapPop_t>(g_origHeapPop)(param_1);
}

// Same fastcall+dummy-edx shim pattern already used for the 8 dispatcher
// hooks, since MinHook needs a raw function-pointer match for the thiscall target.
void __fastcall HookedRelax(void *thisPtr,
                            void * /*edx, unused*/,
                            int param_1,
                            unsigned int param_2) {
    long n = ++g_relaxCount;
    if (n <= 30 || n % 1000 == 0) {
        Log("[twdll][PROBE] relax call #%ld caller=0x%08X",
            n,
            reinterpret_cast<unsigned int>(_ReturnAddress()));
    }
    reinterpret_cast<Relax_t>(g_origRelax)(thisPtr, param_1, param_2);
}

} // namespace

void install_thrones_probe_hooks(uintptr_t base, size_t /*size*/) {
    uintptr_t heapPopAddr = base + kHeapPopRVA;
    MH_STATUS mhs = MH_CreateHook(reinterpret_cast<void *>(heapPopAddr),
                                  reinterpret_cast<void *>(&HookedHeapPop),
                                  &g_origHeapPop);
    if (mhs == MH_OK)
        mhs = MH_EnableHook(reinterpret_cast<void *>(heapPopAddr));
    Log("[twdll][PROBE] heap-pop hook %s at 0x%08X",
        (mhs == MH_OK) ? "installed OK" : "FAILED",
        static_cast<unsigned int>(heapPopAddr));

    uintptr_t relaxAddr = base + kRelaxRVA;
    mhs = MH_CreateHook(
        reinterpret_cast<void *>(relaxAddr), reinterpret_cast<void *>(&HookedRelax), &g_origRelax);
    if (mhs == MH_OK)
        mhs = MH_EnableHook(reinterpret_cast<void *>(relaxAddr));
    Log("[twdll][PROBE] relax hook %s at 0x%08X",
        (mhs == MH_OK) ? "installed OK" : "FAILED",
        static_cast<unsigned int>(relaxAddr));
}

void uninstall_thrones_probe_hooks() {
    if (g_origHeapPop) {
        MH_DisableHook(reinterpret_cast<void *>(g_origHeapPop));
    }
    if (g_origRelax) {
        MH_DisableHook(reinterpret_cast<void *>(g_origRelax));
    }
}