// src/thrones/dbkey_cache.cpp
//
// Fixes the once-per-second campaign HUD hitch (diplomatic_relations_religion lookups).
//
// FUN_11203d10 is a 3-key DB find (religion_A;religion_B;campaign). It first looks the key up
// with the current campaign ("...;vik_attila") in FUN_100f1660, an open-addressing hash index
// with linear probing. No row has a campaign set, so that lookup always fails, and a failing
// lookup has to walk the index up to the next empty slot. The HUD does this ~8000 times per
// second in 1-second bursts.
//
// DB indexes do not change after the database is loaded (twdll loads after that), so each
// distinct (index, key) result is computed once and then served from a hash map.
//
// One E8 call-site patch at 11203D38, verified before writing, restored on uninstall.

#include "../common/log.h"
#include <windows.h>
#include <cstdint>
#include <string>
#include <unordered_map>

static constexpr uintptr_t GH = 0x10000000;          // Ghidra image base
static constexpr uintptr_t SITE_LOOKUP = 0x11203D38; // CALL FUN_100f1660 in FUN_11203d10
static constexpr uintptr_t FN_LOOKUP = 0x100F1660;   // int* __thiscall(index, key*), ret 4

typedef void *(__thiscall *Lookup_t)(void *index, const int *key);

static uintptr_t g_base = 0;
static Lookup_t g_orig = nullptr;
static bool g_active = false;
static int32_t g_orig_rel = 0;

static SRWLOCK g_lock = SRWLOCK_INIT;
static std::unordered_map<std::string, void *> *g_cache = nullptr;

static void *__fastcall cached_lookup(void *index, void * /*edx*/, const int *key) {
    // Key layout (from FUN_100fbf60): +0 length in bytes, +8 pointer to the bytes.
    const int len = key ? key[0] : -1;
    const char *data = key ? reinterpret_cast<const char *>(key[2]) : nullptr;
    if (len < 0 || len > 1024 || (len > 0 && !data) || !g_cache)
        return g_orig(index, key);

    std::string k;
    k.reserve(sizeof(index) + len);
    k.append(reinterpret_cast<const char *>(&index), sizeof(index));
    k.append(data, len);

    AcquireSRWLockShared(&g_lock);
    const auto it = g_cache->find(k);
    const bool found = it != g_cache->end();
    void *r = found ? it->second : nullptr;
    ReleaseSRWLockShared(&g_lock);
    if (found)
        return r;

    r = g_orig(index, key);

    AcquireSRWLockExclusive(&g_lock);
    g_cache->emplace(std::move(k), r);
    ReleaseSRWLockExclusive(&g_lock);
    return r;
}

static bool write_rel(uintptr_t call, int32_t rel) {
    void *p = reinterpret_cast<void *>(call + 1);
    DWORD old;
    if (!VirtualProtect(p, 4, PAGE_EXECUTE_READWRITE, &old))
        return false;
    *reinterpret_cast<volatile int32_t *>(p) = rel;
    VirtualProtect(p, 4, old, &old);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(call), 5);
    return true;
}

void install_dbkey_cache() {
    if (g_active)
        return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleA("empire.retail.dll"));
    if (!g_base) {
        Log("[twdll] [DBKEY_CACHE] empire.retail.dll not found");
        return;
    }
    const uintptr_t site = g_base + (SITE_LOOKUP - GH);
    const uintptr_t fn = g_base + (FN_LOOKUP - GH);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(site);
    if (p[0] != 0xE8) {
        Log("[twdll] [DBKEY_CACHE] no CALL at %08X, skipped", static_cast<unsigned>(SITE_LOOKUP));
        return;
    }
    const int32_t rel = *reinterpret_cast<const int32_t *>(p + 1);
    if (site + 5 + rel != fn) {
        Log("[twdll] [DBKEY_CACHE] CALL at %08X does not target %08X, skipped",
            static_cast<unsigned>(SITE_LOOKUP), static_cast<unsigned>(FN_LOOKUP));
        return;
    }
    g_orig = reinterpret_cast<Lookup_t>(fn);
    if (!g_cache)
        g_cache = new std::unordered_map<std::string, void *>();
    g_cache->reserve(8192);
    g_orig_rel = rel;
    const int32_t nrel =
        static_cast<int32_t>(reinterpret_cast<uintptr_t>(&cached_lookup) - (site + 5));
    g_active = write_rel(site, nrel);
    Log("[twdll] [DBKEY_CACHE] %s", g_active ? "active" : "FAILED (VirtualProtect)");
}

void uninstall_dbkey_cache() {
    if (!g_active)
        return;
    write_rel(g_base + (SITE_LOOKUP - GH), g_orig_rel);
    g_active = false;
    AcquireSRWLockExclusive(&g_lock);
    delete g_cache;
    g_cache = nullptr;
    ReleaseSRWLockExclusive(&g_lock);
}
