#include "../common/campaign_hooks.h"
#include "../common/log.h"
#include <windows.h>
#include <psapi.h>
#include <MinHook.h>

// Forward declarations to the game-specific modules
extern void install_world_hook(uintptr_t base, size_t size);
extern void install_campaign_ui_hook(uintptr_t base, size_t size);
extern void install_settlement_slots_hook(uintptr_t base, size_t size);
extern void install_model_hook(uintptr_t base, size_t size);
extern void install_battle_hook();
extern void install_cai_hooks(uintptr_t base, size_t size);
extern void install_thrones_pathfinder_hook(uintptr_t base, size_t size);
extern void install_overlay_fix();
void uninstall_overlay_fix();
extern void install_dbkey_cache();
extern void uninstall_dbkey_cache();
extern void uninstall_world_hook();
extern void uninstall_campaign_ui_hook();
extern void uninstall_settlement_slots_hook();
extern void uninstall_model_hook();
extern void uninstall_battle_hook();
extern void uninstall_cai_hooks();
extern void uninstall_thrones_pathfinder_hook();

static const char *TARGET_MODULE = "empire.retail.dll";

void install_campaign_hooks() {
    Log("[twdll] install_campaign_hooks: starting for %s", TARGET_MODULE);

    HMODULE hMod = GetModuleHandleA(TARGET_MODULE);
    if (!hMod) {
        Log("[twdll] install_campaign_hooks: %s not loaded yet — skipping", TARGET_MODULE);
        return;
    }

    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) {
        Log("[twdll] install_campaign_hooks: GetModuleInformation failed (%lu)", GetLastError());
        return;
    }

    uintptr_t base = reinterpret_cast<uintptr_t>(hMod);
    size_t size = mi.SizeOfImage;

    MH_STATUS mhs = MH_Initialize();
    if (mhs != MH_OK && mhs != MH_ERROR_ALREADY_INITIALIZED) {
        Log("[twdll] install_campaign_hooks: MH_Initialize failed (%d)", mhs);
        return;
    }

    install_world_hook(base, size);
    install_campaign_ui_hook(base, size);
    install_settlement_slots_hook(base, size);
    install_model_hook(base, size);
    install_battle_hook();
    // install_cai_hooks(base, size);
    install_thrones_pathfinder_hook(base, size);
    install_overlay_fix();
    install_dbkey_cache();

    Log("[twdll] install_campaign_hooks: done");
}

void uninstall_campaign_hooks() {
    Log("[twdll] uninstall_campaign_hooks: starting");
    uninstall_dbkey_cache();
    uninstall_overlay_fix();
    uninstall_world_hook();
    uninstall_campaign_ui_hook();
    uninstall_settlement_slots_hook();
    uninstall_model_hook();
    uninstall_battle_hook();
    // uninstall_cai_hooks(); // install_cai_hooks is disabled above
    uninstall_thrones_pathfinder_hook();
    MH_Uninitialize(); // Required: removes every MinHook hook (pathfinder dispatchers) before
                       // the DLL unloads between campaigns. Do not disable.
    Log("[twdll] uninstall_campaign_hooks: done");
}