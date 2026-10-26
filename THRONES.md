# twdll for Thrones of Britannia (Thrones Reforged)

`twdll_thrones.dll` is a required engine fix for **Total War Saga: Thrones of Britannia**,
made for the [Thrones Reforged](STEAM_WORKSHOP_URL) mod by ShuriK. It is a fork of
[bukowa/twdll](https://github.com/bukowa/twdll) (GPL-3.0) with Thrones-specific engine fixes in
[`src/thrones/`](src/thrones/).

Thrones Reforged requires it: without it the campaign map stutters, and the larger movement ranges
in the mod make the game freeze when exiting a campaign.

## What it fixes

| Problem | Cause in the engine | Fix | File |
|---|---|---|---|
| FPS drop while an army is selected | the movement-range overlay is recomputed from scratch every frame | cache the result while the army and its position are unchanged | `pathfinder.cpp` |
| Exit to desktop / main menu freezing for minutes after selecting an army | the movement-zone builder does a linear search per cell (quadratic on large movement ranges) | hash lookups instead of linear searches, skip border drawing for huge zones | `overlay_fix.cpp` |
| Low FPS while hovering terrain with an army selected | the path to the hovered hex is recomputed every frame | cache per hovered hex | `overlay_fix.cpp` |
| Low FPS while right-click dragging a move order | the drag path search has no distance heuristic and floods the map | add a hex-distance heuristic during the drag only | `overlay_fix.cpp` |
| Hitch once per second on the campaign map with the HUD visible | the HUD looks up religion pairs with a campaign key that never exists, and every failed lookup walks most of the DB index | remember each lookup result | `dbkey_cache.cpp` |

## How it works

- The mod's campaign script loads the DLL with Lua's standard `package.loadlib`, the same way
  every twdll mod does. Nothing is injected into the game process from outside.
- On load it changes a few function calls inside `empire.retail.dll` **in memory**. Every patch
  first checks that the game code is exactly what it expects and skips itself otherwise.
- All patches are removed again when the campaign closes.
- Game files on disk are never modified.

## What it does not do

- No network access of any kind (no sockets, no HTTP).
- Does not start other programs.
- The only file it writes is `twdll.log` in the game folder (one short log per campaign load).
- Does nothing outside Thrones of Britannia, and does nothing unless the mod loads it.

You can check all of this yourself: the full source is in this repository.

## Install

1. Download `twdll_thrones.zip` from the [Releases](../../releases) page.
2. Optional but recommended: check the SHA-256 hash (see below).
3. Copy `twdll_thrones.dll` into the game folder, next to `thrones.exe`
   (usually `C:\Program Files (x86)\Steam\steamapps\common\Total War Saga Thrones of Britannia`).
4. Start the game with Thrones Reforged enabled as usual.

Steam Workshop can only distribute `.pack` files, so this DLL has to be installed by hand.

**Uninstall:** delete `twdll_thrones.dll` from the game folder.

## Verify the download

In PowerShell, in the folder where you saved the DLL:

```powershell
Get-FileHash .\twdll_thrones.dll -Algorithm SHA256
```

The hash must match the one listed in the release notes.

Some antivirus programs may flag the DLL. This is a common false positive for game mods that
patch functions in memory (it uses the MinHook library, which is also used by many overlays and
mods). The release notes link a VirusTotal scan, and you can build the DLL yourself from this
source to be sure.

## Build it yourself

Requirements: Visual Studio 2022 (Desktop development with C++), CMake 3.29+, Git.

```bat
git clone --recursive https://github.com/Shurikino/twdll.git
cd twdll
```

Open **x86 Native Tools Command Prompt for VS 2022** (it must be the x86 one, the game is 32-bit), then:

```bat
cmake --preset attila
cmake --build --preset attila
```

The output is `build\attila\twdll.dll`. Rename it to `twdll_thrones.dll`.

Do not open the project in the Visual Studio IDE to build it: it reconfigures CMake for x64 and
the result will not load in the game.

## Credits and licenses

- [bukowa/twdll](https://github.com/bukowa/twdll), GPL-3.0. This fork is GPL-3.0 as well.
- [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu, BSD 2-Clause
  (license in `vendor/minhook/LICENSE.txt`, also included in the release zip).
- Thrones of Britannia fixes by ShuriK for Thrones Reforged.
