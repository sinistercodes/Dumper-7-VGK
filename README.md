# Dumper-7-VGK

[Dumper-7](https://github.com/Encryqed/Dumper-7) fork that handles Valorant's encrypted-globals scheme. The standard Dumper-7 cannot locate `GObjects` in Valorant because Riot strips the static FUObjectArray pointer and resolves it through a runtime decrypt. This fork ports that decrypt so the SDK generator works against `VALORANT-Win64-Shipping.exe` without manual offset overrides.

## What's added

| File | Purpose |
|---|---|
| `Dumper/Engine/Public/Valorant/Decryption.h` | RVAs, declarations, full algorithm doc |
| `Dumper/Engine/Private/Valorant/Decryption.cpp` | Case 0..6 decrypt math + `FindGObjects()` + `Init()` |
| `Dumper/Engine/Public/Unreal/ObjectArray.h` | New `InitFromAbsolute(uint8_t*, layout)` overload |
| `Dumper/Engine/Private/Unreal/ObjectArray.cpp` | `InitFromAbsolute` implementation |
| `Dumper/Generator/Private/Generators/Generator.cpp` | Calls `Valorant::Init()` in `InitEngineCore()` |

The decrypt was extracted statically from `sub_EA1980` and cross-verified against `sub_3638AC0` (two inline copies of the same GObjects accessor). Both functions use the magic constant `0x2545F4914F6CDD1D` and a 7-case state-machine selected by `(MAGIC * mixedKey) % 7`.

## Patch maintenance

GObjects state and key live in module `.data` at fixed RVAs for each Valorant build. The current values:

```cpp
// Decryption.h
inline constexpr uint32_t kGObjectsStateRVA = 0xA62E600;  // 7 qwords
inline constexpr uint32_t kGObjectsKeyRVA   = 0xA62E638;  // uint32
```

When Valorant patches and the dumper logs `Decrypted pointer is unreadable`, re-extract the RVAs from the new binary in IDA:

- **Strategy 1** — search the magic constant `0x2545F4914F6CDD1D`. Each hit is inside an encrypted-globals accessor; find the nearby `lea` that names the state struct.
- **Strategy 2** — find the `"CloseDisregardForGC"` string xref; the function that uses it calls the GObjects accessor directly.

Both strategies are described in the source. The case math is patch-stable; only the RVAs change.

## Build

### Visual Studio (`.sln`)

Open `Dumper-7.sln` in VS 2022, set configuration to **Release | x64**, then **Build → Build Solution**. Output: `x64\Release\Dumper-7.dll`.

### CMake

```
cmake -S . -B out/build -G "Visual Studio 17 2022" -A x64
cmake --build out/build --config Release
```

Output: `out\build\bin\Release\Dumper-7.dll`.

## Usage

### Launching without Vanguard

Vanguard's kernel driver blocks DLL injection into a running `VALORANT-Win64-Shipping.exe`. To run the dumper, start the game with Vanguard stopped:

1. Open an **elevated** terminal and stop the Vanguard service:

   ```
   sc stop vgk
   ```

2. Launch the game directly, bypassing the Riot Client:

   ```
   "D:\Riot Games\VALORANT\live\VALORANT.exe" -remoting-app-port=58088 -remoting-auth-token=lalalalala -patchline=live -subject=lalalala -ares-deployment=eu -config-endpoint=https://shared.eu.a.pvp.net -savetouserdir -culture=en_US -riotgamesapi-settings-token=dafuq
   ```

   The token args are placeholders — the game will fail to authenticate against Riot's services but engine init still runs, GObjects is populated, and the SDK can be generated. Adjust `-ares-deployment` / `-config-endpoint` for your region if needed.

3. Manual-map `Dumper-7.dll` from an **elevated** injector (FaceInjector, Extreme Injector, SystemInformer's loaded-modules pane, etc.). Standard `LoadLibrary` will be flagged.

### Console output

A console attaches and prints:

```
[Valorant] Resolving GObjects via encrypted-globals decrypt...
[Valorant] GObjects: key=0x... case=N decrypted=0x...
[Valorant] FUObjectArray OK: num=... max=... chunks=...
```

If those lines appear, GObjects is resolved and the rest of Dumper-7 takes over. Default SDK output path is `C:\Dumper-7\<version>-ShooterGame\`. Press `F6` in the console to unload.

The line `GWorld WAS NOT FOUND!!!` is **expected** — Riot strips the static GWorld slot. The generated SDK falls back to `UEngine::GetEngine() -> GameViewport -> World` at consume time, which is correct.

## Pulling upstream Dumper-7

Upstream is set as the `upstream` remote:

```
git fetch upstream
git merge upstream/main           # keeps the Valorant commits on top
git push origin master
```

If upstream conflicts touch `ObjectArray.cpp`/`Generator.cpp`, resolve in favor of the Valorant integration (the InitFromAbsolute overload and the `Valorant::Init()` call site).

## Credits

- Original SDK generator: [Encryqed/Dumper-7](https://github.com/Encryqed/Dumper-7)
- Valorant decrypt RE/integration: this fork
