# Contributing

## Repo structure

- `Dumper/Engine/Public/Valorant/Decryption.h` — RVA declarations, hardcoded fallbacks, Valorant namespace.
- `Dumper/Engine/Private/Valorant/Decryption.cpp` — decrypt state-machine (cases 0–6), `LocateGObjectsStruct()` sig-scan.
- `Dumper/Engine/Private/Valorant/FunctionLocator.cpp` — UFunction-reflection lookups for game function pointers.
- `Dumper/Engine/Private/Valorant/Output.cpp` — emits `ValorantDecrypt.h` (and `.as`) to dump folder.
- `Generator.cpp` — calls `Valorant::Init()` in place of `ObjectArray::Init()` in `InitEngineCore()`.

## Adding a new function locator

When a patch breaks an existing function pointer:

1. Decompile the new function in IDA.
2. **If UFunction-backed** (e.g. blueprint-reflected): add the reflected name to `FunctionLocator.cpp`'s lookup table; it resolves at runtime.
3. **If non-UFunction** (e.g. `FMemory::Malloc`, `StaticLoadObject`): add a sig-scan in `Decryption.cpp` using `Platform::FindPattern("48 8B ?? ??", ...)` pattern syntax.
4. Emit the new RVA in `Output.cpp`'s `WriteDecryptHeader()`.

## Bumping patch-specific RVAs

GObjects state and key RVAs change per Valorant patch. The sig-scan in `LocateGObjectsStruct()` finds them at runtime, but the hardcoded fallback in `Decryption.h` should stay current.

- Run the dumper; watch for `[Valorant] patch drift` warning.
- Copy discovered RVAs into `kGObjectsStateRVA` and `kGObjectsKeyRVA` in `Decryption.h`.
- Commit as: `chore: bump GObjects RVAs for build X.Y.Z`.

## Pulling upstream Dumper-7 updates

The fork uses `origin` = `sinistercodes/Dumper-7-VGK`, `upstream` = `Encryqed/Dumper-7`:

```bash
git fetch upstream
git merge upstream/main
git push origin master
```

Resolve conflicts on `ObjectArray.cpp` and `Generator.cpp` in favor of the Valorant integration (the `InitFromAbsolute` overload and `Valorant::Init()` call).

## Commit conventions

- Use conventional commits: `feat(<scope>):`, `chore:`, `docs:`, `ci:`.
- One enhancement per commit.
- No `Co-Authored-By` footers.
