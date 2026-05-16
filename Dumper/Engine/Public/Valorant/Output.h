#pragma once

#include <filesystem>

// ============================================================================
// Emits ValorantDecrypt.h alongside the generated SDK. The file collects every
// Valorant-relevant RVA (GObjects state/key, GWorld slot, FNamePool, ProcessEvent,
// AppendString, game-specific function pointers) plus inline implementations
// of the decrypt algorithms ported from the live binary.
//
// Some fields are filled from offsets Dumper-7 already auto-discovers
// (`Off::InSDK::*`), some from this fork's hardcoded constants (`Valorant::k*`),
// and the rest are TODO placeholders to be resolved per-patch by adding
// signature scans next to the existing locators.
// ============================================================================

namespace Valorant
{
    namespace fs = std::filesystem;

    // Writes <OutputFolder>/ValorantDecrypt.h. OutputFolder is the per-dump
    // directory (e.g. the same folder CppGenerator writes SDK.hpp into).
    void WriteDecryptHeader(const fs::path& OutputFolder);

    // Writes <OutputFolder>/ValorantOffsets.json. Called automatically by
    // WriteDecryptHeader after the header is emitted.
    void WriteOffsetsJson(const fs::path& OutputFolder);
}
