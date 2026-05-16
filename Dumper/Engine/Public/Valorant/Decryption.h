#pragma once

#include <cstdint>

// ============================================================================
// Valorant encrypted-globals decryption.
//
// Valorant ships every "global" Unreal pointer (GObjects, GNames-resolver,
// etc.) behind a 7-state rotating cipher. Each protected global owns its own
// state struct in the module's .data section:
//
//   [base + StateRVA + 0x00 .. +0x37]   state[7]  (7 little-endian qwords)
//   [base + StateRVA + 0x38]            key       (uint32; high bytes unused)
//
// The decrypt routine is inlined into many functions; each inlined copy uses
// the same MAGIC constant (0x2545F4914F6CDD1D) but specialises the per-case
// math to a particular target global. The GObjects accessor we reverse-engineered
// lives at sub_EA1980 / sub_3638AC0 (two inline copies that share the same
// cases). Its cases (selected by `(MAGIC * mixedKey) % 7` -- full 64-bit) are:
//
//   0: v ^= hi32
//   1: v = uint32(hi+idx) + ROL(state, ((hi+2*idx) % 63) + 1)
//   2: v = ~state - uint32(hi+idx)
//   3: v = ROR(bitrev64(state), ((hi+idx) % 63) + 1)
//   4: v = state + uint32(hi+2*idx) + uint32(hi+idx)
//   5: v = ROL(stage1(state), ((hi+idx) % 63) + 1)
//   6: v = ROR(uint32(hi+2*idx) + state, ((hi+idx) % 63) + 1)
//   final: result = v ^ uint32(key)
//
// The state mutates every 10 reads from the game's side, but the plaintext
// (the FUObjectArray pointer) stays constant across calls. So we can read
// state+key once and decrypt once per generator run.
//
// RVAs were extracted statically against vgk_dump_pages1.exe (the IDA copy
// of the user's VALORANT-Win64-Shipping.exe). They WILL drift on patch days;
// the long-term plan is to find them via signature-scanning the MAGIC
// constant + the LEA that names the state struct (Strategy 1 in the other
// fork's screenshots). For now they're hardcoded — flip the constant when
// the game updates.
// ============================================================================

namespace Valorant
{
    inline constexpr uint64_t kMagic = 0x2545F4914F6CDD1DULL;

    // Patch-specific RVAs — update when the binary changes.
    // These are used as a fallback if the runtime signature scan fails.
    inline constexpr uint32_t kGObjectsStateRVA = 0xA62E600;
    inline constexpr uint32_t kGObjectsKeyRVA   = 0xA62E638;

    // FName-mask cipher anchors (sub_9DAF50). State is 7 qwords, key is u32.
    inline constexpr uint32_t kFNameMaskStateRVA = 0xA7C0A40;
    inline constexpr uint32_t kFNameMaskKeyRVA   = 0xA7C0A78;

    // Runtime-resolved RVAs (populated by LocateGObjectsStruct at startup).
    // Initialized to the hardcoded fallback values so FindGObjects() works
    // even when the scan is not called.
    inline uint32_t gObjectsStateRVA = kGObjectsStateRVA;
    inline uint32_t gObjectsKeyRVA   = kGObjectsKeyRVA;

    // Runtime-resolved RVAs for the FName-mask struct (populated by
    // LocateFNameMaskStruct at startup). Initialized to the hardcoded
    // fallback values so the decrypt works even when the scan is not called.
    inline uint32_t fNameMaskStateRVA = kFNameMaskStateRVA;
    inline uint32_t fNameMaskKeyRVA   = kFNameMaskKeyRVA;

    // -------------------------------------------------------------------------
    // Strict-drift mode
    //
    // When bStrictDrift is true, a mismatch between the runtime sig-scan result
    // and the hardcoded kGObjects* fallback constants is treated as a hard
    // failure (std::exit(2)) rather than a warning. This is intended for CI
    // pipelines where a silent drift would produce a wrong dump.
    //
    // How to enable:
    //   Set the environment variable VALORANT_STRICT_DRIFT=1 before launching
    //   the dumper, or flip the default to `true` in source for permanent CI
    //   enforcement. Init() checks the env var automatically.
    // -------------------------------------------------------------------------
    inline bool bStrictDrift = false;

    // -------------------------------------------------------------------------
    // Generic encrypted-globals struct locator framework
    //
    // Validator callback: receives the absolute address of a candidate struct
    // base and returns true iff the candidate is the encrypted-globals struct
    // for the caller's target. The framework hands every plausible candidate
    // (kMagic hit → LEA decode) to the validator; the first accepted wins.
    // -------------------------------------------------------------------------
    using StructValidator = bool(*)(uintptr_t structBase);

    // Scans for kMagic occurrences, walks back to the RIP-relative LEA,
    // decodes the struct base, and hands each candidate to `validator`.
    // Returns the first accepted struct base as an RVA (relative to module
    // base), or 0 on failure.
    uint32_t FindEncryptedGlobalsStructRVA(StructValidator validator);

    // Returns the live FUObjectArray header address (absolute pointer in the
    // game's heap). Returns nullptr on failure with diagnostic to stderr.
    uint8_t* FindGObjects();

    // Locates GObjects via FindGObjects and hands the absolute pointer to
    // ObjectArray::InitFromAbsolute. Call instead of ObjectArray::Init() from
    // Generator::InitEngineCore().
    void Init();

    // Public wrapper around the FName-mask read-path cipher (sub_9DAF50 read
    // block). Given the live (key, state[7]) snapshot, returns the decrypted
    // qword that the game uses as the FName mask pointer. Exported for tests
    // and for the orchestrator to embed in the emitted ValorantDecrypt.h.
    uint64_t DecryptFNameMask(uint32_t key, const uint64_t state[7]);

    // Public wrapper around the GObjects read-path cipher (sub_EA1980 /
    // sub_3638AC0). Given the live (key, state[7]) snapshot, returns the
    // decrypted FUObjectArray pointer. Exported for self-tests.
    uint64_t DecryptGObjectsPtr(uint32_t key, const uint64_t state[7]);
}
