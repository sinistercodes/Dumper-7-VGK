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
// cases). Its cases (selected by `(LOW32(MAGIC*mixedKey) % 7)`) are:
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
    inline constexpr uint32_t kGObjectsStateRVA = 0xA62E600;
    inline constexpr uint32_t kGObjectsKeyRVA   = 0xA62E638;

    // Returns the live FUObjectArray header address (absolute pointer in the
    // game's heap). Returns nullptr on failure with diagnostic to stderr.
    uint8_t* FindGObjects();

    // Locates GObjects via FindGObjects and hands the absolute pointer to
    // ObjectArray::InitFromAbsolute. Call instead of ObjectArray::Init() from
    // Generator::InitEngineCore().
    void Init();
}
