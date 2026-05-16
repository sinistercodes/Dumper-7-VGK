#include "Valorant/Decryption.h"

#include "Unreal/ObjectArray.h"
#include "OffsetFinder/Offsets.h"
#include "Platform.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

namespace Valorant
{
    // ---------- bit primitives (mirror of sub_EA1980 pseudocode) ----------
    static inline uint64_t Rol64(uint64_t v, uint32_t n)
    {
        n &= 63;
        if (n == 0) return v;
        return (v << n) | (v >> (64 - n));
    }

    static inline uint64_t Ror64(uint64_t v, uint32_t n)
    {
        n &= 63;
        if (n == 0) return v;
        return (v >> n) | (v << (64 - n));
    }

    static inline uint64_t Stage1(uint64_t v) { return (v >> 1) ^ (((v >> 1) ^ (v << 1)) & 0xAAAAAAAAAAAAAAAAULL); }
    static inline uint64_t Stage2(uint64_t v) { return (v >> 2) ^ (((v >> 2) ^ (v << 2)) & 0xCCCCCCCCCCCCCCCCULL); }
    static inline uint64_t Stage3(uint64_t v) { return (v >> 4) ^ (((v >> 4) ^ (v << 4)) & 0xF0F0F0F0F0F0F0F0ULL); }
    static inline uint64_t Stage4(uint64_t v) { return (v >> 8) ^ (((v >> 8) ^ (v << 8)) & 0xFF00FF00FF00FF00ULL); }
    static inline uint64_t Bitrev64(uint64_t v) { return Ror64(Stage4(Stage3(Stage2(Stage1(v)))), 32); }

    // ---------- the GObjects decrypt variant ----------
    // Direct port of the case statements in sub_EA1980 (cross-verified against
    // sub_3638AC0). Both functions are inline copies of the same accessor.
    static uint64_t DecryptGObjectsPtrImpl(uint32_t key, const uint64_t state[7])
    {
        const uint32_t mix  = key ^ (((key ^ (key >> 15)) >> 12)) ^ (key << 25);
        const uint64_t hash = kMagic * static_cast<uint64_t>(mix);
        const uint32_t hi   = static_cast<uint32_t>(hash >> 32);
        // IDA shows `(MAGIC * mix) % 7` — full 64-bit modulo. The low-32 mod
        // is wrong because `HI(hash)*4 mod 7` is usually non-zero.
        const uint32_t idx  = static_cast<uint32_t>(hash % 7ULL);

        uint64_t v = state[idx];

        switch (idx)
        {
        case 0:
            v = v ^ static_cast<uint64_t>(hi);
            break;
        case 1:
        {
            const uint32_t amt = ((hi + 2 * idx) % 63) + 1;
            v = static_cast<uint64_t>(static_cast<uint32_t>(hi + idx)) + Rol64(v, amt);
            break;
        }
        case 2:
            v = (~v) - static_cast<uint64_t>(static_cast<uint32_t>(hi + idx));
            break;
        case 3:
        {
            const uint32_t amt = ((hi + idx) % 63) + 1;
            v = Ror64(Bitrev64(v), amt);
            break;
        }
        case 4:
            v = v
              + static_cast<uint64_t>(static_cast<uint32_t>(hi + 2 * idx))
              + static_cast<uint64_t>(static_cast<uint32_t>(hi + idx));
            break;
        case 5:
        {
            const uint32_t amt = ((hi + idx) % 63) + 1;
            v = Rol64(Stage1(v), amt);
            break;
        }
        case 6:
        {
            const uint32_t amt = ((hi + idx) % 63) + 1;
            v = Ror64(static_cast<uint64_t>(static_cast<uint32_t>(hi + 2 * idx)) + v, amt);
            break;
        }
        }

        return v ^ static_cast<uint64_t>(key);
    }

    // ---------- the FName-mask decrypt variant ----------
    // Direct port of the read-path case statements in sub_9DAF50 (the block
    // after the init loop that reads state[idx], applies per-case math, and
    // returns `v ^ key`). The selector is `(MAGIC * mixedKey) % 7` using the
    // full 64-bit product — identical to DecryptGObjectsPtr. The per-case
    // math differs: cipher cases observed in the read block are:
    //
    //   0: v = ~(state + uint32(hi - 1))           (== ~state - (hi-1))
    //   1: v = stage1(state XOR ~uint32(hi + 2*idx))
    //   2: v = ~stage1(state)
    //   3: v = stage1(state + uint32(hi + 2*idx))
    //   4: v = bitrev64(stage1(state))             (extra stage1 before bitrev)
    //   5: v = ROL(ROL(state, ((hi+2*idx) % 63)+1), ((hi+idx) % 63)+1)
    //   6: v = bitrev64(ROR(state, ((hi+2*idx) % 63)+1))
    //   final: result = v XOR uint32(key)
    static uint64_t DecryptFNameMaskPtr(uint32_t key, const uint64_t state[7])
    {
        const uint32_t mix  = key ^ (((key ^ (key >> 15)) >> 12)) ^ (key << 25);
        const uint64_t hash = kMagic * static_cast<uint64_t>(mix);
        const uint32_t hi   = static_cast<uint32_t>(hash >> 32);
        const uint32_t idx  = static_cast<uint32_t>(hash % 7ULL);

        uint64_t v = state[idx];

        switch (idx)
        {
        case 0:
            v = ~(v + static_cast<uint64_t>(static_cast<uint32_t>(hi - 1)));
            break;
        case 1:
        {
            // NOT is applied at uint32 width then zero-extended -- the
            // decompile shows ~uint32(hi+2*idx), not ~uint64(...).
            const uint64_t mask = static_cast<uint64_t>(~static_cast<uint32_t>(hi + 2 * idx));
            v = Stage1(v ^ mask);
            break;
        }
        case 2:
            v = ~Stage1(v);
            break;
        case 3:
            v = Stage1(v + static_cast<uint64_t>(static_cast<uint32_t>(hi + 2 * idx)));
            break;
        case 4:
            v = Bitrev64(Stage1(v));
            break;
        case 5:
        {
            const uint32_t amt1 = ((hi + 2 * idx) % 63) + 1;
            const uint32_t amt2 = ((hi + idx)     % 63) + 1;
            v = Rol64(Rol64(v, amt1), amt2);
            break;
        }
        case 6:
        {
            const uint32_t amt = ((hi + 2 * idx) % 63) + 1;
            v = Bitrev64(Ror64(v, amt));
            break;
        }
        }

        return v ^ static_cast<uint64_t>(key);
    }

    uint64_t DecryptFNameMask(uint32_t key, const uint64_t state[7])
    {
        return DecryptFNameMaskPtr(key, state);
    }

    uint64_t DecryptGObjectsPtr(uint32_t key, const uint64_t state[7])
    {
        return DecryptGObjectsPtrImpl(key, state);
    }

    // Helper to recompute the case selector for logging — mirrors the same
    // math as DecryptGObjectsPtr so the printed case matches the path taken.
    static uint32_t ComputeCaseIndex(uint32_t key)
    {
        const uint32_t mix  = key ^ (((key ^ (key >> 15)) >> 12)) ^ (key << 25);
        const uint64_t hash = kMagic * static_cast<uint64_t>(mix);
        return static_cast<uint32_t>(hash % 7ULL);
    }

    // -----------------------------------------------------------------------
    // FindEncryptedGlobalsStructRVA  (generic framework)
    //
    // Scans the module for every occurrence of kMagic (0x2545F4914F6CDD1D),
    // then walks backward up to 100 bytes from each hit looking for the
    // RIP-relative LEA that loads the encrypted-globals struct base.
    //
    // LEA encoding (x64):  48 8D <modrm> <disp32>   (7 bytes total)
    //   modrm high 2 bits must be 00 (RIP-relative), bits [5:3] = destination
    //   register (any), bits [2:0] = 101 (disp32 follows).
    //
    // For each decoded struct base, the provided `validator` callback is
    // invoked. The first candidate for which validator returns true is
    // accepted; its RVA (relative to module base) is returned.
    //
    // Returns 0 if no valid candidate was found.
    // -----------------------------------------------------------------------
    uint32_t FindEncryptedGlobalsStructRVA(StructValidator validator)
    {
        const uintptr_t modBase = Platform::GetModuleBase();
        if (!modBase)
            return 0;

        uintptr_t searchStart = 0x0;

        for (int hitCount = 0; hitCount < 256; ++hitCount)
        {
            uint64_t* magicPtr = Platform::FindAlignedValueInAllSections<uint64_t>(
                kMagic,
                /*Alignment=*/1,
                searchStart,
                /*Range=*/0);

            if (!magicPtr)
                break;

            const uintptr_t magicAddr = reinterpret_cast<uintptr_t>(magicPtr);
            searchStart = magicAddr + sizeof(uint64_t);

            const uintptr_t scanStart = (magicAddr > 100) ? (magicAddr - 100) : 0;

            for (uintptr_t cur = magicAddr >= 7 ? magicAddr - 7 : 0;
                 cur >= scanStart && cur < magicAddr;
                 --cur)
            {
                if (Platform::IsBadReadPtr(cur))
                    break;

                const uint8_t* p = reinterpret_cast<const uint8_t*>(cur);

                // REX.W prefix + LEA opcode
                if (p[0] != 0x48 || p[1] != 0x8D)
                    continue;

                // ModRM: mod==00, rm==101 → RIP-relative disp32
                const uint8_t modrm = p[2];
                if ((modrm & 0xC7) != 0x05)
                    continue;

                // Decode: target = lea_instr_addr + 7 + sign-extended disp32
                int32_t disp32;
                std::memcpy(&disp32, p + 3, sizeof(disp32));
                const uintptr_t structBase = cur + 7 + static_cast<uintptr_t>(static_cast<intptr_t>(disp32));

                if (Platform::IsBadReadPtr(structBase) ||
                    Platform::IsBadReadPtr(structBase + 0x78 + 3))
                    continue;

                if (validator(structBase))
                    return static_cast<uint32_t>(structBase - modBase);
            }
        }

        return 0;
    }

    // -----------------------------------------------------------------------
    // IsGObjectsCandidate  (GObjects-specific StructValidator)
    //
    // Reads state[7] from candidateBase + 0x40 and key from + 0x78,
    // runs DecryptGObjectsPtrImpl, and validates the resulting pointer as a
    // plausible FUObjectArray header.
    // -----------------------------------------------------------------------
    static bool IsGObjectsCandidate(uintptr_t structBase)
    {
        const uintptr_t candidateState = structBase + 0x40;
        const uintptr_t candidateKey   = structBase + 0x78;

        const uint32_t key = *reinterpret_cast<const uint32_t*>(candidateKey);
        if (key == 0)
            return false;

        uint64_t state[7];
        std::memcpy(state, reinterpret_cast<const void*>(candidateState), sizeof(state));

        const uint64_t decrypted = DecryptGObjectsPtrImpl(key, state);
        uint8_t* fuoa = reinterpret_cast<uint8_t*>(decrypted);
        if (Platform::IsBadReadPtr(fuoa))
            return false;

        const int32_t numElems  = *reinterpret_cast<int32_t*>(fuoa + 0x14);
        const int32_t maxElems  = *reinterpret_cast<int32_t*>(fuoa + 0x10);
        const int32_t numChunks = *reinterpret_cast<int32_t*>(fuoa + 0x1C);
        const int32_t maxChunks = *reinterpret_cast<int32_t*>(fuoa + 0x18);
        void* const   chunks    = *reinterpret_cast<void**>(fuoa + 0x00);

        if (numElems < 0x100 || numElems > maxElems ||
            maxElems > 0x4000000 ||
            numChunks < 1 || numChunks > maxChunks ||
            maxChunks < 1 || maxChunks > 0x800 ||
            Platform::IsBadReadPtr(chunks))
            return false;

        return true;
    }

    // -----------------------------------------------------------------------
    // IsFNameMaskCandidate  (FName-mask-specific StructValidator)
    //
    // Reads state[7] from candidateBase + 0x40 and key from + 0x78, runs
    // DecryptFNameMaskPtr, and validates the result is plausible:
    //   - The decrypted pointer must be readable.
    //   - It must NOT equal what DecryptGObjectsPtrImpl produces for the same
    //     data — that distinguishes this struct from the GObjects struct.
    //   - structBase + 0x7C holds a uint32 counter (must be < 0x10000 to be
    //     plausible — it's an access counter, not a large integer).
    //   - structBase + 0x80 holds a lock byte (must be 0 or 1).
    // -----------------------------------------------------------------------
    static bool IsFNameMaskCandidate(uintptr_t structBase)
    {
        if (Platform::IsBadReadPtr(structBase + 0x80))
            return false;

        const uintptr_t candidateState = structBase + 0x40;
        const uintptr_t candidateKey   = structBase + 0x78;

        const uint32_t key = *reinterpret_cast<const uint32_t*>(candidateKey);
        if (key == 0)
            return false;

        // Sanity-check lock byte and counter at the well-known offsets.
        const uint32_t counter   = *reinterpret_cast<const uint32_t*>(structBase + 0x7C);
        const uint8_t  lockByte  = *reinterpret_cast<const uint8_t* >(structBase + 0x80);
        if (lockByte > 1 || counter > 0x10000)
            return false;

        uint64_t state[7];
        std::memcpy(state, reinterpret_cast<const void*>(candidateState), sizeof(state));

        const uint64_t fnameMaskResult = DecryptFNameMaskPtr(key, state);
        if (Platform::IsBadReadPtr(reinterpret_cast<void*>(fnameMaskResult)))
            return false;

        // The FName-mask struct must not decrypt to the same value as the
        // GObjects struct would — that proves this is a different struct.
        const uint64_t gobjectsResult = DecryptGObjectsPtrImpl(key, state);
        if (fnameMaskResult == gobjectsResult)
            return false;

        return true;
    }

    // -----------------------------------------------------------------------
    // LocateGObjectsStruct
    //
    // Uses FindEncryptedGlobalsStructRVA with IsGObjectsCandidate to locate
    // the GObjects encrypted-globals struct and store its state/key RVAs.
    // Applies the strict-drift check if bStrictDrift is enabled.
    //
    // Returns true on success, false if no valid candidate was found (caller
    // falls back to the hardcoded RVAs).
    // -----------------------------------------------------------------------
    static bool LocateGObjectsStruct()
    {
        const uintptr_t modBase = Platform::GetModuleBase();
        if (!modBase)
            return false;

        const uint32_t structBaseRVA = FindEncryptedGlobalsStructRVA(IsGObjectsCandidate);
        if (structBaseRVA == 0)
        {
            std::cerr << "[Valorant] sig scan failed, falling back to hardcoded RVAs\n";
            return false;
        }

        const uint32_t stateRVA = structBaseRVA + 0x40;
        const uint32_t keyRVA   = structBaseRVA + 0x78;

        std::cerr << "[Valorant] sig scan: state @ 0x" << std::hex << stateRVA
                  << ", key @ 0x" << keyRVA << std::dec << "\n";

        // Patch-drift detector: when the runtime-discovered RVAs differ from
        // the hardcoded values in Decryption.h, surface it so the source
        // constants get bumped before the scan ever misses on a future patch.
        if (stateRVA != kGObjectsStateRVA || keyRVA != kGObjectsKeyRVA)
        {
            if (bStrictDrift)
            {
                std::cerr << "[Valorant] STRICT-DRIFT: aborting -- bump Decryption.h "
                             "fallback values to match "
                          << "(found state 0x" << std::hex << stateRVA
                          << " key 0x" << keyRVA
                          << ", Decryption.h has state 0x" << kGObjectsStateRVA
                          << " key 0x" << kGObjectsKeyRVA << std::dec << ")\n";
                std::exit(2);
            }

            std::cerr << "[Valorant] patch drift: sig-scan found state @ 0x"
                      << std::hex << stateRVA << " key @ 0x" << keyRVA
                      << " (Decryption.h says state 0x" << kGObjectsStateRVA
                      << " key 0x" << kGObjectsKeyRVA << std::dec
                      << ") -- bump Decryption.h.\n";
        }

        gObjectsStateRVA = stateRVA;
        gObjectsKeyRVA   = keyRVA;
        return true;
    }

    // -----------------------------------------------------------------------
    // LocateFNameMaskStruct
    //
    // Uses FindEncryptedGlobalsStructRVA with IsFNameMaskCandidate to locate
    // the FName-mask encrypted-globals struct and store its state/key RVAs in
    // fNameMaskStateRVA / fNameMaskKeyRVA.
    //
    // Returns true on success, false if no valid candidate was found (caller
    // falls back to the hardcoded kFNameMask* RVAs).
    // -----------------------------------------------------------------------
    static bool LocateFNameMaskStruct()
    {
        const uintptr_t modBase = Platform::GetModuleBase();
        if (!modBase)
            return false;

        const uint32_t structBaseRVA = FindEncryptedGlobalsStructRVA(IsFNameMaskCandidate);
        if (structBaseRVA == 0)
        {
            std::cerr << "[Valorant] FName-mask sig scan failed, "
                         "falling back to hardcoded RVAs\n";
            return false;
        }

        const uint32_t stateRVA = structBaseRVA + 0x40;
        const uint32_t keyRVA   = structBaseRVA + 0x78;

        std::cerr << "[Valorant] FName-mask sig scan: state @ 0x"
                  << std::hex << stateRVA
                  << ", key @ 0x" << keyRVA << std::dec << "\n";

        if (stateRVA != kFNameMaskStateRVA || keyRVA != kFNameMaskKeyRVA)
        {
            std::cerr << "[Valorant] FName-mask patch drift: found state 0x"
                      << std::hex << stateRVA << " key 0x" << keyRVA
                      << " (Decryption.h has state 0x" << kFNameMaskStateRVA
                      << " key 0x" << kFNameMaskKeyRVA << std::dec
                      << ") -- bump Decryption.h.\n";
        }

        fNameMaskStateRVA = stateRVA;
        fNameMaskKeyRVA   = keyRVA;
        return true;
    }

    uint8_t* FindGObjects()
    {
        const uintptr_t modBase = Platform::GetModuleBase();
        if (!modBase)
        {
            std::cerr << "[Valorant] Module base is null.\n";
            return nullptr;
        }

        // Attempt runtime location first; on failure gObjectsStateRVA/gObjectsKeyRVA
        // retain their hardcoded initializer values.
        LocateGObjectsStruct();

        const uintptr_t stateAddr = modBase + gObjectsStateRVA;
        const uintptr_t keyAddr   = modBase + gObjectsKeyRVA;

        if (Platform::IsBadReadPtr(stateAddr) || Platform::IsBadReadPtr(keyAddr))
        {
            std::cerr << "[Valorant] State/key RVAs are unreadable — "
                         "likely a patch shift. Re-anchor kGObjectsStateRVA / "
                         "kGObjectsKeyRVA in Decryption.h.\n";
            return nullptr;
        }

        uint64_t state[7];
        std::memcpy(state, reinterpret_cast<const void*>(stateAddr), sizeof(state));
        const uint32_t key = *reinterpret_cast<const uint32_t*>(keyAddr);

        if (key == 0)
        {
            std::cerr << "[Valorant] GObjects key is zero — globals not "
                         "initialized yet. Try increasing the dumper start delay.\n";
            return nullptr;
        }

        const uint64_t decrypted = DecryptGObjectsPtrImpl(key, state);
        const uint32_t caseIdx   = ComputeCaseIndex(key);

        std::cerr << "[Valorant] GObjects: key=0x" << std::hex << key
                  << " case=" << std::dec << caseIdx
                  << " decrypted=0x" << std::hex << decrypted << std::dec << "\n";

        uint8_t* fuoa = reinterpret_cast<uint8_t*>(decrypted);
        if (Platform::IsBadReadPtr(fuoa))
        {
            std::cerr << "[Valorant] Decrypted pointer is unreadable — "
                         "wrong case math, wrong RVAs, or Vanguard hid the page.\n";
            return nullptr;
        }

        // Validate the FUObjectArray header (chunked layout, Dumper-7 default).
        const int32_t numElems = *reinterpret_cast<int32_t*>(fuoa + 0x14);
        const int32_t maxElems = *reinterpret_cast<int32_t*>(fuoa + 0x10);
        const int32_t numChunks = *reinterpret_cast<int32_t*>(fuoa + 0x1C);
        const int32_t maxChunks = *reinterpret_cast<int32_t*>(fuoa + 0x18);
        void* const chunks = *reinterpret_cast<void**>(fuoa + 0x00);

        if (numElems < 0x100 || numElems > maxElems ||
            maxElems > 0x4000000 ||
            numChunks < 1 || numChunks > maxChunks ||
            maxChunks < 1 || maxChunks > 0x800 ||
            Platform::IsBadReadPtr(chunks))
        {
            std::cerr << "[Valorant] FUObjectArray header rejected: "
                      << "num=" << std::dec << numElems
                      << " max=" << maxElems
                      << " numChunks=" << numChunks
                      << " maxChunks=" << maxChunks
                      << " chunks=0x" << std::hex << chunks << std::dec << "\n";
            return nullptr;
        }

        std::cerr << "[Valorant] FUObjectArray OK: num=" << std::dec << numElems
                  << " max=" << maxElems
                  << " chunks=" << numChunks << "/" << maxChunks
                  << " base=0x" << std::hex << decrypted << std::dec << "\n";

        return fuoa;
    }

    void Init()
    {
        // Check env var to enable strict-drift mode for CI pipelines.
        // Set VALORANT_STRICT_DRIFT=1 in the environment before launching.
        if (const char* env = std::getenv("VALORANT_STRICT_DRIFT"))
        {
            if (env[0] == '1')
                bStrictDrift = true;
        }

        std::cerr << "[Valorant] Resolving GObjects via encrypted-globals decrypt...\n";
        uint8_t* gobjects = FindGObjects();
        if (!gobjects)
        {
            std::cerr << "[Valorant] FATAL: GObjects not located. Generator will "
                         "fail downstream.\n";
            return;
        }

        // Locate the FName-mask struct after GObjects is resolved.
        LocateFNameMaskStruct();

        // Hand the absolute address to ObjectArray — bypasses the scanner.
        ObjectArray::InitFromAbsolute(gobjects);
    }
}
