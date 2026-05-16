#include "Valorant/Decryption.h"

#include "Unreal/ObjectArray.h"
#include "OffsetFinder/Offsets.h"
#include "Platform.h"

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
    static uint64_t DecryptGObjectsPtr(uint32_t key, const uint64_t state[7])
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

    // Helper to recompute the case selector for logging — mirrors the same
    // math as DecryptGObjectsPtr so the printed case matches the path taken.
    static uint32_t ComputeCaseIndex(uint32_t key)
    {
        const uint32_t mix  = key ^ (((key ^ (key >> 15)) >> 12)) ^ (key << 25);
        const uint64_t hash = kMagic * static_cast<uint64_t>(mix);
        return static_cast<uint32_t>(hash % 7ULL);
    }

    uint8_t* FindGObjects()
    {
        const uintptr_t modBase = Platform::GetModuleBase();
        if (!modBase)
        {
            std::cerr << "[Valorant] Module base is null.\n";
            return nullptr;
        }

        const uintptr_t stateAddr = modBase + kGObjectsStateRVA;
        const uintptr_t keyAddr   = modBase + kGObjectsKeyRVA;

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

        const uint64_t decrypted = DecryptGObjectsPtr(key, state);
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
        std::cerr << "[Valorant] Resolving GObjects via encrypted-globals decrypt...\n";
        uint8_t* gobjects = FindGObjects();
        if (!gobjects)
        {
            std::cerr << "[Valorant] FATAL: GObjects not located. Generator will "
                         "fail downstream.\n";
            return;
        }

        // Hand the absolute address to ObjectArray — bypasses the scanner.
        ObjectArray::InitFromAbsolute(gobjects);
    }
}
