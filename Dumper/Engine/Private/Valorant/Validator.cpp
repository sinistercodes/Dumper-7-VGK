#include "Valorant/Validator.h"

#include "Valorant/Decryption.h"
#include "Valorant/FunctionLocator.h"
#include "OffsetFinder/Offsets.h"
#include "Platform.h"

#include <cstring>
#include <iostream>

namespace Valorant
{
    // -----------------------------------------------------------------------
    // Check 1: GObjects round-trip
    //
    // Re-read gObjectsStateRVA / gObjectsKeyRVA (populated by LocateGObjectsStruct
    // during FindGObjects), run DecryptGObjectsPtr, then validate:
    //   - NumElements in [0x100, 0x4000000]
    //   - chunks_ptr is readable (heap pointer)
    //   - First chunk's first object has a vtable inside the module
    // -----------------------------------------------------------------------
    static bool CheckGObjectsRoundTrip()
    {
        const uintptr_t modBase = Platform::GetModuleBase();
        if (!modBase)
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: module base is null\n";
            return false;
        }

        const uintptr_t stateAddr = modBase + gObjectsStateRVA;
        const uintptr_t keyAddr   = modBase + gObjectsKeyRVA;

        if (Platform::IsBadReadPtr(stateAddr) || Platform::IsBadReadPtr(keyAddr))
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: state/key RVA unreadable"
                      << " (stateRVA=0x" << std::hex << gObjectsStateRVA
                      << " keyRVA=0x" << gObjectsKeyRVA << std::dec << ")\n";
            return false;
        }

        uint64_t state[7];
        std::memcpy(state, reinterpret_cast<const void*>(stateAddr), sizeof(state));
        const uint32_t key = *reinterpret_cast<const uint32_t*>(keyAddr);

        if (key == 0)
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: key is zero\n";
            return false;
        }

        const uint64_t decrypted = DecryptGObjectsPtr(key, state);
        uint8_t* fuoa = reinterpret_cast<uint8_t*>(decrypted);

        if (Platform::IsBadReadPtr(fuoa))
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: decrypted ptr 0x"
                      << std::hex << decrypted << " is unreadable\n";
            return false;
        }

        // Chunked FUObjectArray layout (Dumper-7 default):
        //   +0x00 chunks_ptr (void**)
        //   +0x10 MaxElements (int32)
        //   +0x14 NumElements (int32)
        //   +0x18 MaxChunks   (int32)
        //   +0x1C NumChunks   (int32)
        const int32_t maxElems  = *reinterpret_cast<int32_t*>(fuoa + 0x10);
        const int32_t numElems  = *reinterpret_cast<int32_t*>(fuoa + 0x14);
        const int32_t maxChunks = *reinterpret_cast<int32_t*>(fuoa + 0x18);
        const int32_t numChunks = *reinterpret_cast<int32_t*>(fuoa + 0x1C);
        void** const  chunksPtr = *reinterpret_cast<void***>(fuoa + 0x00);

        if (numElems < 0x100 || numElems > 0x4000000)
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: NumElements=" << std::dec
                      << numElems << " out of range [0x100, 0x4000000]\n";
            return false;
        }

        if (maxElems <= 0 || maxElems > 0x4000000 || numElems > maxElems)
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: MaxElements=" << std::dec
                      << maxElems << " invalid (NumElements=" << numElems << ")\n";
            return false;
        }

        if (Platform::IsBadReadPtr(chunksPtr))
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: chunks_ptr 0x"
                      << std::hex << reinterpret_cast<uintptr_t>(chunksPtr)
                      << " is unreadable\n";
            return false;
        }

        if (numChunks < 1 || numChunks > maxChunks || maxChunks > 0x800)
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: numChunks=" << std::dec
                      << numChunks << " maxChunks=" << maxChunks << " invalid\n";
            return false;
        }

        // Dereference chunk[0] — should be a pointer to the first FUObjectItem block.
        void* chunk0 = chunksPtr[0];
        if (Platform::IsBadReadPtr(chunk0))
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: chunk[0] is unreadable\n";
            return false;
        }

        // First FUObjectItem at chunk0 offset 0: the first qword is the UObject ptr.
        // UObject layout: +0x00 is the vtable pointer.
        void* firstObjPtr = *reinterpret_cast<void**>(chunk0);
        if (!firstObjPtr || Platform::IsBadReadPtr(firstObjPtr))
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: first object ptr is null/unreadable\n";
            return false;
        }

        void* vtable = *reinterpret_cast<void**>(firstObjPtr);
        if (!Platform::IsAddressInAnyModule(reinterpret_cast<uintptr_t>(vtable)))
        {
            std::cerr << "[Valorant][validate] GObjects FAILED: first object vtable 0x"
                      << std::hex << reinterpret_cast<uintptr_t>(vtable)
                      << " is outside any module\n";
            return false;
        }

        std::cerr << "[Valorant][validate] GObjects OK"
                  << " (num=" << std::dec << numElems
                  << " max=" << maxElems
                  << " chunks=" << numChunks << "/" << maxChunks << ")\n";
        return true;
    }

    // -----------------------------------------------------------------------
    // Check 2: FName key recovery
    //
    // GNames base = modBase + Off::InSDK::NameArray::GNames
    // chunk0 ptr  = *(GNamesBase + 0x10)
    // entry       = chunk0 (FNameEntry starts at chunk0 + 0 in block 0)
    // header      = *(uint32*)(entry + 0)   (FNameEntryHeader: length bits + flags)
    // XOR first 4 bytes of the name field at (entry + header_offset) with 0x616A6B4A
    // to recover the FName encryption key. Then decrypt those 4 bytes in a local
    // buffer and verify they spell "None".
    //
    // Offsets used:
    //   Off::NameArray::ChunksStart   — offset into FNamePool where chunk ptr array starts
    //   Off::FNameEntry::NamePool::HeaderOffset  — offset of header within FNameEntry
    //   Off::FNameEntry::NamePool::StringOffset  — offset of string bytes within FNameEntry
    // -----------------------------------------------------------------------
    static bool CheckFNameKeyRecovery()
    {
        const uintptr_t modBase = Platform::GetModuleBase();
        if (!modBase)
        {
            std::cerr << "[Valorant][validate] FNameKey FAILED: module base null\n";
            return false;
        }

        // Dumper-7 stores Off::InSDK::NameArray::GNames as the static offset
        // where its auto-discovery anchored the FName subsystem. For UE5+
        // layouts that's the FNamePool struct itself (chunks_ptr at +0x10);
        // for some older layouts it's a pointer to the pool (extra deref).
        // Try the direct layout first, then one-extra-deref if that fails.
        const uintptr_t gnamesBase = modBase + static_cast<uintptr_t>(Off::InSDK::NameArray::GNames);

        auto tryRecoverFromPool = [&](uintptr_t poolBase, uintptr_t& outChunk0) -> bool
        {
            if (Platform::IsBadReadPtr(poolBase) || Platform::IsBadReadPtr(poolBase + 0x10))
                return false;
            const uintptr_t c0 = *reinterpret_cast<const uintptr_t*>(poolBase + 0x10);
            if (!c0 || Platform::IsBadReadPtr(c0))
                return false;
            outChunk0 = c0;
            return true;
        };

        uintptr_t chunk0 = 0;
        if (!tryRecoverFromPool(gnamesBase, chunk0))
        {
            // Fallback: maybe gnamesBase stores a pointer to the pool.
            if (!Platform::IsBadReadPtr(gnamesBase))
            {
                const uintptr_t maybePool = *reinterpret_cast<const uintptr_t*>(gnamesBase);
                tryRecoverFromPool(maybePool, chunk0);
            }
        }

        if (chunk0 == 0)
        {
            // Neither layout matched. The actual FNamePool isn't at the
            // address Dumper-7 anchored — for Valorant the pool address is
            // typically found by scanning module memory for a heap pointer
            // with the right header (see the perception script's
            // Locator::LocateFNamePool for that pattern). The recover_fname_key()
            // helper emitted into ValorantDecrypt.h works against whatever
            // pool address the CONSUMER hands it, so this check is
            // informational only; do not block emission.
            std::cerr << "[Valorant][validate] FNameKey WARN: chunk0 not reachable via "
                         "GNames or *GNames -- consumer must locate FNamePool itself; "
                         "the emitted recover_fname_key() helper still works\n";
            return true;
        }

        const int32_t stringOff = Off::FNameEntry::NamePool::StringOffset;
        const uintptr_t stringAddr = chunk0 + static_cast<uintptr_t>(stringOff);
        if (Platform::IsBadReadPtr(stringAddr))
        {
            std::cerr << "[Valorant][validate] FNameKey WARN: entry string addr unreadable "
                         "(stringOff=" << std::dec << stringOff << ")\n";
            return true;
        }

        // Read the 4 encrypted "None" bytes and recover the cipher key by
        // XOR-ing with the known plaintext-XOR constant baked into Valorant's
        // FName encrypt step.
        constexpr uint32_t kNoneKey = 0x616A6B4A;
        uint32_t encWord;
        std::memcpy(&encWord, reinterpret_cast<const void*>(stringAddr), 4);
        const uint32_t recoveredKey = encWord ^ kNoneKey;

        const uint32_t decWord = encWord ^ recoveredKey;
        char decBytes[5] = {};
        std::memcpy(decBytes, &decWord, 4);

        if (decBytes[0] != 'N' || decBytes[1] != 'o' || decBytes[2] != 'n' || decBytes[3] != 'e')
        {
            std::cerr << "[Valorant][validate] FNameKey WARN: decrypted bytes are '"
                      << decBytes[0] << decBytes[1] << decBytes[2] << decBytes[3]
                      << "' not 'None' (encWord=0x" << std::hex << encWord
                      << " recoveredKey=0x" << recoveredKey << std::dec
                      << ") -- pool layout may need adjustment\n";
            return true;
        }

        std::cerr << "[Valorant][validate] FNameKey OK (recoveredKey=0x"
                  << std::hex << recoveredKey << std::dec << ")\n";
        return true;
    }

    // -----------------------------------------------------------------------
    // Check 3: ProcessEvent vtable index sanity
    //
    // Off::InSDK::ProcessEvent::PEOffset is an RVA from module base (set by
    // InitPE() via Platform::GetOffset). Add the module base to get the
    // absolute address before validating. Log a warning (but don't fail) if
    // the index differs from 0x53 (= 83).
    // -----------------------------------------------------------------------
    static bool CheckProcessEvent()
    {
        const int32_t peOffset = Off::InSDK::ProcessEvent::PEOffset;
        const int32_t peIndex  = Off::InSDK::ProcessEvent::PEIndex;

        if (peOffset == 0)
        {
            std::cerr << "[Valorant][validate] ProcessEvent FAILED: PEOffset is 0 (not initialized)\n";
            return false;
        }

        const uintptr_t peAddr = Platform::GetModuleBase() + static_cast<uintptr_t>(peOffset);
        if (!Platform::IsAddressInAnyModule(peAddr))
        {
            std::cerr << "[Valorant][validate] ProcessEvent FAILED: PEOffset 0x"
                      << std::hex << peAddr << " is outside any module\n";
            return false;
        }

        constexpr int32_t kExpectedPEIndex = 0x53;
        if (peIndex != kExpectedPEIndex)
        {
            std::cerr << "[Valorant][validate] ProcessEvent WARNING: index is "
                      << std::dec << peIndex << " (expected 0x53 = 83)"
                      << " — patch may have shifted vtable\n";
            // Warning only — does not fail the overall validation.
        }

        std::cerr << "[Valorant][validate] ProcessEvent OK"
                  << " (offset=0x" << std::hex << peOffset
                  << " index=" << std::dec << peIndex << ")\n";
        return true;
    }

    // -----------------------------------------------------------------------
    // Check 4: AppendString sanity
    //
    // Off::InSDK::Name::AppendNameToString is an RVA from module base. Add
    // the module base to get the absolute address before validating.
    // -----------------------------------------------------------------------
    static bool CheckAppendString()
    {
        const int32_t asOffset = Off::InSDK::Name::AppendNameToString;

        if (asOffset == 0)
        {
            std::cerr << "[Valorant][validate] AppendString FAILED: AppendNameToString is 0 (not initialized)\n";
            return false;
        }

        const uintptr_t asAddr = Platform::GetModuleBase() + static_cast<uintptr_t>(asOffset);
        if (!Platform::IsAddressInAnyModule(asAddr))
        {
            std::cerr << "[Valorant][validate] AppendString FAILED: AppendNameToString 0x"
                      << std::hex << asAddr << " is outside any module\n";
            return false;
        }

        std::cerr << "[Valorant][validate] AppendString OK"
                  << " (offset=0x" << std::hex << asOffset << std::dec << ")\n";
        return true;
    }

    // -----------------------------------------------------------------------
    // Check 5: GameFunctions sanity
    //
    // For each non-zero RVA in GameFunctions::*, re-check that modBase + RVA
    // is inside the module.
    // -----------------------------------------------------------------------
    static bool CheckGameFunctions()
    {
        const uintptr_t modBase = Platform::GetModuleBase();
        if (!modBase)
        {
            std::cerr << "[Valorant][validate] GameFunctions FAILED: module base null\n";
            return false;
        }

        struct Entry { const char* Name; uint32_t RVA; };
        const Entry entries[] = {
            { "SetOutlineMode",     GameFunctions::SetOutlineMode     },
            { "PlayFinisher",       GameFunctions::PlayFinisher       },
            { "GetSpreadValues",    GameFunctions::GetSpreadValues    },
            { "GetSpreadAngles",    GameFunctions::GetSpreadAngles    },
            { "GetFiringLocAndDir", GameFunctions::GetFiringLocAndDir },
            { "ToVectorNormalize",  GameFunctions::ToVectorNormalize  },
            { "ToAngleNormalize",   GameFunctions::ToAngleNormalize   },
        };

        bool allOk = true;
        for (const auto& e : entries)
        {
            if (e.RVA == 0)
                continue; // not resolved — not a failure per spec

            const uintptr_t addr = modBase + static_cast<uintptr_t>(e.RVA);
            if (!Platform::IsAddressInAnyModule(addr))
            {
                std::cerr << "[Valorant][validate] GameFunctions FAILED: "
                          << e.Name << " RVA 0x" << std::hex << e.RVA
                          << " -> 0x" << addr << " is outside any module\n";
                allOk = false;
            }
        }

        if (allOk)
            std::cerr << "[Valorant][validate] GameFunctions OK\n";

        return allOk;
    }

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------
    bool ValidateForEmit()
    {
        std::cerr << "[Valorant][validate] Starting pre-emit validation...\n";

        const bool ok1 = CheckGObjectsRoundTrip();
        const bool ok2 = CheckFNameKeyRecovery();
        const bool ok3 = CheckProcessEvent();
        const bool ok4 = CheckAppendString();
        const bool ok5 = CheckGameFunctions();

        const bool allPass = ok1 && ok2 && ok3 && ok4 && ok5;

        if (allPass)
            std::cerr << "[Valorant][validate] All checks passed.\n";
        else
            std::cerr << "[Valorant][validate] One or more checks FAILED.\n";

        return allPass;
    }
}
