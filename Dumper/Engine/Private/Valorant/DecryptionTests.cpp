#include "Valorant/DecryptionTests.h"
#include "Valorant/Decryption.h"

#include <cstdint>
#include <iostream>

// ============================================================================
// Decrypt self-tests — behavioral lock against the current implementation.
//
// Each fixture targets a specific selector case by choosing a key value for
// which (kMagic * mix) % 7 resolves to exactly that case. Keys are the
// smallest 32-bit values that land on each case (brute-forced once):
//
//   case 0 → key=0x00000006  (hash=0xAF5CD5C5388D2EAE)
//   case 1 → key=0x00000003  (hash=0xD7AE6AE29C469757)
//   case 2 → key=0x00000005  (hash=0x67780779AF205191)
//   case 3 → key=0x00000002  (hash=0x8FC99C9712D9BA3A)
//   case 4 → key=0x00000004  (hash=0x1F93392E25B37474)
//   case 5 → key=0x00000001  (hash=0x47E4CE4B896CDD1D)
//   case 6 → key=0x00000009  (hash=0x870B40A7D4D3C605)
//
// Expected values were computed in Python by a bit-exact port of the C++
// implementation and baked in as frozen constants.
// ============================================================================

namespace Valorant
{
    namespace
    {
        struct DecryptFixture
        {
            int      caseIdx;
            uint32_t key;
            uint64_t state[7];
            uint64_t expectedGObjects;
            uint64_t expectedFNameMask;
        };

        // Shared deterministic state — varied non-zero values, one per slot.
        static const uint64_t kTestState[7] = {
            0xFEDCBA9876543210ULL,
            0x0FEDCBA987654321ULL,
            0x10FEDCBA98765432ULL,
            0x210FEDCBA9876543ULL,
            0x3210FEDCBA987654ULL,
            0x43210FEDCBA98765ULL,
            0x543210FEDCBA9876ULL,
        };

        static const DecryptFixture kFixtures[7] = {
            // case 0: v ^= hi32
            { 0, 0x00000006U,
              { kTestState[0], kTestState[1], kTestState[2], kTestState[3], kTestState[4], kTestState[5], kTestState[6] },
              0xFEDCBA98D908E7D3ULL, 0x01234566DA4EF82DULL },
            // case 1: v = uint32(hi+idx) + ROL(state, ((hi+2*idx)%63)+1)
            // FNameMask expected re-captured after the width-of-NOT fix in
            // commit 77ecadf -- pre-fix value was 0xF02138A95F38E936ULL, which
            // differed in the upper 32 bits because ~ ran at uint64 width.
            { 1, 0x00000003U,
              { kTestState[0], kTestState[1], kTestState[2], kTestState[3], kTestState[4], kTestState[5], kTestState[6] },
              0x21FDB976089B1344ULL, 0x0FDEC7565F38E936ULL },
            // case 2: v = ~state - uint32(hi+idx)
            { 2, 0x00000005U,
              { kTestState[0], kTestState[1], kTestState[2], kTestState[3], kTestState[4], kTestState[5], kTestState[6] },
              0xEF0123450011A457ULL, 0xDF02138A9B4657CBULL },
            // case 3: v = ROR(bitrev64(state), ((hi+idx)%63)+1)
            { 3, 0x00000002U,
              { kTestState[0], kTestState[1], kTestState[2], kTestState[3], kTestState[4], kTestState[5], kTestState[6] },
              0x54DE109A76FC32BAULL, 0x120FDECC36A202D2ULL },
            // case 4: v = state + uint32(hi+2*idx) + uint32(hi+idx)
            { 4, 0x00000004U,
              { kTestState[0], kTestState[1], kTestState[2], kTestState[3], kTestState[4], kTestState[5], kTestState[6] },
              0x3210FEDCF9BEE8B8ULL, 0x26AE159D048C37BBULL },
            // case 5: v = ROL(stage1(state), ((hi+idx)%63)+1)
            { 5, 0x00000001U,
              { kTestState[0], kTestState[1], kTestState[2], kTestState[3], kTestState[4], kTestState[5], kTestState[6] },
              0xBD8EAC973506241EULL, 0xB2A19087F6E5D4C2ULL },
            // case 6: v = ROR(uint32(hi+2*idx) + state, ((hi+idx)%63)+1)
            { 6, 0x00000009U,
              { kTestState[0], kTestState[1], kTestState[2], kTestState[3], kTestState[4], kTestState[5], kTestState[6] },
              0x10FF63C5D929543BULL, 0x86570A9BC2134ED6ULL },
        };

    } // anonymous namespace

    void RunDecryptSelfTests()
    {
        int passed = 0;
        int failed = 0;

        for (int i = 0; i < 7; ++i)
        {
            const DecryptFixture& f = kFixtures[i];

            const uint64_t gotGObjects  = Valorant::DecryptGObjectsPtr(f.key, f.state);
            const uint64_t gotFNameMask = Valorant::DecryptFNameMask(f.key, f.state);

            bool ok = true;

            if (gotGObjects != f.expectedGObjects)
            {
                std::cerr << "[Valorant][TEST FAIL] case=" << f.caseIdx
                          << " kind=GObjects"
                          << " got=0x"      << std::hex << gotGObjects
                          << " expected=0x" << f.expectedGObjects
                          << std::dec << "\n";
                ok = false;
                ++failed;
            }

            if (gotFNameMask != f.expectedFNameMask)
            {
                std::cerr << "[Valorant][TEST FAIL] case=" << f.caseIdx
                          << " kind=FNameMask"
                          << " got=0x"      << std::hex << gotFNameMask
                          << " expected=0x" << f.expectedFNameMask
                          << std::dec << "\n";
                ok = false;
                ++failed;
            }

            if (ok)
            {
                std::cerr << "[Valorant][TEST PASS] case=" << f.caseIdx << "\n";
                ++passed;
            }
        }

        std::cerr << "[Valorant][TESTS] " << passed << " passed, "
                  << failed << " failed\n";
    }

} // namespace Valorant
