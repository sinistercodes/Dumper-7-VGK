#pragma once

namespace Valorant
{
    // Run deterministic self-tests for the GObjects and FName-mask decrypt
    // functions. Tests use fixed (key, state[7]) fixtures with pre-computed
    // expected outputs. Any mismatch is logged to stderr as:
    //   [Valorant][TEST FAIL] case=N kind=GObjects/FNameMask got=0xXX expected=0xXX
    // The function never aborts the dumper regardless of test outcome.
    void RunDecryptSelfTests();
}
