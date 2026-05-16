#pragma once

namespace Valorant
{
    // Performs an in-process self-consistency check against the live binary
    // state that the dumper would encode into ValorantDecrypt.h.
    //
    // Checks performed (each logged individually):
    //   1. GObjects round-trip   — decrypt, validate FUObjectArray header and vtable
    //   2. FName key recovery    — XOR-recover key from "None" entry, decrypt in-place
    //   3. ProcessEvent index    — pointer inside module; warn if index != 0x53
    //   4. AppendString sanity   — pointer inside module
    //   5. GameFunctions sanity  — every non-zero RVA points inside module
    //
    // Returns true iff all checks pass (ProcessEvent index mismatch is a
    // warning, not a failure). Never writes process memory.
    bool ValidateForEmit();
}
