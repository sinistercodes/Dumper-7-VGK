#include "Valorant/FunctionLocator.h"

#include "Unreal/ObjectArray.h"
#include "Unreal/UnrealObjects.h"
#include "OffsetFinder/Offsets.h"
#include "Platform.h"

#include <iostream>

namespace Valorant
{
    namespace
    {
        // Resolve a UFunction by primary name, falling back to an alternate name.
        // Returns 0 if neither is found. Logs result to stderr either way.
        // OutFullName is set to the resolved UE full path on success, empty on failure.
        uint32_t ResolveUFunction(const char* PrimaryName, const char* AltName, std::string& OutFullName)
        {
            OutFullName.clear();

            UEFunction Func = ObjectArray::FindObjectFast<UEFunction>(PrimaryName, EClassCastFlags::Function);

            if (!Func)
            {
                if (AltName)
                    Func = ObjectArray::FindObjectFast<UEFunction>(AltName, EClassCastFlags::Function);

                if (!Func)
                {
                    std::cerr << "[Valorant] UFunction " << PrimaryName;
                    if (AltName)
                        std::cerr << " / " << AltName;
                    std::cerr << " not found\n";
                    return 0;
                }
            }

            void* ExecPtr = Func.GetExecFunction();
            if (!ExecPtr)
            {
                std::cerr << "[Valorant] UFunction " << PrimaryName << " ExecFunction is null\n";
                return 0;
            }

            // FindObjectFast returns the first short-name match, which can hit
            // an unrelated UFunction in a different class. Verify the resolved
            // ExecFunction lands inside a loaded module — if it doesn't, the
            // result is poison and worse than 0 (consumers would call random
            // memory). Log the full UE path so name collisions are visible.
            const uintptr_t FuncAddr = reinterpret_cast<uintptr_t>(ExecPtr);
            if (!Platform::IsAddressInAnyModule(FuncAddr))
            {
                std::cerr << "[Valorant] UFunction " << PrimaryName
                          << " ExecFunction 0x" << std::hex << FuncAddr << std::dec
                          << " is outside any loaded module -- treating as not found\n";
                return 0;
            }

            const uint32_t RVA = static_cast<uint32_t>(FuncAddr - Platform::GetModuleBase());
            OutFullName = Func.GetFullName();
            std::cerr << "[Valorant] UFunction " << OutFullName
                      << " @ RVA 0x" << std::hex << RVA << std::dec << "\n";
            return RVA;
        }
    }

    void LocateGameFunctions()
    {
        GameFunctions::SetOutlineMode     = ResolveUFunction("SetOutlineMode",          "GetAresOutlineMode",            GameFunctions::SetOutlineModeFullName);
        GameFunctions::PlayFinisher       = ResolveUFunction("PlayFinisher",            "OnFinisherTriggered",           GameFunctions::PlayFinisherFullName);
        GameFunctions::GetSpreadValues    = ResolveUFunction("GetSpreadValues",         nullptr,                         GameFunctions::GetSpreadValuesFullName);
        GameFunctions::GetSpreadAngles    = ResolveUFunction("GetSpreadAngles",         nullptr,                         GameFunctions::GetSpreadAnglesFullName);
        GameFunctions::GetFiringLocAndDir = ResolveUFunction("GetFiringLocAndDir",      "GetFiringLocationAndDirection", GameFunctions::GetFiringLocAndDirFullName);
        GameFunctions::ToVectorNormalize  = ResolveUFunction("ToVectorNormalize",       nullptr,                         GameFunctions::ToVectorNormalizeFullName);
        GameFunctions::ToAngleNormalize   = ResolveUFunction("ToAngleNormalize",        nullptr,                         GameFunctions::ToAngleNormalizeFullName);
    }
}
