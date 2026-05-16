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
            // Validate the ExecFunction lands inside the GAME module specifically,
            // not just any loaded DLL. Otherwise an unrelated module's address
            // would pass IsAddressInAnyModule but produce a poison "RVA" once we
            // subtract the game module base. A loose +0x10000000 (256 MB) bound
            // on the resulting RVA rejects addresses in other modules without
            // needing the (Platform-unexposed) game module size.
            const uintptr_t ModuleBase = Platform::GetModuleBase();
            const bool inGameModule =
                FuncAddr >= ModuleBase &&
                (FuncAddr - ModuleBase) < 0x10000000ULL &&
                Platform::IsAddressInAnyModule(FuncAddr);
            if (!inGameModule)
            {
                std::cerr << "[Valorant] UFunction " << PrimaryName
                          << " ExecFunction 0x" << std::hex << FuncAddr << std::dec
                          << " is outside any loaded module -- treating as not found\n";
                return 0;
            }

            const uint32_t RVA = static_cast<uint32_t>(FuncAddr - ModuleBase);
            OutFullName = Func.GetFullName();
            std::cerr << "[Valorant] UFunction " << OutFullName
                      << " @ RVA 0x" << std::hex << RVA << std::dec << "\n";
            return RVA;
        }
    }

    void LocateGameFunctions()
    {
        GameFunctions::SetOutlineMode     = ResolveUFunction("SetOutlineMode",          "GetAresOutlineMode",                       GameFunctions::SetOutlineModeFullName);

        // PlayFinisher: bare short name isn't registered as a UFunction in
        // this build. The real server-side handler is AuthOnFinisherTriggered;
        // OnFinisherTriggered__DelegateSignature is the multicast delegate.
        GameFunctions::PlayFinisher       = ResolveUFunction("AuthOnFinisherTriggered", "OnFinisherTriggered__DelegateSignature",   GameFunctions::PlayFinisherFullName);

        // GetSpread{Values,Angles}: not present as UFunctions in this build --
        // the spread math is inlined into GetFiringLocationAndDirection.
        // Consumers that need spread should hook that function instead.
        GameFunctions::GetSpreadValues    = ResolveUFunction("GetSpreadValues",         nullptr,                                    GameFunctions::GetSpreadValuesFullName);
        GameFunctions::GetSpreadAngles    = ResolveUFunction("GetSpreadAngles",         nullptr,                                    GameFunctions::GetSpreadAnglesFullName);

        GameFunctions::GetFiringLocAndDir = ResolveUFunction("GetFiringLocAndDir",      "GetFiringLocationAndDirection",            GameFunctions::GetFiringLocAndDirFullName);

        // To{Vector,Angle}Normalize: not UFunction-registered. The BP-callable
        // equivalents from UKismetMathLibrary are Vector_Normalize and
        // NormalizeAxis (Quat_Normalize is a quaternion-specific alt).
        GameFunctions::ToVectorNormalize  = ResolveUFunction("Vector_Normalize",        nullptr,                                    GameFunctions::ToVectorNormalizeFullName);
        GameFunctions::ToAngleNormalize   = ResolveUFunction("NormalizeAxis",           "Quat_Normalize",                           GameFunctions::ToAngleNormalizeFullName);
    }
}
