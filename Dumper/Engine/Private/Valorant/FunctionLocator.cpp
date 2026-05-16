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
        uint32_t ResolveUFunction(const char* PrimaryName, const char* AltName)
        {
            UEFunction Func = ObjectArray::FindObjectFast<UEFunction>(PrimaryName, EClassCastFlags::Function);

            if (!Func)
            {
                if (AltName)
                    Func = ObjectArray::FindObjectFast<UEFunction>(AltName, EClassCastFlags::Function);

                if (!Func)
                {
                    const char* Tried = AltName ? AltName : PrimaryName;
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

            const uintptr_t ModuleBase = Platform::GetModuleBase();
            const uintptr_t FuncAddr   = reinterpret_cast<uintptr_t>(ExecPtr);
            const uint32_t  RVA        = static_cast<uint32_t>(FuncAddr - ModuleBase);

            std::cerr << "[Valorant] UFunction " << PrimaryName << " @ RVA 0x" << std::hex << RVA << std::dec << "\n";
            return RVA;
        }
    }

    void LocateGameFunctions()
    {
        GameFunctions::SetOutlineMode     = ResolveUFunction("SetOutlineMode",          "GetAresOutlineMode");
        GameFunctions::PlayFinisher       = ResolveUFunction("PlayFinisher",            "OnFinisherTriggered");
        GameFunctions::GetSpreadValues    = ResolveUFunction("GetSpreadValues",         nullptr);
        GameFunctions::GetSpreadAngles    = ResolveUFunction("GetSpreadAngles",         nullptr);
        GameFunctions::GetFiringLocAndDir = ResolveUFunction("GetFiringLocAndDir",      "GetFiringLocationAndDirection");
        GameFunctions::ToVectorNormalize  = ResolveUFunction("ToVectorNormalize",       nullptr);
        GameFunctions::ToAngleNormalize   = ResolveUFunction("ToAngleNormalize",        nullptr);
    }
}
