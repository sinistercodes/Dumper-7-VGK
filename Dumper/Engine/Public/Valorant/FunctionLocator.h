#pragma once
#include <cstdint>
#include <string>

namespace Valorant
{
    // Each = 0 until LocateGameFunctions runs. Populated with RVAs (function
    // address - module base) for the matching reflected UFunction.
    // The parallel *FullName strings hold the resolved UE full path
    // (e.g. "Function ShooterGame.AresOutlineComponent.SetOutlineMode")
    // for use in output / JSON manifests. Empty string means not found.
    namespace GameFunctions
    {
        inline uint32_t SetOutlineMode     = 0; // resolves "SetOutlineMode" or "GetAresOutlineMode"
        inline uint32_t PlayFinisher       = 0; // "PlayFinisher" or "OnFinisherTriggered"
        inline uint32_t GetSpreadValues    = 0;
        inline uint32_t GetSpreadAngles    = 0;
        inline uint32_t GetFiringLocAndDir = 0; // "GetFiringLocAndDir" or "GetFiringLocationAndDirection"
        inline uint32_t ToVectorNormalize  = 0;
        inline uint32_t ToAngleNormalize   = 0;

        inline std::string SetOutlineModeFullName;
        inline std::string PlayFinisherFullName;
        inline std::string GetSpreadValuesFullName;
        inline std::string GetSpreadAnglesFullName;
        inline std::string GetFiringLocAndDirFullName;
        inline std::string ToVectorNormalizeFullName;
        inline std::string ToAngleNormalizeFullName;
    }

    void LocateGameFunctions();
}
