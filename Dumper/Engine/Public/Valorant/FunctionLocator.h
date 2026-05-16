#pragma once
#include <cstdint>

namespace Valorant
{
    // Each = 0 until LocateGameFunctions runs. Populated with RVAs (function
    // address - module base) for the matching reflected UFunction.
    namespace GameFunctions
    {
        inline uint32_t SetOutlineMode     = 0; // resolves "SetOutlineMode" or "GetAresOutlineMode"
        inline uint32_t PlayFinisher       = 0; // "PlayFinisher" or "OnFinisherTriggered"
        inline uint32_t GetSpreadValues    = 0;
        inline uint32_t GetSpreadAngles    = 0;
        inline uint32_t GetFiringLocAndDir = 0; // "GetFiringLocAndDir" or "GetFiringLocationAndDirection"
        inline uint32_t ToVectorNormalize  = 0;
        inline uint32_t ToAngleNormalize   = 0;
    }

    void LocateGameFunctions();
}
