#pragma once
#include "nt_internals.h"

namespace Scanner
{
    constexpr int MEM_IMAGE = 0x1000000;
    constexpr int FREE = 0x0000000;
    constexpr int NONE = 0x00;

    void Setup();
    void ScanMemoryRegions(PSYSTEM_PROCESSES process_list);
    void PrintMemoryAllocation(MEMORY_BASIC_INFORMATION* p_info);
}