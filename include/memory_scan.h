#pragma once
#include "nt_internals.h"

// Stolen from winnt.h, included hear to avoid conflicts when including winnt.h and ntddk.h
#define MEM_IMAGE 0x1000000

namespace Scanner
{
    constexpr unsigned int scanner_interval_ms = 30000;

    bool Setup();
    void ScanMemoryRegions(const PSYSTEM_PROCESSES process_list);
    void PrintExecutableMemoryRegion(const PMEMORY_BASIC_INFORMATION p_info);
}