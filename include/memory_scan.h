#pragma once
#include "nt_internals.h"

// Stolen from winnt.h, included hear to avoid conflicts when including winnt.h and ntddk.h
#define MEM_IMAGE 0x1000000

namespace MemoryScanner
{
    constexpr unsigned int scanner_interval_ms = 30000;

    struct State
    {
        // Handle to memory scanner thread.
        HANDLE thread;

        // Timer used to schedule memory scans.
        KTIMER timer;

        // True if the timer used for scheduling our scanner thread has been set.
        bool timer_set;

        void Init()
        {
            thread = nullptr;
            timer = {};
            timer_set = false;
        }
    };

    bool Setup();
    void ScanMemoryRegions(const PSYSTEM_PROCESSES process_list);
    void PrintExecutableMemoryRegion(const PMEMORY_BASIC_INFORMATION p_info);
    void PrintHandlesOpenToTargetProcess(const PSYSTEM_PROCESSES p_process_list, const PSYSTEM_HANDLE_INFORMATION_EX p_handle_list);
}