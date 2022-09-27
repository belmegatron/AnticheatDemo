#pragma once
#include "nt_internals.h"
#include "common.h"

// Stolen from winnt.h, included hear to avoid conflicts when including winnt.h and ntddk.h
#define MEM_IMAGE 0x1000000

namespace MemoryScanner
{
    constexpr unsigned int scanner_interval_ms = 30000;

    class Scanner
    {
    private:

        // Contains details on the target process that we are protecting.
        const TargetProcess* mp_target_process;

        // Handle to memory scanner thread.
        HANDLE m_thread;

        // Timer used to schedule memory scans.
        KTIMER m_timer;

        // Signalled when we wish to stop scanning.
        KEVENT m_terminate_scan;

        void ScanMemoryRegions(const PSYSTEM_PROCESSES process_list);
        void PrintExecutableMemoryRegion(const PMEMORY_BASIC_INFORMATION p_info);
        void PrintHandlesOpenToTargetProcess(const PSYSTEM_PROCESSES p_process_list, const PSYSTEM_HANDLE_INFORMATION_EX p_handle_list);

    public:
        Scanner(const TargetProcess* p_target_process);
        virtual ~Scanner();

        void* operator new(size_t n);
        void operator delete(void* p);

        void Scan();
    };
}