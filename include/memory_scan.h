#pragma once
#include "nt_internals.h"
#include "common.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

// Stolen from winnt.h, included hear to avoid conflicts when including winnt.h and ntddk.h
#define MEM_IMAGE 0x1000000

namespace MemoryScanner
{
    constexpr unsigned int scanner_interval_ms = 30000;

    class Scanner
    {
    private:
        // Handle to memory scanner thread.
        HANDLE m_thread;

        // Timer used to schedule memory scans.
        KTIMER m_timer;

        void ScanMemoryRegions(const PSYSTEM_PROCESSES process_list);
        void PrintExecutableMemoryRegion(const PMEMORY_BASIC_INFORMATION p_info);
        void PrintHandlesOpenToTargetProcess(const PSYSTEM_PROCESSES p_process_list, const PSYSTEM_HANDLE_INFORMATION_EX p_handle_list);

    public:
        Scanner();
        virtual ~Scanner();

        void Scan();

        void* operator new(size_t n)
        {
            void* const p = ExAllocatePoolWithTag(PagedPool, n, POOL_TAG);
            return p;
        }

        void operator delete(void* p)
        {
            ExFreePoolWithTag(p, POOL_TAG);
        }
    };
}