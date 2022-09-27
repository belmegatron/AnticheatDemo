#include "anticheat.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

AntiCheat::AntiCheat() : mp_target_process(nullptr), mp_scanner(nullptr), mp_monitor(nullptr)
{
    mp_target_process = new(TargetProcess);
    mp_monitor = new(ProcessMonitor::Monitor)(mp_target_process);
    mp_scanner = new(MemoryScanner::Scanner)(mp_target_process);
}

AntiCheat::~AntiCheat()
{
    if (mp_monitor)
    {
        delete(mp_monitor);
    }

    if (mp_scanner)
    {
        delete(mp_scanner);
    }

    if (mp_target_process)
    {
        delete(mp_target_process);
    }
}

void* AntiCheat::operator new(size_t n)
{
    void* const p = ExAllocatePoolWithTag(PagedPool, n, POOL_TAG);
    return p;
}

void AntiCheat::operator delete(void* p)
{
    ExFreePoolWithTag(p, POOL_TAG);
}