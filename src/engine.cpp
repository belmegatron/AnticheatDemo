#include "engine.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

AntiCheat::Engine::Engine() : 
    mp_target_process(new(TargetProcess)), 
    mp_scanner(new(MemoryScanner)(mp_target_process)),
    mp_monitor(new(ProcessMonitor)(mp_target_process))
{
}

AntiCheat::Engine::~Engine()
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

void* AntiCheat::Engine::operator new(size_t n)
{
    void* const p = ExAllocatePoolWithTag(PagedPool, n, POOL_TAG);
    return p;
}

void AntiCheat::Engine::operator delete(void* p)
{
    ExFreePoolWithTag(p, POOL_TAG);
}