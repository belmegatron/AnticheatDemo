#pragma once
#include "common.h"
#include "memory_scan.h"
#include "process_monitor.h"

class AntiCheat
{
public:
    TargetProcess* const mp_target_process;
    ProcessMonitor::Monitor* const mp_monitor;
    MemoryScanner::Scanner* const mp_scanner;

    AntiCheat();
    virtual ~AntiCheat();

    void* operator new(size_t n);
    void operator delete(void* p);
};
