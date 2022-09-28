#pragma once
#include "common.h"
#include "memory_scan.h"
#include "process_monitor.h"

namespace AntiCheat
{
    class Engine
    {
    public:
        TargetProcess* const mp_target_process;
        ProcessMonitor* const mp_monitor;
        MemoryScanner* const mp_scanner;

        Engine();
        virtual ~Engine();

        void* operator new(size_t n);
        void operator delete(void* p);
    };
}