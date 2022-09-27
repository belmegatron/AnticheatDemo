#pragma once
#include "common.h"
#include "memory_scan.h"
#include "process_notifications.h"

class AntiCheat
{
public:
    TargetProcess* mp_target_process;
    ProcessNotifications::Notifier* mp_notifier;
    MemoryScanner::Scanner* mp_scanner;

    AntiCheat();
    virtual ~AntiCheat();

    void* operator new(size_t n);
    void operator delete(void* p);
};
