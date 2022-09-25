#pragma once
#include <ntddk.h>

#define POOL_TAG 'ca'

struct GlobalState
{
    HANDLE pid;
    PEPROCESS process;
    void* reg_handle;
    HANDLE thread;
    bool terminate;
    KTIMER timer;
    KDPC timer_dpc;

    void Init()
    {
        pid = 0;
        process = nullptr;
        reg_handle = nullptr;
        thread = nullptr;
    };

};
