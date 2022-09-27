#pragma once
#include <ntddk.h>

#define POOL_TAG 'ca'

class TargetProcess
{
public:
    // This is the process we are going to protect.
    PWCHAR name;

    // PID of target process.
    HANDLE pid;

    // Pointer to target process.
    PEPROCESS p_process;

    TargetProcess();
    virtual ~TargetProcess() = default;

    void* operator new(size_t n);
    void operator delete(void* p);
};