#pragma once
#include <ntddk.h>

#define POOL_TAG 'ca'

class TargetProcess
{
private:
    // This is the process we are going to protect.
    PWCHAR m_name;

    // PID of target process.
    HANDLE m_pid;

    // Pointer to target process.
    PEPROCESS mp_process;

public:
    TargetProcess();
    virtual ~TargetProcess() = default;

    void* operator new(size_t n);
    void operator delete(void* p);

    const PWCHAR& get_name() const;
    void set_name(const PWCHAR name);

    const HANDLE& get_pid() const;
    void set_pid(const HANDLE pid);

    const PEPROCESS& get_process() const;
    void set_process(const PEPROCESS process);
};