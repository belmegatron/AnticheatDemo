#include "common.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

AntiCheat::TargetProcess::TargetProcess() :
    m_name(L"notepad.exe"), 
    m_pid(0), 
    mp_process(nullptr)
{
}

void* AntiCheat::TargetProcess::operator new(size_t n)
{
    return ExAllocatePoolWithTag(PagedPool, n, POOL_TAG);
}

void AntiCheat::TargetProcess::operator delete(void* p)
{
    ExFreePoolWithTag(p, POOL_TAG);
}

const PWCHAR& AntiCheat::TargetProcess::get_name() const
{
    return m_name;
}

void AntiCheat::TargetProcess::set_name(const PWCHAR name)
{
    m_name = name;
}

const HANDLE& AntiCheat::TargetProcess::get_pid() const
{
    return m_pid;
}

void AntiCheat::TargetProcess::set_pid(const HANDLE pid)
{
    m_pid = pid;
}

const PEPROCESS& AntiCheat::TargetProcess::get_process() const
{
    return mp_process;
}

void AntiCheat::TargetProcess::set_process(const PEPROCESS process)
{
    mp_process = process;
}
