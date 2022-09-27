#include "common.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

TargetProcess::TargetProcess() : m_name(L"notepad.exe"), m_pid(0), mp_process(nullptr)
{
}

void* TargetProcess::operator new(size_t n)
{
    return ExAllocatePoolWithTag(PagedPool, n, POOL_TAG);

}

void TargetProcess::operator delete(void* p)
{
    ExFreePoolWithTag(p, POOL_TAG);
}

const PWCHAR& TargetProcess::get_name()
{
    return m_name;
}

void TargetProcess::set_name(const PWCHAR name)
{
    m_name = name;
}

const HANDLE& TargetProcess::get_pid()
{
    return m_pid;
}

void TargetProcess::set_pid(const HANDLE pid)
{
    m_pid = pid;
}

const PEPROCESS& TargetProcess::get_process()
{
    return mp_process;
}

void TargetProcess::set_process(const PEPROCESS process)
{
    mp_process = process;
}
