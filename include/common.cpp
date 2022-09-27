#include "common.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

TargetProcess::TargetProcess() : name(L"notepad.exe"), pid(0), p_process(nullptr)
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
