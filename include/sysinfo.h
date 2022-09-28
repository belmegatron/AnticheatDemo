#pragma once
#include "nt_internals.h"

namespace AntiCheat
{
    template<typename T>
    T* SysInfo(SYSTEM_INFORMATION_CLASS info_class)
    {
        NTSTATUS status = STATUS_INVALID_HANDLE;

        ULONG buf_size = sizeof(T);
        void* buf = nullptr;

        do
        {
            if (buf)
            {
                ExFreePoolWithTag(buf, POOL_TAG);
                buf = nullptr;
            }

            buf = ExAllocatePoolWithTag(PagedPool, buf_size, POOL_TAG);

            status = ZwQuerySystemInformation(info_class, buf, buf_size, &buf_size);

        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (NT_ERROR(status) && buf)
        {
            ExFreePoolWithTag(buf, POOL_TAG);
        }

        return reinterpret_cast<T*>(buf);
    }

    template<typename T>
    T* ProcessInfo(const HANDLE h_process, PROCESSINFOCLASS info_class)
    {
        NTSTATUS status = STATUS_INVALID_HANDLE;

        ULONG buf_size = sizeof(T);
        void* buf = nullptr;

        do
        {
            if (buf)
            {
                ExFreePoolWithTag(buf, POOL_TAG);
                buf = nullptr;
            }

            buf = ExAllocatePoolWithTag(PagedPool, buf_size, POOL_TAG);

            status = ZwQueryInformationProcess(h_process, info_class, buf, buf_size, &buf_size);

        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (NT_ERROR(status) && buf)
        {
            ExFreePoolWithTag(buf, POOL_TAG);
        }

        return reinterpret_cast<T*>(buf);
    }

    PSYSTEM_PROCESSES FindProcess(const PSYSTEM_PROCESSES process_list, ULONG_PTR pid);
}