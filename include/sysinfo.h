#pragma once
#include "nt_internals.h"

namespace AntiCheat
{
    template<typename T>
    T* SysInfo(SYSTEM_INFORMATION_CLASS info_type)
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

            status = ZwQuerySystemInformation(info_type, buf, buf_size, &buf_size);

        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (NT_ERROR(status) && buf)
        {
            ExFreePoolWithTag(buf, POOL_TAG);
        }

        return reinterpret_cast<T*>(buf);
    }

    PSYSTEM_PROCESSES FindProcess(const PSYSTEM_PROCESSES process_list, ULONG_PTR pid);
}