#include "sysinfo.h"
#include "common.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

PSYSTEM_PROCESSES SysInfo::ProcessList()
{
    NTSTATUS status = STATUS_INVALID_HANDLE;

    ULONG buf_size = sizeof(SYSTEM_HANDLE_INFORMATION_EX);
    void* buf = nullptr;

    do
    {
        if (buf)
        {
            ExFreePoolWithTag(buf, POOL_TAG);
            buf = nullptr;
        }

        buf = ExAllocatePoolWithTag(PagedPool, buf_size, POOL_TAG);

        status = ZwQuerySystemInformation(SystemProcessInformation, buf, buf_size, &buf_size);

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status) && buf)
    {
        ExFreePoolWithTag(buf, POOL_TAG);
    }

    return reinterpret_cast<PSYSTEM_PROCESSES>(buf);
}

PSYSTEM_HANDLE_INFORMATION_EX  SysInfo::HandleList()
{
    NTSTATUS status = STATUS_INVALID_HANDLE;
    
    ULONG buf_size = sizeof(SYSTEM_HANDLE_INFORMATION_EX);
    void* buf = nullptr;

    do
    {
        if (buf)
        {
            ExFreePoolWithTag(buf, POOL_TAG);
            buf = nullptr;
        }

        buf = ExAllocatePoolWithTag(PagedPool, buf_size, POOL_TAG);

        status = ZwQuerySystemInformation(SystemExtendedHandleInformation, buf, buf_size, &buf_size);

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status) && buf)
    {
        ExFreePoolWithTag(buf, POOL_TAG);
    }

    return reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buf);
}

PSYSTEM_PROCESSES SysInfo::FindProcess(const PSYSTEM_PROCESSES p_process_list, ULONG_PTR pid)
{
    if (!p_process_list)
    {
        return nullptr;
    }

    PSYSTEM_PROCESSES p_entry = p_process_list;

    do
    {
        if (p_entry->ProcessId == pid)
        {
            return p_entry;
        }

        p_entry = reinterpret_cast<PSYSTEM_PROCESSES>(reinterpret_cast<char*>(p_entry) + p_entry->NextEntryDelta);

    } while (p_entry->ProcessId);

    return nullptr;
}
