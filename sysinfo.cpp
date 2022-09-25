#include "sysinfo.h"
#include "globals.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

PSYSTEM_PROCESSES SysInfo::ProcessList()
{
    ULONG bufferSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, nullptr, 0, &bufferSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        void* buf = ExAllocatePoolWithTag(PagedPool, bufferSize, POOL_TAG);
        if (buf)
        {
            status = ZwQuerySystemInformation(SystemProcessInformation, buf, bufferSize, &bufferSize);
            if (NT_SUCCESS(status))
            {
                return reinterpret_cast<PSYSTEM_PROCESSES>(buf);
            }

            ExFreePoolWithTag(buf, POOL_TAG);
        }
    }

    return nullptr;
}

PSYSTEM_HANDLE_INFORMATION_EX  SysInfo::HandleList()
{
    ULONG bufferSize = sizeof(SYSTEM_HANDLE_INFORMATION_EX);
    NTSTATUS status = STATUS_INVALID_HANDLE;
    void* buf = nullptr;

    do
    {
        if (buf)
        {
            ExFreePoolWithTag(buf, POOL_TAG);
            buf = nullptr;
        }

        buf = ExAllocatePoolWithTag(PagedPool, bufferSize, POOL_TAG);

        status = ZwQuerySystemInformation(SystemExtendedHandleInformation, buf, bufferSize, &bufferSize);

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status))
    {
        return reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buf);
    }
    else
    {
        if (buf)
        {
            ExFreePoolWithTag(buf, POOL_TAG);
        }
    }

    return nullptr;
}

PSYSTEM_PROCESSES SysInfo::FindProcess(PSYSTEM_PROCESSES process_list, ULONG_PTR pid)
{
    PSYSTEM_PROCESSES p_entry = process_list;

    do
    {
        if (p_entry->ProcessId == pid)
        {
            return p_entry;
        }

        p_entry = (PSYSTEM_PROCESSES)((char*)p_entry + p_entry->NextEntryDelta);

    } while (p_entry->ProcessId);

    return nullptr;
}

PSYSTEM_PROCESSES SysInfo::FindProcess(PSYSTEM_PROCESSES process_list, const wchar_t* process_name)
{
    PSYSTEM_PROCESSES p_entry = process_list;

    do
    {
        if (p_entry->ProcessName.Length)
        {
            // TODO: Perform some kind of integrity check here.

            if (wcsstr(p_entry->ProcessName.Buffer, process_name))
            {
                return p_entry;
            }
        }

        p_entry = (PSYSTEM_PROCESSES)((char*)p_entry + p_entry->NextEntryDelta);

    } while (p_entry->NextEntryDelta);

    return nullptr;
}
