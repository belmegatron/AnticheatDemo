#include "sysinfo.h"
#include "common.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

PSYSTEM_PROCESSES AntiCheat::FindProcess(const PSYSTEM_PROCESSES p_process_list, ULONG_PTR pid)
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
