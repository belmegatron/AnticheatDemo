#include "process_notifications.h"
#include "globals.h"
#include "sysinfo.h"

#pragma warning (disable : 4244)

extern GlobalState g_state;


OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID, POB_PRE_OPERATION_INFORMATION p_info)
{
    Notifications::OnPreOpenProcess(p_info);
    return OB_PREOP_SUCCESS;
}

void OnProcessNotify(PEPROCESS p_process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO p_create_info)
{
    if (p_create_info)
    {
        // TODO: Switch to using process name defined in global state?
        if (wcsstr(p_create_info->CommandLine->Buffer, L"notepad") != nullptr)
        {
            if (g_state.pid != 0)
            {
                p_create_info->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }

            g_state.pid = process_id;
            g_state.process = p_process;

            KdPrint(("notepad.exe has started."));
        }
    }
    else
    {
        if (process_id == g_state.pid)
        {
            KdPrint(("notepad.exe has stopped"));
            g_state.pid = 0;
            g_state.process = nullptr;
        }
    }
}

NTSTATUS Notifications::Setup()
{
    OB_OPERATION_REGISTRATION operations[] = 
    {
        {
            PsProcessType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            ::OnPreOpenProcess, nullptr
        }
    };

    OB_CALLBACK_REGISTRATION reg = 
    {
        OB_FLT_REGISTRATION_VERSION,
        1,
        RTL_CONSTANT_STRING(L"1337.1337"),
        nullptr,
        operations
    };

    return ObRegisterCallbacks(&reg, &g_state.reg_handle);
}

void Notifications::RemoveRWMemoryAccess(POB_PRE_OPERATION_INFORMATION p_info)
{
    if (!p_info)
    {
        return;
    }

    constexpr unsigned long mask = PROCESS_VM_READ | PROCESS_VM_WRITE;

    switch (p_info->Operation)
    {
    case OB_OPERATION_HANDLE_CREATE:
        p_info->Parameters->CreateHandleInformation.DesiredAccess &= ~mask;
        break;
    case OB_OPERATION_HANDLE_DUPLICATE:
        p_info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~mask;
        break;
    default:
        KdPrint(("Requested memory operation unrecognized: %x", p_info->Operation));
    }
}

bool exclusion_check(PSYSTEM_PROCESSES p_entry, HANDLE requesting_pid, const wchar_t* excluded_process_name)
{
    // TODO: Perform some kind of integrity check here.

    bool excluded = false;

    if (p_entry->ProcessName.Length)
    {
        if (wcsstr(p_entry->ProcessName.Buffer, excluded_process_name))
        {
            // Check that the PID from our process list matches the PID of the process requesting access.
            if (ULongToHandle(p_entry->ProcessId) == requesting_pid)
            {
                excluded = true;
            }
        }
    }

    return excluded;
}

void Notifications::OnPreOpenProcess(POB_PRE_OPERATION_INFORMATION p_info)
{
    // Ignore kernel access.
    if (p_info->KernelHandle)
    {
        return;
    }

    PEPROCESS p_process = reinterpret_cast<PEPROCESS>(p_info->Object);
    HANDLE pid = PsGetProcessId(p_process);

    // Ignore cases where the process being accessed is not our target process.
    if (pid != g_state.pid)
    {
        return;
    }

    HANDLE requesting_pid = PsGetCurrentProcessId();

    // Ignore cases where the target process tries to interact with a handle to itself.
    if (requesting_pid == g_state.pid)
    {
        return;
    }

    bool excluded = false;

    // TODO: This is quite expensive but realistically shouldn't be happening too often. Perhaps cache the result
    // and only call again if it's too old?
    PSYSTEM_PROCESSES process_list = SysInfo::ProcessList();

    if (process_list)
    {
        PSYSTEM_PROCESSES p_entry = process_list;

        do
        {
            excluded = exclusion_check(p_entry, requesting_pid, L"csrss.exe");
            if (excluded)
            {
                break;
            }

            excluded = exclusion_check(p_entry, requesting_pid, L"explorer.exe");
            if (excluded)
            {
                break;
            }

            p_entry = reinterpret_cast<PSYSTEM_PROCESSES>(reinterpret_cast<char*>(p_entry) + p_entry->NextEntryDelta);

        } while (p_entry->NextEntryDelta);

        ExFreePoolWithTag(process_list, POOL_TAG);

        // TODO: Would be nice to specify who we denied access to.
        if (!excluded)
        {
            RemoveRWMemoryAccess(p_info);
        }
    }
}

