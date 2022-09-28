#include "engine.h"
#include "process_monitor.h"
#include "sysinfo.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

extern AntiCheat::Engine* gp_anticheat;

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID, POB_PRE_OPERATION_INFORMATION p_info)
{
    gp_anticheat->mp_monitor->OnPreOpenProcess(p_info);
    return OB_PREOP_SUCCESS;
}

void OnProcessNotify(PEPROCESS p_process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO p_create_info)
{
    gp_anticheat->mp_monitor->OnProcessNotify(p_process, process_id, p_create_info);
}

void AntiCheat::ProcessMonitor::RemoveRWMemoryAccess(POB_PRE_OPERATION_INFORMATION p_info)
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

bool AntiCheat::ProcessMonitor::ProcessEntryMatchesNameAndPID(const PSYSTEM_PROCESSES p_entry, const wchar_t* name, const HANDLE pid)
{
    bool matches = false;

    if (!p_entry || !name)
    {
        return matches;
    }

    if (p_entry->ProcessName.Length)
    {
        if (wcsstr(p_entry->ProcessName.Buffer, name))
        {
            if (reinterpret_cast<HANDLE>(p_entry->ProcessId) == pid)
            {
                matches = true;
            }
        }
    }

    return matches;
}

AntiCheat::ProcessMonitor::ProcessMonitor(TargetProcess* p_target_process) :
    mp_target_process(p_target_process), 
    m_notification_set(false), 
    mp_callback_reg_handle(nullptr)
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(::OnProcessNotify, false);

    if (!NT_SUCCESS(status))
    {
        return;
    }

    m_notification_set = true;

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
        RTL_CONSTANT_STRING(L"9876.5432"),
        nullptr,
        operations
    };

    ObRegisterCallbacks(&reg, &mp_callback_reg_handle);
}

AntiCheat::ProcessMonitor::~ProcessMonitor()
{
    if (m_notification_set)
    {
        PsSetCreateProcessNotifyRoutineEx(::OnProcessNotify, true);
    }

    if (mp_callback_reg_handle)
    {
        ObUnRegisterCallbacks(mp_callback_reg_handle);
    }
}

void* AntiCheat::ProcessMonitor::operator new(size_t n)
{
    void* const p = ExAllocatePoolWithTag(PagedPool, n, POOL_TAG);
    return p;
}

void AntiCheat::ProcessMonitor::operator delete(void* p)
{
    ExFreePoolWithTag(p, POOL_TAG);
}

void AntiCheat::ProcessMonitor::OnPreOpenProcess(POB_PRE_OPERATION_INFORMATION p_info)
{
    if (!p_info)
    {
        return;
    }

    // Ignore kernel access.
    if (p_info->KernelHandle)
    {
        return;
    }

    const PEPROCESS p_process = reinterpret_cast<PEPROCESS>(p_info->Object);
    const HANDLE pid = PsGetProcessId(p_process);

    // Ignore cases where the process being accessed is not our target process.
    if (pid != mp_target_process->get_pid())
    {
        return;
    }

    const HANDLE requesting_pid = PsGetCurrentProcessId();

    // Ignore cases where the process requesting access to our target process, is the target process.
    if (requesting_pid == mp_target_process->get_pid())
    {
        return;
    }

    bool allow_access = false;

    const PSYSTEM_PROCESSES p_process_list = ProcessList();

    if (p_process_list)
    {
        PSYSTEM_PROCESSES p_entry = p_process_list;

        do
        {
            allow_access = ProcessEntryMatchesNameAndPID(p_entry, L"csrss.exe", requesting_pid);
            if (allow_access)
            {
                break;
            }

            allow_access = ProcessEntryMatchesNameAndPID(p_entry, L"explorer.exe", requesting_pid);
            if (allow_access)
            {
                break;
            }

            p_entry = reinterpret_cast<PSYSTEM_PROCESSES>(reinterpret_cast<char*>(p_entry) + p_entry->NextEntryDelta);

        } while (p_entry->NextEntryDelta);

        ExFreePoolWithTag(p_process_list, POOL_TAG);

        if (!allow_access)
        {
            RemoveRWMemoryAccess(p_info);
        }
    }
}

void AntiCheat::ProcessMonitor::OnProcessNotify(PEPROCESS p_process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO p_create_info)
{
    if (p_create_info)
    {
        if (wcsstr(p_create_info->CommandLine->Buffer, mp_target_process->get_name()) != nullptr)
        {
            if (mp_target_process->get_pid() != 0)
            {
                p_create_info->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }

            mp_target_process->set_pid(process_id);
            mp_target_process->set_process(p_process);

            KdPrint(("%ws has started.", mp_target_process->get_name()));
        }
    }
    else
    {
        if (mp_target_process->get_pid() == process_id)
        {
            KdPrint(("%ws has stopped", mp_target_process->get_name()));
            mp_target_process->set_pid(0);
            mp_target_process->set_process(nullptr);
        }
    }
}

