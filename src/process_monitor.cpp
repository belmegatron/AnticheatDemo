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

void AntiCheat::ProcessMonitor::DenyRWMemoryAccess(POB_PRE_OPERATION_INFORMATION p_info)
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

AntiCheat::ProcessMonitor::ProcessMonitor(TargetProcess* p_target_process) :
    mp_target_process(p_target_process), 
    m_notification_set(false), 
    mp_callback_reg_handle(nullptr)
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(::OnProcessNotify, false);

    if (NT_ERROR(status))
    {
        mp_initialization_error.code = InitializationError::set_notify_routine;
        mp_initialization_error.status = status;
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

    status = ObRegisterCallbacks(&reg, &mp_callback_reg_handle);
    if (NT_ERROR(status))
    {
        mp_initialization_error.code = InitializationError::register_callbacks;
        mp_initialization_error.status = status;
    }
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

AntiCheat::Error AntiCheat::ProcessMonitor::Initialized()
{
    return mp_initialization_error;
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

    // Ignore cases where the target process is requesting access to itself.
    if (requesting_pid == mp_target_process->get_pid())
    {
        return;
    }

    const PSYSTEM_PROCESSES p_process_list = SysInfo<SYSTEM_PROCESSES>(SystemProcessInformation);

    if (p_process_list)
    {
        const PSYSTEM_PROCESSES p_requesting_process = FindProcess(p_process_list, reinterpret_cast<ULONG_PTR>(requesting_pid));
        if (!p_requesting_process)
        {
            return;
        }

        const PWCHAR process_name = p_requesting_process->ProcessName.MaximumLength > 0 ? p_requesting_process->ProcessName.Buffer : L"";
        
        bool allowed_process = false;

        constexpr size_t allowed_process_count = 2;

        // In a real life scenario, we would do some additional verification here. We would get the path to the actual PE used to launch this process (ZwQueryInformationProcess with ProcessImageFileName)
        // Open a handle to the file (ZwCreateFile) and then use a Crypt provider to perform a hash of the file content and perform a lookup against a list of known hashes.

        const PWCHAR allowed_processes[allowed_process_count] = { L"csrss.exe", L"explorer.exe" };

        for (unsigned int i = 0; i < allowed_process_count; ++i)
        {
            if (wcsstr(process_name, allowed_processes[i]))
            {
                KdPrint(("Allowed %ws", process_name));
                allowed_process = true;
                break;
            }
        }

        if (!allowed_process)
        {
            DenyRWMemoryAccess(p_info);
        }

        ExFreePoolWithTag(p_process_list, POOL_TAG);
    }
}

void AntiCheat::ProcessMonitor::OnProcessNotify(PEPROCESS p_process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO p_create_info)
{
    if (p_create_info)
    {
        // Check if it's a notification regarding our target process.
        if (wcsstr(p_create_info->CommandLine->Buffer, mp_target_process->get_name()) == nullptr)
        {
            return;
        }

        // If the PID isn't 0, it means we are already protecting a process. For the purposes of this demo, we will only allow allow one process to run 
        // that matches the name of our target executable.
        if (mp_target_process->get_pid() != 0)
        {
            p_create_info->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }

        mp_target_process->set_pid(process_id);
        mp_target_process->set_process(p_process);

        KdPrint(("%ws has started.", mp_target_process->get_name()));
    }
    else
    {
        // Check it if it's our target process that has stopped.
        if (mp_target_process->get_pid() != process_id)
        {
            return;
        }

        KdPrint(("%ws has stopped", mp_target_process->get_name()));
        mp_target_process->set_pid(0);
        mp_target_process->set_process(nullptr);
    }
}

