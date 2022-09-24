#include "driver.h"

#pragma warning (disable : 4244)
#pragma warning (disable : 4996)

GlobalState g_state;

#define POOL_TAG 'derp'

void OnProcessNotify(PEPROCESS process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO create_info)
{
    if (create_info)
    {
        if (wcsstr(create_info->CommandLine->Buffer, L"notepad") != nullptr)
        {
            if (g_state.pid != 0)
            {
                create_info->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }

            g_state.pid = process_id;
            g_state.process = process;

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

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID, POB_PRE_OPERATION_INFORMATION info)
{
    if (info->KernelHandle)
    {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS process = reinterpret_cast<PEPROCESS>(info->Object);
    HANDLE pid = PsGetProcessId(process);

    if (pid != g_state.pid)
    {
        return OB_PREOP_SUCCESS;
    }

    HANDLE requesting_pid = PsGetCurrentProcessId();

    if (requesting_pid != g_state.pid)
    {
        ULONG bufferSize = 0;

        bool allow_handle_access = false;

        NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            void* buf = ExAllocatePoolWithTag(PagedPool, bufferSize, POOL_TAG);
            if (buf)
            {
                status = ZwQuerySystemInformation(SystemProcessInformation, buf, bufferSize, &bufferSize);
                if (NT_SUCCESS(status))
                {
                    PSYSTEM_PROCESSES processEntry = reinterpret_cast<PSYSTEM_PROCESSES>(buf);

                    do 
                    {
                        if (processEntry->ProcessName.Length) 
                        {
                            // TODO: Perform some kind of integrity check here.

                            if (wcsstr(processEntry->ProcessName.Buffer, L"csrss.exe"))
                            {
                                if (ULongToHandle(processEntry->ProcessId) == requesting_pid)
                                {
                                    allow_handle_access = true;
                                    break;
                                }
                            }

                            // TODO: Perform some kind of integrity check here.

                            if (wcsstr(processEntry->ProcessName.Buffer, L"explorer.exe"))
                            {
                                if (ULongToHandle(processEntry->ProcessId) == requesting_pid)
                                {
                                    allow_handle_access = true;
                                    break;
                                }
                            }
                        }
                        processEntry = (PSYSTEM_PROCESSES)((char*)processEntry + processEntry->NextEntryDelta);
                    } while (processEntry->NextEntryDelta);
                }

                ExFreePoolWithTag(buf, POOL_TAG);
            }
        }

        if (!allow_handle_access)
        {
            info->Parameters->CreateHandleInformation.DesiredAccess = 0;
            info->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
            KdPrint(("Denied access to notepad.exe process handle"));
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT p_device_object, PIRP irp)
{
    UNREFERENCED_PARAMETER(p_device_object);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, 0);

    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT p_driver_object)
{
    ObUnRegisterCallbacks(g_state.reg_handle);

    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, true);

    UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\AntiCheatDemo");

    IoDeleteSymbolicLink(&symlink);
    IoDeleteDevice(p_driver_object->DeviceObject);

    KdPrint(("Unloaded Driver"));
}

void DriverEntryCleanup(bool symlink_created, PDEVICE_OBJECT p_device_object)
{
    if (symlink_created)
    {
        UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\AntiCheatDemo");
        IoDeleteSymbolicLink(&symlink);
    }

    if (p_device_object)
    {
        IoDeleteDevice(p_device_object);
    }
}

NTSTATUS SetupHandleCallback()
{
    OB_OPERATION_REGISTRATION operations[] = {
        {
            PsProcessType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            OnPreOpenProcess, nullptr
        }
    };

    OB_CALLBACK_REGISTRATION reg = {
        OB_FLT_REGISTRATION_VERSION,
        1,
        RTL_CONSTANT_STRING(L"1337.1337"),
        nullptr,
        operations
    };

    return ObRegisterCallbacks(&reg, &g_state.reg_handle);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT p_driver_object, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);

    KdPrint(("DriverEntry called"));

    PDEVICE_OBJECT p_device_object = nullptr;
    bool symlink_created = false;
    g_state.Init();

    UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\AntiCheatDemo");

    NTSTATUS status = IoCreateDevice(p_driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, true, &p_device_object);
    if (NT_SUCCESS(status))
    {
        UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\AntiCheatDemo");
        status = IoCreateSymbolicLink(&symlink, &device_name);
        if (NT_SUCCESS(status))
        {
            symlink_created = true;

            status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, false);
            
            if (NT_SUCCESS(status))
            {
                status = SetupHandleCallback();
                if (NT_SUCCESS(status))
                {
                    p_driver_object->DriverUnload = DriverUnload;
                    p_driver_object->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
                    p_driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;

                    // TODO: Add read function here!
                }
            }
            else
            {
                KdPrint(("Failed to call PsSetCreateProcessNotifyRoutineEx"));
            }
        }
        else
        {
            KdPrint(("Failed to create symbolic link"));
        }
    }
    else
    {
        KdPrint(("Failed to create device"));
    }

    if (!NT_SUCCESS(status))
    {
        DriverEntryCleanup(symlink_created, p_device_object);
    }

    return status;
}

void GlobalState::Init()
{
    pid = 0;
    process = nullptr;
    reg_handle = nullptr;
}
