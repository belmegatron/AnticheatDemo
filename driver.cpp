#include "driver.h"

#pragma warning (disable : 4244)
#pragma warning (disable : 4996)

GlobalState g_state;

#define POOL_TAG 'ca'

#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE  0x0020

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

PSYSTEM_PROCESSES ProcessList()
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

PSYSTEM_HANDLE_INFORMATION_EX  HandleList()
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

PSYSTEM_PROCESSES FindProcess(PSYSTEM_PROCESSES process_list, unsigned long pid)
{
    PSYSTEM_PROCESSES entry = process_list;

    do
    {
        if (entry->ProcessId == pid)
        {
            return entry;
        }

        entry = (PSYSTEM_PROCESSES)((char*)entry + entry->NextEntryDelta);

    } while (entry->NextEntryDelta);

    return nullptr;
}

void MemoryScanRoutine(PVOID context)
{
    UNREFERENCED_PARAMETER(context);

    // TODO: DriverUnload needs to signal this thread to terminate.

    while (true)
    {
        NTSTATUS status = KeWaitForSingleObject(&g_state.timer, Executive, KernelMode, true, nullptr);

        if (NT_SUCCESS(status))
        {
            auto process_list = ProcessList();

            if (!process_list)
            {
                KdPrint(("Failed to perform initial process list when executing memory scan"));
                continue;
            }

            KdPrint(("Executing memory scan routine."));

            PSYSTEM_HANDLE_INFORMATION_EX handle_information = HandleList();

            if (handle_information)
            {
                for (unsigned int i = 0; i < handle_information->NumberOfHandles; ++i)
                {
                    auto handle = handle_information->Handles[i];

                    if (g_state.process == handle.Object)
                    {
                        auto process = FindProcess(process_list, handle.UniqueProcessId);
                        if (process)
                        {
                            KdPrint(("Process: %wZ, Access: %x", process->ProcessName, handle.GrantedAccess));
                        }
                    }
                }

                ExFreePoolWithTag(handle_information, POOL_TAG);
            }
            ExFreePoolWithTag(process_list, POOL_TAG);
        }
    }
}

void SetupMemoryScanRoutine()
{
    KeInitializeTimerEx(&g_state.timer, SynchronizationTimer);
    LARGE_INTEGER interval{ 10000 , 0 };
    KeSetTimerEx(&g_state.timer, interval, 30000, nullptr);
    PsCreateSystemThread(&g_state.thread, GENERIC_ALL, nullptr, nullptr, nullptr, MemoryScanRoutine, nullptr);
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
        bool allow_handle_access = false;

        PSYSTEM_PROCESSES process_list = ProcessList();

        if (process_list)
        {
            PSYSTEM_PROCESSES entry = process_list;

            do
            {
                if (entry->ProcessName.Length)
                {
                    // TODO: Perform some kind of integrity check here.

                    if (wcsstr(entry->ProcessName.Buffer, L"csrss.exe"))
                    {
                        if (ULongToHandle(entry->ProcessId) == requesting_pid)
                        {
                            allow_handle_access = true;
                            break;
                        }
                    }

                    // TODO: Perform some kind of integrity check here.

                    if (wcsstr(entry->ProcessName.Buffer, L"explorer.exe"))
                    {
                        if (ULongToHandle(entry->ProcessId) == requesting_pid)
                        {
                            allow_handle_access = true;
                            break;
                        }
                    }
                }
                entry = (PSYSTEM_PROCESSES)((char*)entry + entry->NextEntryDelta);
            } while (entry->NextEntryDelta);

            ExFreePoolWithTag(process_list, POOL_TAG);
        }

        if (!allow_handle_access)
        {
            unsigned long mask = PROCESS_VM_READ | PROCESS_VM_WRITE;

            if (info->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                info->Parameters->CreateHandleInformation.DesiredAccess &= ~mask;
            }
            else if (info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~mask;
            }
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
    KeCancelTimer(&g_state.timer);

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

                    SetupMemoryScanRoutine();
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
    thread = nullptr;
}
