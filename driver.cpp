#include "driver.h"

#pragma warning (disable : 4244)
#pragma warning (disable : 4996)

GlobalState g_state;

#define POOL_TAG 'ca'

#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE  0x0020

#define MEM_IMAGE 0x1000000
#define FREE 0x0000000

#define NONE 0x00

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

PSYSTEM_PROCESSES FindProcess(PSYSTEM_PROCESSES process_list, ULONG_PTR pid)
{
    PSYSTEM_PROCESSES entry = process_list;

    do
    {
        if (entry->ProcessId == pid)
        {
            return entry;
        }

        entry = (PSYSTEM_PROCESSES)((char*)entry + entry->NextEntryDelta);

    } while (entry->ProcessId);

    return nullptr;
}

void PrintMemoryAllocation(PMEMORY_BASIC_INFORMATION p_info)
{
    PWCHAR protect = nullptr;
    PWCHAR type = nullptr;

    switch (p_info->Protect)
    {
    case PAGE_EXECUTE:
        protect = L"PAGE_EXECUTE";
        break;
    case PAGE_EXECUTE_READ:
        protect = L"PAGE_EXECUTE_READ";
        break;
    case PAGE_EXECUTE_READWRITE:
        protect = L"PAGE_EXECUTE_READWRITE";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        protect = L"PAGE_EXECUTE_WRITECOPY";
        break;
    case PAGE_READONLY:
        protect = L"PAGE_READONLY";
        break;
    case PAGE_READWRITE:
    case PAGE_READWRITE | PAGE_GUARD:
        protect = L"PAGE_READWRITE";
        break;
    case PAGE_WRITECOPY:
        protect = L"PAGE_WRITECOPY";
        break;
    case PAGE_NOACCESS:
        protect = L"PAGE_NOACCESS";
        break;
    case NONE:
        protect = L"";
        break;
    default:
        KdPrint(("Protect: %x", p_info->Protect));
        protect = L"UNKNOWN";
    }

    switch (p_info->Type)
    {
    case MEM_PRIVATE:
        type = L"MEM_PRIVATE";
        break;
    case MEM_MAPPED:
        type = L"MEM_MAPPED";
        break;
    case MEM_IMAGE:
        type = L"MEM_IMAGE";
        break;
    case FREE:
        type = L"FREE";
        break;
    default:
        KdPrint(("Type: %x", p_info->Type));
        type = L"UNKNOWN";
    }

    KdPrint(("Base Address: 0x%Ix, Page Protection: %ws, Type: %ws", p_info->BaseAddress, protect, type));
}

void ScanMemoryRegions(PSYSTEM_PROCESSES process_list)
{
    if (g_state.pid == 0)
    {
        return;
    }

    KdPrint(("Starting memory region scan"));

    auto process = FindProcess(process_list, reinterpret_cast<ULONG_PTR>(g_state.pid));
    if (!process)
    {
        KdPrint(("Unable to find target process when performing memory region scan: %i", g_state.pid));
        return;
    }

    CLIENT_ID client_id = {};

    client_id.UniqueProcess = g_state.pid;
    client_id.UniqueThread = 0;

    HANDLE process_handle;
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    NTSTATUS status = ZwOpenProcess(&process_handle, GENERIC_ALL, &attributes, &client_id);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("Unable to open handle to notepad.exe: %x", status));
        return;
    }

    KdPrint(("Obtained handle to target process"));

    MEMORY_BASIC_INFORMATION info = {};
    ULONG_PTR base = 0;

    SIZE_T ReturnLength = 0;

    do
    {
        status = ZwQueryVirtualMemory(process_handle, (PVOID)base, MemoryBasicInformation, &info, sizeof(info), &ReturnLength);
        if (NT_SUCCESS(status))
        {
            PrintMemoryAllocation(&info);
        }

        base += info.RegionSize;
        RtlSecureZeroMemory(&info, sizeof(info));

    } while (NT_SUCCESS(status));

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
                            // TODO: Perform lookup on access values maybe?
                            KdPrint(("Process: %wZ, Access: %x", process->ProcessName, handle.GrantedAccess));
                        }
                    }
                }

                ExFreePoolWithTag(handle_information, POOL_TAG);
            }

            ScanMemoryRegions(process_list);

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
