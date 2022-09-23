#include <ntddk.h>

HANDLE g_pid = 0;


void OnProcessNotify(PEPROCESS process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO create_info)
{
    UNREFERENCED_PARAMETER(process);

    // TODO: Can we be cheeky and deny multiple processes being spawned from the same executable? Would mean that we don't need to keep an array of process handles.

    if (create_info)
    {
        if (wcsstr(create_info->CommandLine->Buffer, L"notepad") != nullptr)
        {
            g_pid = process_id;

            KdPrint(("notepad.exe has started."));
        }
    }
    else
    {
        if (process_id == g_pid)
        {
            KdPrint(("notepad.exe has stopped"));
            g_pid = 0;
        }
    }
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

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT p_driver_object, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);

    KdPrint(("DriverEntry called"));

    PDEVICE_OBJECT p_device_object = nullptr;
    bool symlink_created = false;

    UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\AntiCheatDemo");

    NTSTATUS status = IoCreateDevice(p_driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, true, &p_device_object);
    if (NT_SUCCESS(status))
    {
        UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\AntiCheatDemo");
        status = IoCreateSymbolicLink(&symlink, &device_name);
        if (NT_SUCCESS(status))
        {
            symlink_created = true;

            //p_device_object->Flags |= DO_DIRECT_IO;

            status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, false);
            
            if (NT_SUCCESS(status))
            {
                p_driver_object->DriverUnload = DriverUnload;
                p_driver_object->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
                p_driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
                
                // TODO: Add read function here!
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