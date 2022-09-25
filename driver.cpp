#include "nt_internals.h"
#include "globals.h"
#include "process_notifications.h"
#include "memory_scan.h"

GlobalState g_state;

void DriverUnload(PDRIVER_OBJECT p_driver_object);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT p_device_object, PIRP irp);
void DriverEntryCleanup(bool symlink_created, PDEVICE_OBJECT p_device_object);

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
                status = Notifications::Setup();
                if (NT_SUCCESS(status))
                {
                    p_driver_object->DriverUnload = DriverUnload;
                    p_driver_object->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
                    p_driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;

                    Scanner::Setup();
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

    KdPrint(("Unloaded AntiCheat Driver"));
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

