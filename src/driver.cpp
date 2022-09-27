#include "nt_internals.h"
#include "globals.h"
#include "process_notifications.h"
#include "memory_scan.h"

GlobalState g_state;

constexpr UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\AntiCheatDemo");
constexpr UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\AntiCheatDemo");

void DriverUnload(PDRIVER_OBJECT p_driver_object);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT p_device_object, PIRP p_irp);
void DriverEntryCleanup(PDEVICE_OBJECT p_device_object);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT p_driver_object, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);

    p_driver_object->DriverUnload = DriverUnload;
    p_driver_object->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    p_driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;

    PDEVICE_OBJECT p_device_object = nullptr;
    bool setup_success = false;

    // Initialize our global state.
    g_state.Init();

    NTSTATUS status = IoCreateDevice(p_driver_object, 0, const_cast<PUNICODE_STRING>(&device_name), FILE_DEVICE_UNKNOWN, 0, true, &p_device_object);
    if (NT_SUCCESS(status))
    {
        status = IoCreateSymbolicLink(const_cast<PUNICODE_STRING>(&symlink), const_cast<PUNICODE_STRING>(&device_name));
        if (NT_SUCCESS(status))
        {
            g_state.symlink_created = true;

            setup_success = ProcessNotifications::Setup();
            if (setup_success)
            {
                KdPrint(("Loaded AntiCheat Driver."));
            }
        }
    }

    if (!NT_SUCCESS(status) || !setup_success)
    {
        DriverEntryCleanup(p_device_object);
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
    DriverEntryCleanup(p_driver_object->DeviceObject);

    KdPrint(("Unloaded AntiCheat Driver"));
}

void DriverEntryCleanup(PDEVICE_OBJECT p_device_object)
{
    if (g_state.callback_reg_handle)
    {
        ObUnRegisterCallbacks(g_state.callback_reg_handle);
    }

    if (g_state.process_notification_set)
    {
        PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, true);
    }

    if (g_state.symlink_created)
    {
        IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&symlink));
    }

    if (p_device_object)
    {
        IoDeleteDevice(p_device_object);
    }
}

