#include "nt_internals.h"
#include "globals.h"
#include "process_notifications.h"
#include "memory_scan.h"

GlobalState g_state;

constexpr UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\AntiCheatDemo");
constexpr UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\AntiCheatDemo");

void DriverUnload(PDRIVER_OBJECT p_driver_object);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT p_device_object, PIRP irp);
void DriverEntryCleanup(bool symlink_created, PDEVICE_OBJECT p_device_object);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT p_driver_object, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);

    KdPrint(("DriverEntry called"));

    PDEVICE_OBJECT p_device_object = nullptr;
    bool symlink_created = false;

    // Initialize our global state.
    g_state.Init();

    NTSTATUS status = IoCreateDevice(p_driver_object, 0, const_cast<PUNICODE_STRING>(&device_name), FILE_DEVICE_UNKNOWN, 0, true, &p_device_object);
    if (NT_SUCCESS(status))
    {
        status = IoCreateSymbolicLink(const_cast<PUNICODE_STRING>(&symlink), const_cast<PUNICODE_STRING>(&device_name));
        if (NT_SUCCESS(status))
        {
            symlink_created = true;

            status = Notifications::Setup();
            if (NT_SUCCESS(status))
            {
                p_driver_object->DriverUnload = DriverUnload;
                p_driver_object->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
                p_driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;

                // TODO: This should report errors.
                Scanner::Setup();
            }
        }
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

    IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&symlink));
    IoDeleteDevice(p_driver_object->DeviceObject);

    KdPrint(("Unloaded AntiCheat Driver"));
}

void DriverEntryCleanup(bool symlink_created, PDEVICE_OBJECT p_device_object)
{
    if (symlink_created)
    {
        IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&symlink));
    }

    if (p_device_object)
    {
        IoDeleteDevice(p_device_object);
    }
}

