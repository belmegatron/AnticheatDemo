#include "nt_internals.h"
#include "anticheat.h"
#include "process_notifications.h"
#include "memory_scan.h"

AntiCheat* gp_anticheat = nullptr;

constexpr UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\AntiCheatDemo");
constexpr UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\AntiCheatDemo");

void DriverUnload(PDRIVER_OBJECT p_driver_object);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT p_device_object, PIRP p_irp);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT p_driver_object, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);

    p_driver_object->DriverUnload = DriverUnload;
    p_driver_object->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    p_driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;

    PDEVICE_OBJECT p_device_object = nullptr;

    NTSTATUS status = IoCreateDevice(p_driver_object, 0, const_cast<PUNICODE_STRING>(&device_name), FILE_DEVICE_UNKNOWN, 0, true, &p_device_object);
    if (NT_SUCCESS(status))
    {
        status = IoCreateSymbolicLink(const_cast<PUNICODE_STRING>(&symlink), const_cast<PUNICODE_STRING>(&device_name));
        if (NT_SUCCESS(status))
        {
            gp_anticheat = new(AntiCheat);
            KdPrint(("Loaded AntiCheat Driver."));
        }
        else
        {
            IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&symlink));
        }
    }

    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(p_driver_object->DeviceObject);
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
    if (gp_anticheat)
    {
        delete(gp_anticheat);
        gp_anticheat = nullptr;
    }
    
    IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&symlink));
    IoDeleteDevice(p_driver_object->DeviceObject);

    KdPrint(("Unloaded AntiCheat Driver"));
}
