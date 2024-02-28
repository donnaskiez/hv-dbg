#include "driver.h"

#include <intrin.h>
#include "vmx.h"
#include "common.h"
#include "ept.h"
#include <intrin.h>
#include "arch.h"

UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\hv");
UNICODE_STRING device_link = RTL_CONSTANT_STRING(L"\\??\\hv-link");

NTSTATUS
DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
        UNREFERENCED_PARAMETER(DeviceObject);
        BroadcastVmxTermination();
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
}

NTSTATUS
DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
        UNREFERENCED_PARAMETER(DeviceObject);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
}

/*
 * TODO: need to refactor this to safely return from vmx operation and also fix da leaks.
 */
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
        UNREFERENCED_PARAMETER(RegistryPath);

        NTSTATUS status = STATUS_SUCCESS;

        status = AllocateDriverState();

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("AllocateDriverState failed with status %x", status);
                return status;
        }

        status = InitialisePowerCallback();

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("InitialisePowerCallback failed with status %x", status);
                FreeGlobalDriverState();
                return status;
        }

        status = SetupVmxOperation();

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("SetupVmxOperation failed with status %x", status);
                FreeGlobalDriverState();
                UnregisterPowerCallback();
                return status;
        }

        status = IoCreateDevice(DriverObject,
                                0,
                                &device_name,
                                FILE_DEVICE_UNKNOWN,
                                FILE_DEVICE_SECURE_OPEN,
                                FALSE,
                                &DriverObject->DeviceObject);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("IoCreateDevice failed with status %x", status);
                FreeVmxState();
                FreeGlobalDriverState();
                UnregisterPowerCallback();
        }

        status = IoCreateSymbolicLink(&device_link, &device_name);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("IoCreateSymbolicLink failed with status %x", status);
                FreeVmxState();
                FreeGlobalDriverState();
                UnregisterPowerCallback();
                IoDeleteDevice(&DriverObject->DeviceObject);
                return status;
        }

        DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]  = DeviceClose;

        DEBUG_LOG("Driver entry complete");

        return status;
}