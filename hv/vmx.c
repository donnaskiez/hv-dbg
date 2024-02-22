#include "vmx.h"

#include "common.h"
#include "ia32.h"
#include "arch.h"
#include "vmcs.h"
#include "ept.h"

#include <intrin.h>

PDRIVER_STATE          driver_state = NULL;
PVIRTUAL_MACHINE_STATE vmm_state    = NULL;

/*
 * Assuming the thread calling this is binded to a particular core
 */
STATIC
NTSTATUS
EnableVmxOperationOnCore()
{
        CR4 cr4       = {0};
        cr4.AsUInt    = __readcr4();
        cr4.VmxEnable = TRUE;
        __writecr4(cr4.AsUInt);
        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
IsVmxSupported()
{
        CPUID_EAX_01 cpuid_features = {0};
        __cpuid((INT*)&cpuid_features, CPUID_VERSION_INFORMATION);

        if (!cpuid_features.CpuidFeatureInformationEcx.VirtualMachineExtensions)
                return STATUS_NOT_SUPPORTED;

        IA32_FEATURE_CONTROL_REGISTER Control = {0};
        Control.AsUInt                        = __readmsr(IA32_FEATURE_CONTROL);

        if (Control.LockBit == 0) {
                Control.LockBit             = TRUE;
                Control.EnableVmxOutsideSmx = TRUE;
                __writemsr(IA32_FEATURE_CONTROL, Control.AsUInt);
        }
        else if (Control.EnableVmxOutsideSmx == FALSE) {
                DEBUG_LOG("VMX not enabled in the bios");
                return STATUS_NOT_SUPPORTED;
        }

        return STATUS_SUCCESS;
}

/*
 * VMCS region comprises up to 4096 bytes, with the following format:
 *
 * offset 0: VMCS revision identifier
 * offset 4: VMX abort indicator
 * offset 8: VMCS data
 *
 * Source: 3c 24.2
 */
STATIC
NTSTATUS
AllocateVmcsRegion(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        INT                     status              = 0;
        PVOID                   virtual_allocation  = NULL;
        UINT64                  physical_allocation = NULL;
        PHYSICAL_ADDRESS        physical_max        = {0};
        PHYSICAL_ADDRESS        physical_address    = {0};
        IA32_VMX_BASIC_REGISTER ia32_basic_msr      = {0};

        physical_max.QuadPart = MAXULONG64;

        virtual_allocation = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);

        if (!virtual_allocation) {
                DEBUG_ERROR("Failed to allocate vmcs region");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlSecureZeroMemory(virtual_allocation, PAGE_SIZE);

        physical_allocation = MmGetPhysicalAddress(virtual_allocation).QuadPart;

        if (!physical_allocation) {
                DEBUG_LOG("Faield to get vmcs pa address");
                MmFreeContiguousMemory(virtual_allocation);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        ia32_basic_msr.AsUInt = __readmsr(IA32_VMX_BASIC);

        *(UINT64*)virtual_allocation = ia32_basic_msr.VmcsRevisionId;

        VmmState->vmcs_region_pa = physical_allocation;
        VmmState->vmcs_region_va = virtual_allocation;

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AllocateVmxonRegion(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        INT                     status              = 0;
        PVOID                   virtual_allocation  = NULL;
        UINT64                  physical_allocation = NULL;
        PHYSICAL_ADDRESS        physical_max        = {0};
        PHYSICAL_ADDRESS        physical_address    = {0};
        IA32_VMX_BASIC_REGISTER ia32_basic_msr      = {0};

        physical_max.QuadPart = MAXULONG64;

        virtual_allocation = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);

        if (!virtual_allocation) {
                DEBUG_ERROR("MmAllocateContiguousMemory failed");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlSecureZeroMemory(virtual_allocation, PAGE_SIZE);

        physical_allocation = MmGetPhysicalAddress(virtual_allocation).QuadPart;

        if (!physical_allocation) {
                MmFreeContiguousMemory(virtual_allocation);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        ia32_basic_msr.AsUInt = __readmsr(IA32_VMX_BASIC);

        *(UINT64*)virtual_allocation = ia32_basic_msr.VmcsRevisionId;

        status = __vmx_on(&physical_allocation);

        /*
         * 0 : The operation succeeded
         * 1 : The operation failed with extended status available in the
         * VM-instruction error field of the current VMCS. 2 : The operation
         * failed without status available.
         */
        if (status) {
                DEBUG_LOG("VmxOn failed with status: %i", status);
                MmFreeContiguousMemory(virtual_allocation);
                return STATUS_FAIL_CHECK;
        }

        VmmState->vmxon_region_pa = physical_allocation;
        VmmState->vmxon_region_va = virtual_allocation;

        return STATUS_SUCCESS;
}

NTSTATUS
AllocateDriverState()
{
        driver_state = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DRIVER_STATE), POOLTAG);

        if (!driver_state)
                return STATUS_MEMORY_NOT_ALLOCATED;

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
InitiateVmmState(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        VmmState->cache.cpuid.active  = FALSE;
        VmmState->exit_state.exit_vmx = FALSE;
        VmmState->state               = VMX_VCPU_STATE_OFF;
        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AllocateVmmStack(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        VmmState->vmm_stack_va = ExAllocatePool2(POOL_FLAG_NON_PAGED, VMX_HOST_STACK_SIZE, POOLTAG);

        if (!VmmState->vmm_stack_va) {
                DEBUG_LOG("Error in allocating VMM Stack.");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AllocateMsrBitmap(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        VmmState->msr_bitmap_va = MmAllocateNonCachedMemory(PAGE_SIZE);

        if (!VmmState->msr_bitmap_va) {
                DEBUG_LOG("Error in allocating MSRBitMap.");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlSecureZeroMemory(VmmState->msr_bitmap_va, PAGE_SIZE);

        VmmState->msr_bitmap_pa = MmGetPhysicalAddress(VmmState->msr_bitmap_va).QuadPart;

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AllocateVmmStateStructure()
{
        vmm_state = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                    sizeof(VIRTUAL_MACHINE_STATE) * KeQueryActiveProcessorCount(0),
                                    POOLTAG);
        if (!vmm_state) {
                DEBUG_LOG("Failed to allocate vmm state");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        return STATUS_SUCCESS;
}

VOID
InitialiseVmxOperation(_In_ PKDPC*    Dpc,
                       _In_opt_ PVOID DeferredContext,
                       _In_opt_ PVOID SystemArgument1,
                       _In_opt_ PVOID SystemArgument2)
{
        NTSTATUS               status  = STATUS_ABANDONED;
        PVIRTUAL_MACHINE_STATE vcpu    = &vmm_state[KeGetCurrentProcessorNumber()];
        PDPC_CALL_CONTEXT      context = (PDPC_CALL_CONTEXT)DeferredContext;

        DEBUG_LOG("Core: %lx - Initiating VMX Operation state.", KeGetCurrentProcessorNumber());

        if (!ARGUMENT_PRESENT(DeferredContext)) {
                KeSignalCallDpcSynchronize(SystemArgument2);
                KeSignalCallDpcDone(SystemArgument1);
                return;
        }

        status = EnableVmxOperationOnCore();

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("EnableVmxOperationOnCore failed with status %x", status);
                goto end;
        }

        status = AllocateVmxonRegion(vcpu);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("AllocateVmxonRegion failed with status %x", status);
                goto end;
        }

        status = AllocateVmcsRegion(vcpu);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("AllocateVmcsRegion failed with status %x", status);
                goto end;
        }

        status = AllocateVmmStack(vcpu);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("AllocateVmmStack failed with status %x", status);
                goto end;
        }

        status = AllocateMsrBitmap(vcpu);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("AllocateMsrBitmap failed with status %x", status);
                goto end;
        }

        status = InitiateVmmState(vcpu);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("InitiateVmmState failed with status %x", status);
                goto end;
        }
end:
        context->status[KeGetCurrentProcessorNumber()] = status;
        KeSignalCallDpcSynchronize(SystemArgument2);
        KeSignalCallDpcDone(SystemArgument1);
}

VOID
VirtualizeCore(_In_ PDPC_CALL_CONTEXT Context, _In_ PVOID StackPointer)
{
        NTSTATUS               status = STATUS_UNSUCCESSFUL;
        PVIRTUAL_MACHINE_STATE vcpu   = &vmm_state[KeGetCurrentProcessorNumber()];

        status = SetupVmcs(vcpu, StackPointer);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("SetupVmcs failed with status %x", status);
                return;
        }

        __vmx_vmlaunch();

        /* only if vmlaunch fails will we end up here */
        DEBUG_ERROR("vmlaunch failed with status %llx", VmxVmRead(VMCS_VM_INSTRUCTION_ERROR));

        vcpu->state = VMX_VCPU_STATE_TERMINATED;
}

NTSTATUS
ValidateVmxLaunch()
{
        for (UINT32 core = 0; core < KeQueryActiveProcessorCount(NULL); core++) {
                PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[core];

                if (vcpu->state != VMX_VCPU_STATE_RUNNING) {
                        DEBUG_LOG("Core: %lx failed to enter VMX operation.", core);
                        return STATUS_UNSUCCESSFUL;
                }
        }

        DEBUG_LOG("All cores succesfully entered VMX operation.");
        return STATUS_SUCCESS;
}

NTSTATUS
BeginVmxOperation(_In_ PDPC_CALL_CONTEXT Context)
{
        NTSTATUS status = IsVmxSupported();

        if (!NT_SUCCESS(status)) {
                DEBUG_LOG("VMX operation is not supported on this machine");
                return status;
        }

        /* What happens if something fails? TODO: think. */
        KeIpiGenericCall(SaveStateAndVirtualizeCore, Context);

        /* lets make sure we entered VMX operation on ALL cores. If a core failed to enter, the
         * vcpu->state == VMX_VCPU_STATE_TERMINATED.*/
        return ValidateVmxLaunch();
}

NTSTATUS
VmxVmCall(_In_ UINT64     VmCallId,
          _In_opt_ UINT64 OptionalParameter1,
          _In_opt_ UINT64 OptionalParameter2,
          _In_opt_ UINT64 OptionalParameter3)
{
        NTSTATUS status =
            __vmx_vmcall(VmCallId, OptionalParameter1, OptionalParameter2, OptionalParameter3);

        if (!NT_SUCCESS(status))
                DEBUG_ERROR("VmCall failed wtih status %x", status);

        return status;
}

STATIC
VOID
FreeCoreVmxState(_In_ UINT32 Core)
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[Core];

        if (vcpu->vmxon_region_va)
                MmFreeContiguousMemory(vcpu->vmxon_region_va);
        if (vcpu->vmcs_region_va)
                MmFreeContiguousMemory(vcpu->vmcs_region_va);
        if (vcpu->msr_bitmap_va)
                MmFreeNonCachedMemory(vcpu->msr_bitmap_va, PAGE_SIZE);
        if (vcpu->vmm_stack_va)
                ExFreePoolWithTag(vcpu->vmm_stack_va, POOLTAG);
}

STATIC
VOID
FreeGlobalVmmState()
{
        if (vmm_state) {
                ExFreePoolWithTag(vmm_state, POOLTAG);
                vmm_state = NULL;
        }
}

STATIC
VOID
TerminateVmxDpcRoutine(_In_ PKDPC*    Dpc,
                       _In_opt_ PVOID DeferredContext,
                       _In_opt_ PVOID SystemArgument1,
                       _In_opt_ PVOID SystemArgument2)
{
        UNREFERENCED_PARAMETER(Dpc);
        UNREFERENCED_PARAMETER(DeferredContext);

        DEBUG_LOG("Core: %lx - Terminating VMX Operation.", KeGetCurrentProcessorNumber());

        if (!NT_SUCCESS(VmxVmCall(VMX_HYPERCALL_TERMINATE_VMX, 0, 0, 0))) {
                return STATUS_UNSUCCESSFUL;
        }

        /*
         * At this point, we have exited VMX operation and we can safely free our per core
         * allocations.
         */
        FreeCoreVmxState(KeGetCurrentProcessorNumber());

        KeSignalCallDpcSynchronize(SystemArgument2);
        KeSignalCallDpcDone(SystemArgument1);
}

NTSTATUS
BroadcastVmxTermination()
{
        /* Our routine blocks until all DPCs have executed. */
        KeGenericCallDpc(TerminateVmxDpcRoutine, NULL);

        /*
         * Now that each per core stuctures have been freed, we are safe to revert the affinity of
         * the current thread and free the global vmm state array.
         */
        FreeGlobalVmmState();
        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
ValidateSuccessVmxInitiation(PDPC_CALL_CONTEXT Context)
{
        for (UINT32 index = 0; index < Context->status_count; index++) {
                if (Context->status[index] != STATUS_SUCCESS)
                        return Context->status[index];
        }

        /* zero the memory since we use these status codes for our IPI. */
        RtlZeroMemory(Context->status, sizeof(NTSTATUS) * Context->status_count);
        return STATUS_SUCCESS;
}

NTSTATUS
SetupVmxOperation()
{
        NTSTATUS          status     = STATUS_UNSUCCESSFUL;
        PDPC_CALL_CONTEXT context    = NULL;
        EPT_POINTER*      pept       = NULL;
        UINT32            core_count = 0;

        core_count = KeQueryActiveProcessorCount(NULL);

        context =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, core_count * sizeof(DPC_CALL_CONTEXT), POOLTAG);

        if (!context)
                goto end;

        context->status_count = core_count;
        context->status =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, core_count * sizeof(NTSTATUS), POOLTAG);

        if (!context->status)
                goto end;

        status = InitializeEptp(&pept);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("Failed to initialise EPT");
                goto end;
        }

        for (INT core = 0; core < KeQueryActiveProcessorCount(NULL); core++) {
                context[core].eptp        = pept;
                context[core].guest_stack = NULL;
                context->status[core]     = STATUS_UNSUCCESSFUL;
        }

        status = AllocateVmmStateStructure();

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("AllocateVmmStateStructure failed with status %x", status);
                return status;
        }

        /*
         * Here we use both DPCs and IPIs to initialise and then begin VMX operation. IPIs run at
         * IRQL = IPI_LEVEL which means many of the routines used in InitialiseVmxOperation will
         * fail. To solve this, we use DPCs to initialise our per-core VMX state. We then
         * synchronize each DPC to ensure each core has executed their respective DPC before
         * returning. Once we've initiated the per core state, we can use an IPI to execute vmxon
         * and begin VMX operation on each core.
         */
        KeGenericCallDpc(InitialiseVmxOperation, context);

        /* we will synchronise our DPCs so at this point all will have run */
        status = ValidateSuccessVmxInitiation(context);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("InitialiseVmxOperation failed with status %x", status);
                goto end;
        }

        status = BeginVmxOperation(context);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("BeginVmxOperation failed with status %x", status);

                /* We could have potentially entered VMX operation on some cores, so lets terminate
                 * on any cores that did enter VMX operation before we clear the global vcpu
                 * state.*/
                BroadcastVmxTermination();
                goto end;
        }

end:
        if (context && context->status)
                ExFreePoolWithTag(context->status, POOLTAG);
        if (context)
                ExFreePoolWithTag(context, POOLTAG);

        return status;
}

VOID
TerminatePowerCallback()
{
        if (driver_state->power_callback)
                ExUnregisterCallback(driver_state->power_callback);

        if (driver_state->power_callback_object)
                ObDereferenceObject(driver_state->power_callback_object);
}

/*
 * Argument1 consists of a set of constants cast to a void*. In our case we are only interested in
 * the PO_CB_SYSTEM_STATE_LOCK argument. This argument denotes a change in the system power policy
 * has changed.
 *
 * When Argument1 is equal to PO_CB_SYSTEM_STATE_LOCK, Argument2 is FALSE if the computer is about
 * to exit system power state s0, and is TRUE if the computer has just reentered s0.
 */
STATIC
VOID
PowerCallbackRoutine(_In_ PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
        UNREFERENCED_PARAMETER(CallbackContext);

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        HANDLE   handle = NULL;

        if (Argument1 != (PVOID)PO_CB_SYSTEM_STATE_LOCK)
                return;

        if (Argument2) {
                DEBUG_LOG("Resuming VMX operation after sleep..");

                status = SetupVmxOperation();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("SetupVmxOperation failed with status %x", status);
        }
        else {
                DEBUG_LOG("Exiting VMX operation for sleep...");

                status = BroadcastVmxTermination();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("BroadcastVmxTermination failed with status %x", status);
        }
}

NTSTATUS
InitialisePowerCallback()
{
        NTSTATUS          status = STATUS_ABANDONED;
        UNICODE_STRING    name   = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
        OBJECT_ATTRIBUTES object_attributes =
            RTL_CONSTANT_OBJECT_ATTRIBUTES(&name, OBJ_CASE_INSENSITIVE);

        status =
            ExCreateCallback(&driver_state->power_callback_object, &object_attributes, FALSE, TRUE);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("ExCreateCallback failed with status %x", status);
                return status;
        }

        driver_state->power_callback =
            ExRegisterCallback(driver_state->power_callback_object, PowerCallbackRoutine, NULL);

        if (!driver_state->power_callback) {
                DEBUG_ERROR("ExRegisterCallback failed");
                ObDereferenceObject(driver_state->power_callback_object);
                driver_state->power_callback_object = NULL;
                return STATUS_UNSUCCESSFUL;
        }

        return status;
}