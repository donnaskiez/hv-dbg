#include "dispatch.h"

#include "vmx.h"
#include "vmcs.h"
#include <intrin.h>
#include "arch.h"
#include "log.h"

#define CPUID_HYPERVISOR_INTERFACE_VENDOR 0x40000000
#define CPUID_HYPERVISOR_INTERFACE_LOL    0x40000001

#define VMX_CPUID_FUNCTION_LOW  0x40000000
#define VMX_CPUID_FUNCTION_HIGH 0x400000FF

#define CPUID_EAX 0
#define CPUID_EBX 1
#define CPUID_ECX 2
#define CPUID_EDX 3

#define VMX_BUGCHECK_INVALID_MTF_EXIT 0x0

#define DEBUG_DR0 0
#define DEBUG_DR1 1
#define DEBUG_DR2 2
#define DEBUG_DR3 3
#define DEBUG_DR6 6
#define DEBUG_DR7 7

FORCEINLINE
STATIC
VOID
IncrementGuestRip()
{
        VmxVmWrite(VMCS_GUEST_RIP,
                   VmxVmRead(VMCS_GUEST_RIP) +
                       VmxVmRead(VMCS_VMEXIT_INSTRUCTION_LENGTH));
}

FORCEINLINE
STATIC
UINT64
RetrieveValueInContextRegister(_In_ PGUEST_CONTEXT Context,
                               _In_ UINT32         Register)
{
        switch (Register) {
        case VMX_EXIT_QUALIFICATION_GENREG_RAX: return Context->rax;
        case VMX_EXIT_QUALIFICATION_GENREG_RCX: return Context->rcx;
        case VMX_EXIT_QUALIFICATION_GENREG_RDX: return Context->rdx;
        case VMX_EXIT_QUALIFICATION_GENREG_RBX: return Context->rbx;
        case VMX_EXIT_QUALIFICATION_GENREG_RSP: return Context->rsp;
        case VMX_EXIT_QUALIFICATION_GENREG_RBP: return Context->rbp;
        case VMX_EXIT_QUALIFICATION_GENREG_RSI: return Context->rsi;
        case VMX_EXIT_QUALIFICATION_GENREG_RDI: return Context->rdi;
        case VMX_EXIT_QUALIFICATION_GENREG_R8: return Context->r8;
        case VMX_EXIT_QUALIFICATION_GENREG_R9: return Context->r9;
        case VMX_EXIT_QUALIFICATION_GENREG_R10: return Context->r10;
        case VMX_EXIT_QUALIFICATION_GENREG_R11: return Context->r11;
        case VMX_EXIT_QUALIFICATION_GENREG_R12: return Context->r12;
        case VMX_EXIT_QUALIFICATION_GENREG_R13: return Context->r13;
        case VMX_EXIT_QUALIFICATION_GENREG_R14: return Context->r14;
        case VMX_EXIT_QUALIFICATION_GENREG_R15: return Context->r15;
        default: return 0;
        }
}

FORCEINLINE
STATIC
VOID
WriteValueInContextRegister(_In_ PGUEST_CONTEXT Context,
                            _In_ UINT32         Register,
                            _In_ UINT64         Value)
{
        switch (Register) {
        case VMX_EXIT_QUALIFICATION_GENREG_RAX: Context->rax = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RCX: Context->rcx = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RDX: Context->rdx = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RBX: Context->rbx = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RSP: Context->rsp = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RBP: Context->rbp = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RSI: Context->rsi = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RDI: Context->rdi = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R8: Context->r8 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R9: Context->r9 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R10: Context->r10 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R11: Context->r11 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R12: Context->r12 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R13: Context->r13 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R14: Context->r14 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R15: Context->r15 = Value; return;
        default: return;
        }
}

STATIC
UINT32
__vapic_offset_from_msr(_In_ UINT32 Register)
{
        return (Register & 0xFF) << 4;
}

/* Pass in the MSR, not the direct offset */
VOID
__write_vapic_32(_In_ UINT64 VirtualApicPage,
                 _In_ UINT32 Register,
                 _In_ UINT32 Value)
{
        UINT32 offset = __vapic_offset_from_msr(Register);
        *(UINT32*)(VirtualApicPage + offset) = Value;
}

VOID
__write_vapic_64(_In_ UINT64 VirtualApicPage,
                 _In_ UINT32 Register,
                 _In_ UINT64 Value)
{
        UINT32 offset = __vapic_offset_from_msr(Register);
        *(UINT64*)(VirtualApicPage + offset) = Value;
}

UINT32
__read_vapic_32(_In_ UINT64 VirtualApicPage, _In_ UINT32 Register)
{
        UINT32 offset = __vapic_offset_from_msr(Register);
        return *(UINT32*)(VirtualApicPage + offset);
}

UINT64
__read_vapic_64(_In_ UINT64 VirtualApicPage, _In_ UINT32 Register)
{
        UINT32 offset = __vapic_offset_from_msr(Register);
        return *(UINT64*)(VirtualApicPage + offset);
}

#define CPL_KERNEL 0
#define CPL_USER   3

/*
 * CS or SS segment selector contain the current protection level (CPL) for the
 * currently executing program.
 */
FORCEINLINE
STATIC
UINT16
ProbeGuestCurrentProtectionLevel()
{
        SEGMENT_SELECTOR cs = {.AsUInt =
                                   (UINT16)VmxVmRead(VMCS_GUEST_CS_SELECTOR)};
        return cs.RequestPrivilegeLevel;
}

FORCEINLINE
STATIC
VOID
InjectHardwareException(_In_ UINT8 Vector, _In_ UINT8 DeliverErrorCode)
{
        VMENTRY_INTERRUPT_INFORMATION gp = {0};
        gp.DeliverErrorCode              = DeliverErrorCode;
        gp.InterruptionType              = HardwareException;
        gp.Valid                         = TRUE;
        gp.Vector                        = Vector;
        VmxVmWrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, gp.AsUInt);
}

FORCEINLINE
STATIC
VOID
InjectGuestWithUdFault()
{
        InjectHardwareException(InvalidOpcode, FALSE);
}

FORCEINLINE
STATIC
VOID
InjectGuestWithGpFault()
{
        InjectHardwareException(GeneralProtection, FALSE);
}

FORCEINLINE
STATIC
VOID
InjectGuestWithDbFault()
{
        InjectHardwareException(Debug, FALSE);
}

FORCEINLINE
STATIC
VOID
HandleNotImplementedExit(_In_opt_ UINT64 BugCheckParameter1,
                         _In_opt_ UINT64 BugCheckParameter2,
                         _In_opt_ UINT64 BugCheckParameter3,
                         _In_opt_ UINT64 BugCheckParameter4)
{
        KeBugCheckEx(STATUS_NOT_IMPLEMENTED,
                     BugCheckParameter1,
                     BugCheckParameter2,
                     BugCheckParameter3,
                     BugCheckParameter4);
}

/*
 * Write the value of the designated general purpose register into the
 * designated control register
 */
FORCEINLINE
STATIC
VOID
DispatchExitReasonMovToCr(_In_ VMX_EXIT_QUALIFICATION_MOV_CR* Qualification,
                          _In_ PGUEST_CONTEXT                 Context)
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
        UINT64                 value = RetrieveValueInContextRegister(
            Context, Qualification->GeneralPurposeRegister);

        switch (Qualification->ControlRegister) {
        case VMX_EXIT_QUALIFICATION_REGISTER_CR0:;
                CR0 cr0 = {.AsUInt = value};
                CR3 cr3 = {.AsUInt = VmxVmRead(VMCS_GUEST_CR3)};

                /* Setting any of the CR4 reserved bits causes a #GP */
                if (cr0.Fields.Reserved1 || cr0.Fields.Reserved2 ||
                    cr0.Fields.Reserved3 || cr0.Fields.Reserved4) {
                        InjectGuestWithGpFault();
                        return;
                }

                /* Clearing the PG bit in 64 bit mode causes a #GP */
                if (!cr0.Fields.PagingEnable) {
                        InjectGuestWithGpFault();
                        return;
                }

                /* Setting the PagingEnable bit with ProtectionEnable
                 * bit not set raises #GP */
                if (cr0.Fields.PagingEnable && !cr0.Fields.ProtectionEnable) {
                        InjectGuestWithGpFault();
                        return;
                }

                /* Setting the CacheDisable flag while the
                 * NotWriteThrough flag is set raises #GP */
                if (!cr0.Fields.CacheDisable && cr0.Fields.NotWriteThrough) {
                        InjectGuestWithGpFault();
                        return;
                }

                VmxVmWrite(VMCS_GUEST_CR0, value);
                VmxVmWrite(VMCS_CTRL_CR0_READ_SHADOW, value);
                return;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR3:;
                VmxVmWrite(VMCS_GUEST_CR3, CLEAR_CR3_RESERVED_BIT(value));
                return;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR4:;
                CR4 cr4 = {.AsUInt = value};

                /* Setting reserved bits raises #GP */
                if (cr4.Reserved1 || cr4.Reserved2) {
                        InjectGuestWithGpFault();
                        return;
                }

                VmxVmWrite(VMCS_GUEST_CR4, value);
                VmxVmWrite(VMCS_CTRL_CR4_READ_SHADOW, value);
        case VMX_EXIT_QUALIFICATION_REGISTER_CR8: __writecr8(value);
#if APIC
                /* again, for now this must be done... */
                __write_vapic_32(
                    vcpu->virtual_apic_va, IA32_X2APIC_TPR, (UINT32)value << 4);
#endif
                return;
        default: return;
        }
}

/*
 * Write the value of the designated control register in the designated general
 * purpose register
 */
STATIC
VOID
DispatchExitReasonMovFromCr(_In_ VMX_EXIT_QUALIFICATION_MOV_CR* Qualification,
                            _In_ PGUEST_CONTEXT                 Context)
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
        UINT32                 tpr  = 0;

        switch (Qualification->ControlRegister) {
        case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
                WriteValueInContextRegister(
                    Context,
                    Qualification->GeneralPurposeRegister,
                    VmxVmRead(VMCS_GUEST_CR0));
                break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR3:
                WriteValueInContextRegister(
                    Context,
                    Qualification->GeneralPurposeRegister,
                    VmxVmRead(VMCS_GUEST_CR3));
                break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
                WriteValueInContextRegister(
                    Context,
                    Qualification->GeneralPurposeRegister,
                    VmxVmRead(VMCS_GUEST_CR4));
                break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR8:;
#if APIC
                tpr = __read_vapic_32(vcpu->virtual_apic_va, IA32_X2APIC_TPR);

                WriteValueInContextRegister(
                    Context, Qualification->GeneralPurposeRegister, tpr >> 4);
#else
                WriteValueInContextRegister(
                    Context,
                    Qualification->GeneralPurposeRegister,
                    __readcr8());
#endif
                break;
        default: break;
        }
}

/*
 * CLTS instruction clears the Task-Switched flag in CR0
 *
 * https://www.felixcloutier.com/x86/clts
 *
 * The CLTS instruction causes a VM exit if the bits in position 3
 * (corresponding to CR0.TS) are set in both the CR0 guest/host mask and the CR0
 * read shadow.
 */
STATIC
VOID
DispatchExitReasonCLTS(_In_ VMX_EXIT_QUALIFICATION_MOV_CR* Qualification,
                       _In_ PGUEST_CONTEXT                 Context)
{
        CR0 cr0                 = {0};
        cr0.AsUInt              = VmxVmRead(VMCS_GUEST_CR0);
        cr0.Fields.TaskSwitched = FALSE;

        if (ProbeGuestCurrentProtectionLevel() != CPL_KERNEL) {
                InjectGuestWithGpFault();
                return;
        }

        VmxVmWrite(VMCS_GUEST_CR0, cr0.AsUInt);
        VmxVmWrite(VMCS_CTRL_CR0_READ_SHADOW, cr0.AsUInt);
}

STATIC
BOOLEAN
DispatchExitReasonControlRegisterAccess(_In_ PGUEST_CONTEXT Context)
{
        VMX_EXIT_QUALIFICATION_MOV_CR qualification = {0};
        qualification.AsUInt = VmxVmRead(VMCS_EXIT_QUALIFICATION);

        if (ProbeGuestCurrentProtectionLevel() != CPL_KERNEL) {
                InjectGuestWithGpFault();
                return FALSE;
        }

        switch (qualification.AccessType) {
        case VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR:
                DispatchExitReasonMovToCr(&qualification, Context);
                break;
        case VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR:
                DispatchExitReasonMovFromCr(&qualification, Context);
                break;
        case VMX_EXIT_QUALIFICATION_ACCESS_CLTS:
                DispatchExitReasonCLTS(&qualification, Context);
                break;
        case VMX_EXIT_QUALIFICATION_ACCESS_LMSW: break;
        default: break;
        }

        /*
         * MOV to CR8 and MOV from CR8 are trap-like exits, where the
         * instruction completes before the vmx host handler is invoked, hence
         * we shouldnt increment the guest rip.
         */
        // if (qualification.ControlRegister ==
        //     VMX_EXIT_QUALIFICATION_REGISTER_CR8) {
        //         return TRUE;
        // }

        return FALSE;
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonINVD(_In_ PGUEST_CONTEXT GuestState)
{
        /* this is how hyper-v performs their invd */
        __wbinvd();
}

/*
 * Intel reserves CPUID Function levels 0x40000000 - 0x400000FF
 * for software use. This allows us to setup our own CPUID based
 * hypercall interface. For now we simple return the vendor, in
 * this case i love fortnite!
 */
FORCEINLINE
STATIC
BOOLEAN
IsCpuidFunctionAtHypervisorAltitude(_In_ UINT64 Rax)
{
        return Rax >= VMX_CPUID_FUNCTION_LOW && Rax <= VMX_CPUID_FUNCTION_HIGH
                   ? TRUE
                   : FALSE;
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonCPUID(_In_ PGUEST_CONTEXT GuestState)
{
        /* todo: implement some sort of caching mechanism */
        PVIRTUAL_MACHINE_STATE state =
            &vmm_state[KeGetCurrentProcessorNumber()];

        if (IsCpuidFunctionAtHypervisorAltitude(GuestState->rax)) {
                switch (GuestState->rax) {
                case CPUID_HYPERVISOR_INTERFACE_VENDOR:
                        state->cache.cpuid.value[CPUID_EAX] = 'i';
                        state->cache.cpuid.value[CPUID_EBX] = 'evol';
                        state->cache.cpuid.value[CPUID_ECX] = 'trof';
                        state->cache.cpuid.value[CPUID_EDX] = 'etin';
                        break;
                default:
#if DEBUG
                        HIGH_IRQL_LOG_SAFE(
                            "Invalid HV CPUID Function identifier passed.");
#endif
                        break;
                }
        }
        else {
                __cpuidex(state->cache.cpuid.value,
                          (INT32)GuestState->rax,
                          (INT32)GuestState->rcx);
        }

        GuestState->rax = state->cache.cpuid.value[CPUID_EAX];
        GuestState->rbx = state->cache.cpuid.value[CPUID_EBX];
        GuestState->rcx = state->cache.cpuid.value[CPUID_ECX];
        GuestState->rdx = state->cache.cpuid.value[CPUID_EDX];
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonWBINVD(_In_ PGUEST_CONTEXT Context)
{
        __wbinvd();
}

FORCEINLINE
STATIC
VOID
DispatchVmCallTerminateVmx()
{
        PVIRTUAL_MACHINE_STATE state = &vmm_state[KeGetCurrentProcessorIndex()];
        InterlockedExchange(&state->exit_state.exit_vmx, TRUE);
}

FORCEINLINE
STATIC
NTSTATUS
DispatchVmCallPing()
{
        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
VmCallDispatcher(_In_ UINT64     HypercallId,
                 _In_opt_ UINT64 OptionalParameter1,
                 _In_opt_ UINT64 OptionalParameter2,
                 _In_opt_ UINT64 OptionalParameter3)
{
        switch (HypercallId) {
        case VMX_HYPERCALL_TERMINATE_VMX: DispatchVmCallTerminateVmx(); break;
        case VMX_HYPERCALL_PING: return DispatchVmCallPing();
        default: break;
        }

        return STATUS_SUCCESS;
}

FORCEINLINE
STATIC
VOID
RestoreGuestStateOnTerminateVmx(PVIRTUAL_MACHINE_STATE State)
{
        /*
         * Before we execute vmxoff, store the guests rip and rsp in our vmxoff
         * state structure, this will allow us to use these values in the vmxoff
         * part of our vmx exit handler to properly restore the stack and
         * instruction pointer after we execute vmxoff
         *
         * The reason we must do this is since we are executing vmxoff, the rip
         * and rsp will no longer be automatically updated by hardware from the
         * vmcs, hence we need to save the 2 values and update the registers
         * with the values during our exit handler before we call vmxoff
         */
        State->exit_state.guest_rip = VmxVmRead(VMCS_GUEST_RIP);
        State->exit_state.guest_rsp = VmxVmRead(VMCS_GUEST_RSP);

        /*
         * As with the guest RSP and RIP, we need to restore the guests DEBUGCTL
         * msr.
         */
        __writemsr(IA32_DEBUGCTL, VmxVmRead(VMCS_GUEST_DEBUGCTL));

        /*
         * Since vmx root operation makes use of the system cr3, we need to
         * ensure we write the value of the guests previous cr3 before the exit
         * took place to ensure they have access to the correct dtb
         */
        __writecr3(VmxVmRead(VMCS_GUEST_CR3));

        /*
         * Do the same with the FS and GS base
         */
        __writemsr(IA32_FS_BASE, VmxVmRead(VMCS_GUEST_FS_BASE));
        __writemsr(IA32_GS_BASE, VmxVmRead(VMCS_GUEST_GS_BASE));

        /*
         * Write back the guest gdtr and idtrs
         */
        SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = {0};
        gdtr.BaseAddress                    = VmxVmRead(VMCS_GUEST_GDTR_BASE);
        gdtr.Limit                          = VmxVmRead(VMCS_GUEST_GDTR_LIMIT);
        __lgdt(&gdtr);

        SEGMENT_DESCRIPTOR_REGISTER_64 idtr = {0};
        idtr.BaseAddress                    = VmxVmRead(VMCS_GUEST_IDTR_BASE);
        idtr.Limit                          = VmxVmRead(VMCS_GUEST_IDTR_LIMIT);
        __lidt(&idtr);

        /*
        Execute the vmxoff instruction, leaving vmx operation
        */
        __vmx_off();
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonTprBelowThreshold(_In_ PGUEST_CONTEXT Context)
{
        DEBUG_LOG("exit reason tpr threshold");
        __debugbreak();
}

FORCEINLINE STATIC VOID
InjectExceptionOnVmEntry(VMEXIT_INTERRUPT_INFORMATION* ExitInterrupt)
{
        VMENTRY_INTERRUPT_INFORMATION intr = {
            .Vector           = ExitInterrupt->Vector,
            .DeliverErrorCode = ExitInterrupt->ErrorCodeValid,
            .InterruptionType = ExitInterrupt->InterruptionType,
            .Valid            = ExitInterrupt->Valid};

        /*
         * If bits 31 (Valid) and 11 (ErrorCodeValid) the vm-exit
         * interruption error code VMCS field receives the error code
         * that would've been pushed onto the stack by the exception.
         */
        if (ExitInterrupt->Valid && ExitInterrupt->ErrorCodeValid) {
                VmxVmWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE,
                           VmxVmRead(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE));
        }

        VmxVmWrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD,
                   intr.AsUInt);
}

/*
 * If vm-entry successfully injects an event with interruption type
 * external interrupt, NMI or hardware exception the current guest RIP
 * is pushed onto the stack.
 *
 * if vm-entry successfully injects an event with interruption type
 * software interrupt, privileged software exception or software
 * exception the current guest RIP is incremented by the vm-entry
 * instruction length before being pushed onto the stack, hence we do
 * not advance the guest rip in this case.
 */
FORCEINLINE
STATIC
BOOLEAN
ShouldExceptionAdvanceGuestRip(VMEXIT_INTERRUPT_INFORMATION* ExitInformation)
{
        if (ExitInformation->InterruptionType == SoftwareInterrupt ||
            ExitInformation->InterruptionType == PrivilegedSoftwareException ||
            ExitInformation->InterruptionType == SoftwareException)
                return FALSE;

        return TRUE;
}

FORCEINLINE
STATIC
BOOLEAN
DispatchExitReasonExceptionOrNmi(_In_ PGUEST_CONTEXT Context)
{
        VMEXIT_INTERRUPT_INFORMATION intr = {
            .AsUInt = VmxVmRead(VMCS_VMEXIT_INTERRUPTION_INFORMATION)};

#if DEBUG
        HIGH_IRQL_LOG_SAFE("Core: %lx - Vector: %lx, Interruption type: %lx",
                           KeGetCurrentProcessorNumber(),
                           intr.Vector,
                           intr.InterruptionType);
#endif

        switch (intr.Vector) {
        case EXCEPTION_DIVIDED_BY_ZERO: InjectExceptionOnVmEntry(&intr); break;
        case EXCEPTION_DEBUG:
        case EXCEPTION_NMI:
        case EXCEPTION_INT3:
        case EXCEPTION_BOUND_CHECK:
        case EXCEPTION_INVALID_OPCODE:
        case EXCEPTION_NPX_NOT_AVAILABLE:
        case EXCEPTION_DOUBLE_FAULT:
        case EXCEPTION_NPX_OVERRUN:
        case EXCEPTION_INVALID_TSS:
        case EXCEPTION_SEGMENT_NOT_PRESENT:
        case EXCEPTION_STACK_FAULT:
        case EXCEPTION_GP_FAULT:
        case EXCEPTION_RESERVED_TRAP:
        case EXCEPTION_NPX_ERROR:
        case EXCEPTION_ALIGNMENT_CHECK:
        case EXCEPTION_CP_FAULT:
        case EXCEPTION_SE_FAULT:
        case EXCEPTION_VIRTUALIZATION_FAULT:
        default:
                HandleNotImplementedExit(
                    STATUS_NOT_IMPLEMENTED, intr.Vector, NULL, NULL);
        }

        return ShouldExceptionAdvanceGuestRip(&intr);
}

/*
 * If we are delivering an interruption type equal to 7 (Other) and the
 * vector field is 0, vm-entry will cause an MTF vm-exit to be pending
 * on the instruction boundary. This will occur even if the monitor trap
 * flag VMCS control is set to 0.
 */
FORCEINLINE
STATIC
VOID
DispatchExitReasonMonitorTrapFlag(_In_ PGUEST_CONTEXT Context)
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
        /*
         * Since we don't set the monitor trap flag vmcs ctrl, lets
         * simply clear the mtf flag for the guest and continue
         * execution.
         */
        if (!vcpu->proc_ctls.MonitorTrapFlag) {
                RFLAGS flags    = {.AsUInt = Context->rflags};
                flags.TrapFlag  = FALSE;
                Context->rflags = flags.AsUInt;
        }
        else {
                /* For now, just bugcheck */
                KeBugCheckEx(VMX_BUGCHECK_INVALID_MTF_EXIT,
                             VmxVmRead(VMCS_GUEST_RIP),
                             Context->rflags,
                             vcpu->proc_ctls.AsUInt,
                             0);
        }
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonWrmsr(_In_ PGUEST_CONTEXT Context)
{
        LARGE_INTEGER          msr  = {0};
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];

        if (ProbeGuestCurrentProtectionLevel() != CPL_KERNEL) {
                InjectGuestWithGpFault();
                return;
        }

        if (Context->rcx == IA32_X2APIC_TPR) {
                *(UINT32*)(vcpu->virtual_apic_va + APIC_TASK_PRIORITY) =
                    (UINT32)Context->rcx << 4;
        }
        else {
                msr.LowPart  = (UINT32)Context->rax;
                msr.HighPart = (UINT32)Context->rdx;
                __writemsr((UINT32)Context->rcx, msr.QuadPart);
        }
}

#define X2APIC_MSR_LOW  0x800
#define X2APIC_MSR_HIGH 0x83f

FORCEINLINE
STATIC
BOOLEAN
IsMsrReadX2Apic(UINT32 Ecx)
{
        return Ecx >= X2APIC_MSR_LOW && Ecx <= X2APIC_MSR_HIGH ? TRUE : FALSE;
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonRdmsr(_In_ PGUEST_CONTEXT Context)
{
        LARGE_INTEGER          msr  = {0};
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];

        if (ProbeGuestCurrentProtectionLevel() != CPL_KERNEL) {
                InjectGuestWithGpFault();
                return;
        }

        if ((UINT32)Context->rcx == IA32_X2APIC_TPR) {
                Context->rax = 0;
                (UINT32) Context->rax =
                    *(UINT32*)(vcpu->virtual_apic_va + APIC_TASK_PRIORITY) >> 4;
                Context->rdx = 0;
        }
        else {
                msr.QuadPart = __readmsr((UINT32)Context->rcx);
                Context->rax = msr.LowPart;
                Context->rdx = msr.HighPart;
        }
}

/*
 * String based I/O reads/writes use RSI for OUT and RDI for IN. Else we
 * use RAX as we would for any other call.
 */
FORCEINLINE
STATIC
PUINT64
GetIoInstructionOutputRegister(
    _In_ PGUEST_CONTEXT                         Context,
    _In_ VMX_EXIT_QUALIFICATION_IO_INSTRUCTION* Qualification)
{
        if (Qualification->StringInstruction ==
            VMX_EXIT_QUALIFICATION_IS_STRING_STRING) {
                return Qualification->DirectionOfAccess ==
                               VMX_EXIT_QUALIFICATION_DIRECTION_IN
                           ? &Context->rdi
                           : &Context->rsi;
        }

        return &Context->rax;
}

/*
 * If the associated IN / OUT instruction is prefixed with REP, the
 * string instruction will be repeated the number of times specified in
 * the count register (ECX) or until the indicated position of the ZF
 * flag is no longer met.
 */
FORCEINLINE
STATIC
UINT32
GetIoInstructionRepeatCount(
    _In_ PGUEST_CONTEXT                         Context,
    _In_ VMX_EXIT_QUALIFICATION_IO_INSTRUCTION* Qualification)
{
        return Qualification->RepPrefixed ? (UINT32)Context->rcx : 1;
}

FORCEINLINE
STATIC
VOID
HandleIoInStringOrByte(_In_ UINT16     PortNumber,
                       _Inout_ PUINT32 OutRegister,
                       _In_ UINT32     AccessSize,
                       _In_ BOOLEAN    String)
{
        if (String) {
                switch (AccessSize) {
                case VMX_EXIT_QUALIFICATION_WIDTH_1_BYTE:
                        __inbytestring(
                            PortNumber, (PUINT8)OutRegister, AccessSize);
                        break;
                case VMX_EXIT_QUALIFICATION_WIDTH_2_BYTE:
                        __inwordstring(
                            PortNumber, (PUINT16)OutRegister, AccessSize);
                        break;
                case VMX_EXIT_QUALIFICATION_WIDTH_4_BYTE:
                        __indwordstring(
                            PortNumber, (PUINT32)OutRegister, AccessSize);
                        break;
                }
        }
        else {
                switch (AccessSize) {
                case VMX_EXIT_QUALIFICATION_WIDTH_1_BYTE:
                        *OutRegister = __inbyte(PortNumber);
                        break;
                case VMX_EXIT_QUALIFICATION_WIDTH_2_BYTE:
                        *OutRegister = __inword(PortNumber);
                        break;
                case VMX_EXIT_QUALIFICATION_WIDTH_4_BYTE:
                        *OutRegister = __indword(PortNumber);
                        break;
                }
        }
}

FORCEINLINE
STATIC
VOID
HandleIoOutStringOrByte(_In_ UINT16     PortNumber,
                        _Inout_ PUINT32 OutRegister,
                        _In_ UINT32     AccessSize,
                        _In_ BOOLEAN    String)
{
        if (String) {
                switch (AccessSize) {
                case VMX_EXIT_QUALIFICATION_WIDTH_1_BYTE:
                        __outbytestring(
                            PortNumber, (PUINT8)OutRegister, AccessSize);
                        break;
                case VMX_EXIT_QUALIFICATION_WIDTH_2_BYTE:
                        __outwordstring(
                            PortNumber, (PUINT16)OutRegister, AccessSize);
                        break;
                case VMX_EXIT_QUALIFICATION_WIDTH_4_BYTE:
                        __outdwordstring(
                            PortNumber, (PUINT32)OutRegister, AccessSize);
                        break;
                }
        }
        else {
                switch (AccessSize) {
                case VMX_EXIT_QUALIFICATION_WIDTH_1_BYTE:
                        __outbyte(PortNumber, (UINT8)*OutRegister);
                        break;
                case VMX_EXIT_QUALIFICATION_WIDTH_2_BYTE:
                        __outword(PortNumber, (UINT16)*OutRegister);
                        break;
                case VMX_EXIT_QUALIFICATION_WIDTH_4_BYTE:
                        __outdword(PortNumber, (UINT32)*OutRegister);
                        break;
                }
        }
}

FORCEINLINE
STATIC
VOID
UpdateDirectionFlagRegister(_Inout_ PUINT64     Output,
                            _In_ PGUEST_CONTEXT Context,
                            _In_ UINT32         Repetitions,
                            _In_ UINT32         AccessSize)
{
        if (Context->rflags & EFLAGS_DIRECTION_FLAG_BIT)
                (UINT32)* Output -= Repetitions * AccessSize;
        else
                (UINT32)* Output += Repetitions * AccessSize;
}

#define KPCR_TSS_BASE_OFFSET 0x008

FORCEINLINE
STATIC
BOOLEAN
IsIoPortAvailable(_In_ UINT64 GuestKpcr, _In_ UINT64 Port)
{
        TASK_STATE_SEGMENT_64* tss =
            *(TASK_STATE_SEGMENT_64**)(GuestKpcr + KPCR_TSS_BASE_OFFSET);

        /* If no tss lets just return true e.e */
        if (!tss)
                return TRUE;

        UINT64 bitmap     = (UINT64)tss + tss->IoMapBase;
        UINT64 byte_index = Port / sizeof(UINT64);
        UINT64 bit_index  = Port % sizeof(UINT64);
        UINT8  byte       = *(UINT8*)(bitmap + byte_index);

        /* if port bit is 0, its available, else its not. */
        return byte & (1 << bit_index) ? FALSE : TRUE;
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonIoInstruction(_In_ PGUEST_CONTEXT Context)
{
        VMX_EXIT_QUALIFICATION_IO_INSTRUCTION qual = {
            .AsUInt = VmxVmRead(VMCS_EXIT_QUALIFICATION)};
        UINT64 guest_kpcr  = VmxVmRead(VMCS_GUEST_GS_BASE);
        EFLAGS guest_flags = {.AsUInt = Context->rflags};

        /* If CPL > IOPL, raise #GP */
        if (ProbeGuestCurrentProtectionLevel() > guest_flags.IoPrivilegeLevel) {
                InjectGuestWithGpFault();
                return;
        }

        /*
         * If the specified I/O port permission bit is set, the operation is not
         * allowed -> raise #GP
         */
        if (!IsIoPortAvailable(guest_kpcr, qual.PortNumber)) {
                InjectGuestWithGpFault();
                return;
        }

        PUINT64 output      = GetIoInstructionOutputRegister(Context, &qual);
        UINT32  repetitions = GetIoInstructionRepeatCount(Context, &qual);

        if (qual.DirectionOfAccess == VMX_EXIT_QUALIFICATION_DIRECTION_IN) {
                HandleIoInStringOrByte(qual.PortNumber,
                                       (PUINT32)output,
                                       qual.SizeOfAccess,
                                       qual.StringInstruction);
        }
        else {
                HandleIoOutStringOrByte(qual.PortNumber,
                                        (PUINT32)output,
                                        qual.SizeOfAccess,
                                        qual.StringInstruction);
        }

        /*
         * RCX contains the number of iterations that the I/O
         * instruction will run, update the register to ensure the
         * instruction is executed the correct number of times.
         */
        if (qual.StringInstruction == VMX_EXIT_QUALIFICATION_IS_STRING_STRING)
                UpdateDirectionFlagRegister(
                    output, Context, repetitions, qual.SizeOfAccess);
}

FORCEINLINE
STATIC
VOID
WriteToDebugRegister(_In_ PGUEST_CONTEXT Context,
                     _In_ UINT8          Register,
                     _In_ UINT64         Value)
{
        switch (Register) {
        case DEBUG_DR0: Context->dr0 = Value; break;
        case DEBUG_DR1: Context->dr1 = Value; break;
        case DEBUG_DR2: Context->dr2 = Value; break;
        case DEBUG_DR3: Context->dr3 = Value; break;
        case DEBUG_DR6: Context->dr6 = Value; break;
        case DEBUG_DR7: Context->dr7 = Value; break;
        default: InjectGuestWithGpFault(); return;
        }
}

FORCEINLINE
STATIC
UINT64
ReadDebugRegister(_In_ PGUEST_CONTEXT Context, _In_ UINT8 Register)
{
        switch (Register) {
        case DEBUG_DR0: return Context->dr0;
        case DEBUG_DR1: return Context->dr1;
        case DEBUG_DR2: return Context->dr2;
        case DEBUG_DR3: return Context->dr3;
        case DEBUG_DR6: return Context->dr6;
        case DEBUG_DR7: return Context->dr7;
        default: InjectGuestWithGpFault(); return;
        }
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonDebugRegisterAccess(_In_ PGUEST_CONTEXT Context)
{
        VMX_EXIT_QUALIFICATION_MOV_DR qual = {
            .AsUInt = VmxVmRead(VMCS_EXIT_QUALIFICATION)};
        CR4 cr4 = {.AsUInt = VmxVmRead(VMCS_GUEST_CR4)};
        DR7 dr7 = {.AsUInt = VmxVmRead(VMCS_GUEST_DR7)};

        if (ProbeGuestCurrentProtectionLevel() != CPL_KERNEL) {
                InjectGuestWithGpFault();
                return;
        }

        /* if CR3.DE = 1 and a mov instruction is involving DR4 or DR5, raise
         * #UD */
        if (cr4.DebuggingExtensions &&
                qual.DebugRegister == VMX_EXIT_QUALIFICATION_REGISTER_DR4 ||
            qual.DebugRegister == VMX_EXIT_QUALIFICATION_REGISTER_DR5) {
                InjectGuestWithUdFault();
                return;
        }

        /* any dr register access while DR7.GD = 1, raise #DB */
        if (dr7.GeneralDetect) {
                InjectGuestWithDbFault();
                return;
        }

        if (qual.DirectionOfAccess ==
            VMX_EXIT_QUALIFICATION_DIRECTION_MOV_TO_DR) {
                WriteToDebugRegister(Context,
                                     qual.DebugRegister,
                                     RetrieveValueInContextRegister(
                                         Context, qual.GeneralPurposeRegister));
        }
        else {
                WriteValueInContextRegister(
                    Context,
                    qual.GeneralPurposeRegister,
                    ReadDebugRegister(Context, qual.DebugRegister));
        }
}

/*
 * Assuming no debug state is stored upon vmexit, it would mean the host makes
 * use of the guests debug register state. This can make debugging hard and very
 * buggy. To combat this, we should store the hosts state on vmexit and vmentry
 * in the associated vcpu. This allows us to keep track of both the guest and
 * the hosts debug state seperately, allowing for (mostly) easy debugging. It
 * currently isnt perfect, as placing breakpoints at certain key positions such
 * as before the host state is loaded can cause some errors, for now though its
 * good enough.
 *
 * General implementation idea can be found in this openbsd patch:
 * https://reviews.freebsd.org/D13229
 */

VOID
LoadHostDebugRegisterState()
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorIndex()];
        __writedr(DEBUG_DR0, vcpu->debug_state.dr0);
        __writedr(DEBUG_DR1, vcpu->debug_state.dr1);
        __writedr(DEBUG_DR2, vcpu->debug_state.dr2);
        __writedr(DEBUG_DR3, vcpu->debug_state.dr3);
        __writedr(DEBUG_DR6, vcpu->debug_state.dr6);
        __writedr(DEBUG_DR7, vcpu->debug_state.dr7);
}

VOID
StoreHostDebugRegisterState()
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorIndex()];
        vcpu->debug_state.dr0       = __readdr(DEBUG_DR0);
        vcpu->debug_state.dr1       = __readdr(DEBUG_DR1);
        vcpu->debug_state.dr2       = __readdr(DEBUG_DR2);
        vcpu->debug_state.dr3       = __readdr(DEBUG_DR3);
        vcpu->debug_state.dr6       = __readdr(DEBUG_DR6);
        vcpu->debug_state.dr7       = __readdr(DEBUG_DR7);
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonVirtualisedEoi(_In_ PGUEST_CONTEXT Context)
{
        DEBUG_LOG("EOI EXIUT REASON!");
        __debugbreak();
}

BOOLEAN
VmExitDispatcher(_In_ PGUEST_CONTEXT Context)
{
        UINT64                 additional_rip_offset = 0;
        PVIRTUAL_MACHINE_STATE state = &vmm_state[KeGetCurrentProcessorIndex()];

        switch (VmxVmRead(VMCS_EXIT_REASON)) {
        case VMX_EXIT_REASON_EXECUTE_CPUID:
                DispatchExitReasonCPUID(Context);
                break;
        case VMX_EXIT_REASON_EXECUTE_INVD:
                DispatchExitReasonINVD(Context);
                break;
        case VMX_EXIT_REASON_EXECUTE_VMCALL:
                Context->rax = VmCallDispatcher(
                    Context->rcx, Context->rdx, Context->r8, Context->r9);
                break;
        case VMX_EXIT_REASON_MOV_CR:
                if (DispatchExitReasonControlRegisterAccess(Context))
                        goto no_rip_increment;
                break;
        case VMX_EXIT_REASON_EXECUTE_WBINVD:
                DispatchExitReasonWBINVD(Context);
                break;

        /*
         * TPR_BELOW_THRESHOLD is a trap-like exit and will perform the
         * exit-casuing instruction before invoking our handler, hence
         * we shouldn't increment the rip.
         */
        case VMX_EXIT_REASON_TPR_BELOW_THRESHOLD:
                DispatchExitReasonTprBelowThreshold(Context);
                goto no_rip_increment;

        /*
         * If DispatchExitReasonExceptionOrNmi returns FALSE, we don't
         * advanced the guest rip, else we do as normal.
         */
        case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
                if (!DispatchExitReasonExceptionOrNmi(Context))
                        goto no_rip_increment;
                break;

        case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
                DispatchExitReasonMonitorTrapFlag(Context);
                goto no_rip_increment;
        case VMX_EXIT_REASON_EXECUTE_WRMSR:
                DispatchExitReasonWrmsr(Context);
                break;
        case VMX_EXIT_REASON_EXECUTE_RDMSR:
                DispatchExitReasonRdmsr(Context);
                break;
        case VMX_EXIT_REASON_EXECUTE_IO_INSTRUCTION:
                DispatchExitReasonIoInstruction(Context);
                break;
        case VMX_EXIT_REASON_MOV_DR:
                DispatchExitReasonDebugRegisterAccess(Context);
                break;
        case VMX_EXIT_REASON_VIRTUALIZED_EOI:
                /* EOI induced exits are trap like */
                DispatchExitReasonVirtualisedEoi(Context);
                goto no_rip_increment;
        default: break;
        }

        /*
         * Increment our guest rip by the size of the exiting
         * instruction since we've processed it
         */
        IncrementGuestRip();

no_rip_increment:
        /*
         * If we are indeed exiting VMX operation, return TRUE to
         * indicate to our handler that we have indeed exited VMX
         * operation.
         */
        if (InterlockedExchange(&state->exit_state.exit_vmx,
                                state->exit_state.exit_vmx)) {
                RestoreGuestStateOnTerminateVmx(state);
                return TRUE;
        }

        /* continue vmx operation as usual */
        return FALSE;
}