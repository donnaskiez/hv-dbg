#include "vmcs.h"

#include "ia32.h"
#include "vmx.h"
#include "encode.h"
#include "arch.h"

VMCS_GUEST_STATE_FIELDS   guest_state_fields = { 0 };
VMCS_HOST_STATE_FIELDS    host_state_fields = { 0 };
VMCS_CONTROL_STATE_FIELDS control_state_fields = { 0 };

STATIC
BOOLEAN
GetSegmentDescriptor(
        _In_ PSEGMENT_SELECTOR SegmentSelector,
        _In_ USHORT            Selector,
        _In_ PUCHAR            GdtBase
)
{
        ULONG64 temp = 0;
        PSEGMENT_DESCRIPTOR segment_descriptor = NULL;

        if (!SegmentSelector)
                return FALSE;

        if (Selector & 0x4)
                return FALSE;

        segment_descriptor = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

        SegmentSelector->SEL = Selector;
        SegmentSelector->BASE = segment_descriptor->BASE0 | segment_descriptor->BASE1 << 16 | segment_descriptor->BASE2 << 24;
        SegmentSelector->LIMIT = segment_descriptor->LIMIT0 | (segment_descriptor->LIMIT1ATTR1 & 0xf) << 16;
        SegmentSelector->ATTRIBUTES.UCHARs = segment_descriptor->ATTR0 | (segment_descriptor->LIMIT1ATTR1 & 0xf0) << 4;

        if (!(segment_descriptor->ATTR0 & 0x10))
        {
                // this is a TSS or callgate etc, save the base high part
                temp = (*(PULONG64)((PUCHAR)segment_descriptor + 8));
                SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (temp << 32);
        }

        if (SegmentSelector->ATTRIBUTES.Fields.G)
        {
                // 4096-bit granularity is enabled for this segment, scale the limit
                SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
        }

        return TRUE;
}

ULONG
AdjustMsrControl(
        _In_ ULONG Control,
        _In_ ULONG  Msr
)
{
        MSR MsrValue = { 0 };

        MsrValue.Content = __readmsr(Msr);
        Control &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
        Control |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
        return Control;
}

VOID
VmcsWriteSelectors(
        _In_ PVOID  GdtBase,
        _In_ ULONG  SegmentRegisters,
        _In_ USHORT Selector
)
{
        SEGMENT_SELECTOR segment_selector = { 0 };
        ULONG            access_rights;

        GetSegmentDescriptor(&segment_selector, Selector, GdtBase);
        access_rights = ((PUCHAR)&segment_selector.ATTRIBUTES)[0] + (((PUCHAR)&segment_selector.ATTRIBUTES)[1] << 12);

        if (!Selector)
                access_rights |= 0x10000;

        __vmx_vmwrite(guest_state_fields.word_state.es_selector + SegmentRegisters * 2, Selector);
        __vmx_vmwrite(guest_state_fields.dword_state.es_limit + SegmentRegisters * 2, segment_selector.LIMIT);
        __vmx_vmwrite(GUEST_ES_AR_BYTES + SegmentRegisters * 2, access_rights);
        __vmx_vmwrite(GUEST_ES_BASE + SegmentRegisters * 2, segment_selector.BASE);
}

STATIC
VOID
VmcsWriteHostStateFields(
        _In_ PVIRTUAL_MACHINE_STATE GuestState
)
{
        SEGMENT_SELECTOR selector = { 0 };
        GetSegmentDescriptor(&selector, __readtr(), (PUCHAR)__readgdtbase());
        __vmx_vmwrite(HOST_TR_BASE, selector.BASE);

        __vmx_vmwrite(host_state_fields.word_state.es_selector, __reades() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.cs_selector, __readcs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.ss_selector, __readss() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.ds_selector, __readds() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.fs_selector, __readfs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.gs_selector, __readgs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.tr_selector, __readtr() & 0xF8);

        __vmx_vmwrite(host_state_fields.natural_state.cr0, __readcr0());
        __vmx_vmwrite(host_state_fields.natural_state.cr3, __readcr3());
        __vmx_vmwrite(host_state_fields.natural_state.cr4, __readcr4());

        __vmx_vmwrite(host_state_fields.natural_state.gdtr_base, __readgdtbase());
        __vmx_vmwrite(host_state_fields.natural_state.idtr_base, __readidtbase());

        __vmx_vmwrite(host_state_fields.natural_state.rsp, GuestState->vmm_stack + VMM_STACK_SIZE - 1);
        __vmx_vmwrite(host_state_fields.natural_state.rip, VmexitHandler);

        __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
        __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

        __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
        __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
        __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
}

STATIC
VOID
VmcsWriteGuestStateFields(
        _In_ PVOID StackPointer
)
{
        __vmx_vmwrite(guest_state_fields.qword_state.vmcs_link_pointer, ~0ull);

        __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);
        __vmx_vmwrite(guest_state_fields.qword_state.debug_control, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);

        VmcsWriteSelectors(__readgdtbase(), ES, __reades());
        VmcsWriteSelectors(__readgdtbase(), CS, __readcs());
        VmcsWriteSelectors(__readgdtbase(), SS, __readss());
        VmcsWriteSelectors(__readgdtbase(), DS, __readds());
        VmcsWriteSelectors(__readgdtbase(), FS, __readfs());
        VmcsWriteSelectors(__readgdtbase(), GS, __readgs());
        VmcsWriteSelectors(__readgdtbase(), LDTR, __readldtr());
        VmcsWriteSelectors(__readgdtbase(), TR, __readtr());

        __vmx_vmwrite(guest_state_fields.natural_state.cr0, __readcr0());
        __vmx_vmwrite(guest_state_fields.natural_state.cr3, __readcr3());
        __vmx_vmwrite(guest_state_fields.natural_state.cr4, __readcr4());
        __vmx_vmwrite(guest_state_fields.natural_state.dr7, 0x400);

        __vmx_vmwrite(guest_state_fields.natural_state.gdtr_base, __readgdtbase());
        __vmx_vmwrite(guest_state_fields.natural_state.idtr_base, __readidtbase());

        __vmx_vmwrite(guest_state_fields.dword_state.gdtr_limit, __segmentlimit(__readgdtbase));
        __vmx_vmwrite(guest_state_fields.dword_state.idtr_limit, __segmentlimit(__readidtbase));

        __vmx_vmwrite(guest_state_fields.natural_state.rflags, __readrflags());

        __vmx_vmwrite(guest_state_fields.dword_state.sysenter_cs, __readmsr(MSR_IA32_SYSENTER_CS));
        __vmx_vmwrite(guest_state_fields.natural_state.sysenter_eip, __readmsr(MSR_IA32_SYSENTER_EIP));
        __vmx_vmwrite(guest_state_fields.natural_state.sysenter_esp, __readmsr(MSR_IA32_SYSENTER_ESP));
        __vmx_vmwrite(guest_state_fields.natural_state.fs_base, __readmsr(MSR_FS_BASE));
        __vmx_vmwrite(guest_state_fields.natural_state.gs_base, __readmsr(MSR_GS_BASE));

        __vmx_vmwrite(guest_state_fields.natural_state.rsp, StackPointer);
        __vmx_vmwrite(guest_state_fields.natural_state.rip, VmxRestoreState);
}

STATIC
VOID
VmcsWriteControlStateFields(
        _In_ PVIRTUAL_MACHINE_STATE GuestState
)
{
        /*
        * ActivateSecondaryControls activates the secondary processor-based VM-execution controls.
        * If UseMsrBitmaps is not set, all RDMSR and WRMSR instructions cause vm-exits.
        */
        IA32_VMX_PROCBASED_CTLS_REGISTER proc_ctls = { 0 };
        proc_ctls.ActivateSecondaryControls = TRUE;
        proc_ctls.UseMsrBitmaps = TRUE;

        __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                AdjustMsrControl((UINT32)proc_ctls.AsUInt, MSR_IA32_VMX_PROCBASED_CTLS));

        /*
        * Ensure RDTSCP, INVPCID and XSAVES/XRSTORS do not raise an invalid opcode exception.
        */
        IA32_VMX_PROCBASED_CTLS2_REGISTER proc_ctls2 = { 0 };
        proc_ctls2.EnableRdtscp = TRUE;
        proc_ctls2.EnableInvpcid = TRUE;
        proc_ctls2.EnableXsaves = TRUE;

        __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL,
                AdjustMsrControl((UINT32)proc_ctls2.AsUInt, MSR_IA32_VMX_PROCBASED_CTLS2));

        /*
        * Lets not force a vmexit on any external interrupts
        */
        IA32_VMX_PINBASED_CTLS_REGISTER pin_ctls = { 0 };

        __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL,
                AdjustMsrControl((UINT32)pin_ctls.AsUInt, MSR_IA32_VMX_PINBASED_CTLS));

        /*
        * Ensure we acknowledge interrupts on VMEXIT and are in 64 bit mode.
        */
        IA32_VMX_EXIT_CTLS_REGISTER exit_ctls = { 0 };
        exit_ctls.AcknowledgeInterruptOnExit = TRUE;
        exit_ctls.HostAddressSpaceSize = TRUE;

        __vmx_vmwrite(VM_EXIT_CONTROLS,
                AdjustMsrControl((UINT32)exit_ctls.AsUInt, MSR_IA32_VMX_EXIT_CTLS));

        /*
        * Ensure we are in 64bit mode on VMX entry.
        */
        IA32_VMX_ENTRY_CTLS_REGISTER entry_ctls = { 0 };
        entry_ctls.Ia32EModeGuest = TRUE;

        __vmx_vmwrite(VM_ENTRY_CONTROLS,
                AdjustMsrControl((UINT32)entry_ctls.AsUInt, MSR_IA32_VMX_ENTRY_CTLS));

        __vmx_vmwrite(control_state_fields.qword_state.msr_bitmap_address, GuestState->msr_bitmap_pa);
}

NTSTATUS
SetupVmcs(
        _In_ PVIRTUAL_MACHINE_STATE GuestState,
        _In_ PVOID StackPointer
)
{
        EncodeVmcsControlStateFields(&control_state_fields);
        EncodeVmcsGuestStateFields(&guest_state_fields);
        EncodeVmcsHostStateFields(&host_state_fields);

        if (__vmx_vmclear(&GuestState->vmcs_region_pa) != VMX_OK)
        {
                DEBUG_ERROR("Unable to clear the vmcs region");
                return STATUS_ABANDONED;
        }

        if (__vmx_vmptrld(&GuestState->vmcs_region_pa) != VMX_OK)
        {
                ULONG64 error_code = 0;
                __vmx_vmread(VM_INSTRUCTION_ERROR, &error_code);
                DEBUG_ERROR("vmptrld failed with status: %x", (ULONG)error_code);
                return STATUS_ABANDONED;
        }

        VmcsWriteControlStateFields(GuestState);
        VmcsWriteGuestStateFields(StackPointer);
        VmcsWriteHostStateFields(GuestState);

        return STATUS_SUCCESS;
}