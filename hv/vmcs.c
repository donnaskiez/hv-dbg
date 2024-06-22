#include "vmcs.h"

#include "ia32.h"
#include "vmx.h"
#include "arch.h"
#include <intrin.h>

/* Wrapper functions to read and write to and from the vmcs. */
UINT64
VmxVmRead(_In_ UINT64 VmcsField)
{
        UINT64 result = 0;
        __vmx_vmread(VmcsField, &result);
        return result;
}

VOID
VmxVmWrite(_In_ UINT64 VmcsField, _In_ UINT64 Value)
{
        __vmx_vmwrite(VmcsField, Value);
}

STATIC
UINT32
__segmentar(SEGMENT_SELECTOR* Selector)
{
        VMX_SEGMENT_ACCESS_RIGHTS ar = {0};

        /*
         * If the table is set to the GDT and there is no index, set the segment
         * as unusable.
         */
        if (Selector->Table == FALSE && Selector->Index == FALSE) {
                ar.Unusable = TRUE;
                return ar.AsUInt;
        }

        /*
         * Use the lar instruction to load the access rights. remove the first
         * byte as the value is not used in the access rights. Set the unusable
         * flag to false to allow the access rightse to be used.
         */
        ar.AsUInt    = (__lar(Selector->AsUInt) >> 8);
        ar.Unusable  = 0;
        ar.Reserved1 = 0;
        ar.Reserved2 = 0;

        return ar.AsUInt;
}

STATIC
UINT32
AdjustMsrControl(_In_ UINT32 Control, _In_ UINT32 Msr)
{
        ULARGE_INTEGER msr = {0};
        msr.QuadPart       = __readmsr(Msr);

        Control &= msr.HighPart;
        Control |= msr.LowPart;

        return Control;
}

/*
 * Given either the LDT or GDT base, return the segment descriptor given the
 * selector talble index. We do this by taking the Selectors Index value and
 * multiplying it by 8 as each entry is the size of a pointer.
 */
STATIC
SEGMENT_DESCRIPTOR_64*
GetSegmentDescriptor(_In_ UINT64 TableBase, _In_ SEGMENT_SELECTOR* Selector)
{
        return (SEGMENT_DESCRIPTOR_64*)(TableBase +
                                        Selector->Index * sizeof(UINT64));
}

STATIC
UINT64
GetSegmentDescriptorBase(_In_ SEGMENT_DESCRIPTOR_64* Descriptor)
{
        UINT64 base = Descriptor->BaseAddressHigh << 24 |
                      Descriptor->BaseAddressMiddle << 16 |
                      Descriptor->BaseAddressLow;

        /*
         * If our our descriptor is a system descriptor and, more specifically,
         * points to the TSS - it means we need to expand the base to 16 bytes.
         * The reason for this is as most descriptors are 8 bytes, the
         * call-gate, IDT and LDT/TSS descriptors are expanded to 16 bytes.
         */
        if (Descriptor->DescriptorType == SEGMENT_DESCRIPTOR_TYPE_SYSTEM &&
            (Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE ||
             Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY))
                base |= (UINT64)(((SEGMENT_DESCRIPTOR_64*)Descriptor)
                                     ->BaseAddressUpper)
                        << 32;

        return base;
}

STATIC
UINT64
__segmentbase(_In_ SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr,
              _In_ SEGMENT_SELECTOR*               Selector)
{
        if (!Selector->AsUInt)
                return 0;

        SEGMENT_DESCRIPTOR_64* descriptor =
            GetSegmentDescriptor(Gdtr->BaseAddress, Selector);

        /*
         * Selector->Table specifies the descriptor table to use. Clearing the
         * flag selects the GDT while setting the flags selects the current LDT.
         *
         * Because all execution will happen within the context of the OS, we
         * don't need to worry about LDT descriptors
         */
        if (Selector->Table == TRUE)
                return 0;

        /*
         * Given our segment descriptor, find the base address the descriper
         * describes and return it.
         */
        return GetSegmentDescriptorBase(descriptor);
}

STATIC
VOID
VmcsWriteHostStateFields(_In_ PVIRTUAL_MACHINE_STATE GuestState)
{
        SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = {0};
        SEGMENT_DESCRIPTOR_REGISTER_64 idtr = {0};

        __sgdt(&gdtr);
        __sidt(&idtr);

        SEGMENT_SELECTOR tr = {0};

        tr.AsUInt = __readtr();

        VmxVmWrite(VMCS_HOST_ES_SELECTOR, __reades() & VMCS_HOST_SELECTOR_MASK);
        VmxVmWrite(VMCS_HOST_CS_SELECTOR, __readcs() & VMCS_HOST_SELECTOR_MASK);
        VmxVmWrite(VMCS_HOST_SS_SELECTOR, __readss() & VMCS_HOST_SELECTOR_MASK);
        VmxVmWrite(VMCS_HOST_DS_SELECTOR, __readds() & VMCS_HOST_SELECTOR_MASK);
        VmxVmWrite(VMCS_HOST_FS_SELECTOR, __readfs() & VMCS_HOST_SELECTOR_MASK);
        VmxVmWrite(VMCS_HOST_GS_SELECTOR, __readgs() & VMCS_HOST_SELECTOR_MASK);
        VmxVmWrite(VMCS_HOST_TR_SELECTOR, __readtr() & VMCS_HOST_SELECTOR_MASK);

        VmxVmWrite(VMCS_HOST_CR0, __readcr0());
        VmxVmWrite(VMCS_HOST_CR3, __readcr3());
        VmxVmWrite(VMCS_HOST_CR4, __readcr4());

        VmxVmWrite(VMCS_HOST_GDTR_BASE, gdtr.BaseAddress);
        VmxVmWrite(VMCS_HOST_IDTR_BASE, idtr.BaseAddress);

        VmxVmWrite(VMCS_HOST_RSP, GuestState->vmm_stack_va);
        VmxVmWrite(VMCS_HOST_RIP, VmExitHandler);

        VmxVmWrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
        VmxVmWrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));
        VmxVmWrite(VMCS_HOST_TR_BASE, __segmentbase(&gdtr, &tr));

        VmxVmWrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
        VmxVmWrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
        VmxVmWrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
}

STATIC
VOID
VmcsWriteGuestStateFields(_In_ PVOID                  StackPointer,
                          _In_ PVIRTUAL_MACHINE_STATE GuestState)
{
        SEGMENT_SELECTOR es   = {0};
        SEGMENT_SELECTOR cs   = {0};
        SEGMENT_SELECTOR ss   = {0};
        SEGMENT_SELECTOR ds   = {0};
        SEGMENT_SELECTOR fs   = {0};
        SEGMENT_SELECTOR gs   = {0};
        SEGMENT_SELECTOR tr   = {0};
        SEGMENT_SELECTOR ldtr = {0};

        es.AsUInt  = __reades();
        cs.AsUInt  = __readcs();
        ss.AsUInt  = __readss();
        ds.AsUInt  = __readds();
        fs.AsUInt  = __readfs();
        gs.AsUInt  = __readgs();
        tr.AsUInt  = __readtr();
        ldtr.Table = __readldtr();

        SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = {0};
        SEGMENT_DESCRIPTOR_REGISTER_64 idtr = {0};

        __sgdt(&gdtr);
        __sidt(&idtr);

        VmxVmWrite(VMCS_GUEST_ES_SELECTOR, es.AsUInt);
        VmxVmWrite(VMCS_GUEST_CS_SELECTOR, cs.AsUInt);
        VmxVmWrite(VMCS_GUEST_SS_SELECTOR, ss.AsUInt);
        VmxVmWrite(VMCS_GUEST_DS_SELECTOR, ds.AsUInt);
        VmxVmWrite(VMCS_GUEST_FS_SELECTOR, fs.AsUInt);
        VmxVmWrite(VMCS_GUEST_GS_SELECTOR, gs.AsUInt);
        VmxVmWrite(VMCS_GUEST_TR_SELECTOR, tr.AsUInt);
        VmxVmWrite(VMCS_GUEST_LDTR_SELECTOR, ldtr.AsUInt);

        VmxVmWrite(VMCS_GUEST_ES_BASE, __segmentbase(&gdtr, &es));
        VmxVmWrite(VMCS_GUEST_CS_BASE, __segmentbase(&gdtr, &cs));
        VmxVmWrite(VMCS_GUEST_SS_BASE, __segmentbase(&gdtr, &ss));
        VmxVmWrite(VMCS_GUEST_DS_BASE, __segmentbase(&gdtr, &ds));
        VmxVmWrite(VMCS_GUEST_FS_BASE, __segmentbase(&gdtr, &fs));
        VmxVmWrite(VMCS_GUEST_GS_BASE, __segmentbase(&gdtr, &gs));
        VmxVmWrite(VMCS_GUEST_TR_BASE, __segmentbase(&gdtr, &tr));
        VmxVmWrite(VMCS_GUEST_LDTR_BASE, __segmentbase(&gdtr, &ldtr));

        VmxVmWrite(VMCS_GUEST_ES_LIMIT, __segmentlimit(es.AsUInt));
        VmxVmWrite(VMCS_GUEST_CS_LIMIT, __segmentlimit(cs.AsUInt));
        VmxVmWrite(VMCS_GUEST_SS_LIMIT, __segmentlimit(ss.AsUInt));
        VmxVmWrite(VMCS_GUEST_DS_LIMIT, __segmentlimit(ds.AsUInt));
        VmxVmWrite(VMCS_GUEST_FS_LIMIT, __segmentlimit(fs.AsUInt));
        VmxVmWrite(VMCS_GUEST_GS_LIMIT, __segmentlimit(gs.AsUInt));
        VmxVmWrite(VMCS_GUEST_TR_LIMIT, __segmentlimit(tr.AsUInt));
        VmxVmWrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(ldtr.AsUInt));

        VmxVmWrite(VMCS_GUEST_ES_ACCESS_RIGHTS, __segmentar(&es));
        VmxVmWrite(VMCS_GUEST_CS_ACCESS_RIGHTS, __segmentar(&cs));
        VmxVmWrite(VMCS_GUEST_SS_ACCESS_RIGHTS, __segmentar(&ss));
        VmxVmWrite(VMCS_GUEST_DS_ACCESS_RIGHTS, __segmentar(&ds));
        VmxVmWrite(VMCS_GUEST_FS_ACCESS_RIGHTS, __segmentar(&fs));
        VmxVmWrite(VMCS_GUEST_GS_ACCESS_RIGHTS, __segmentar(&gs));
        VmxVmWrite(VMCS_GUEST_TR_ACCESS_RIGHTS, __segmentar(&tr));
        VmxVmWrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, __segmentar(&ldtr));

        VmxVmWrite(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
        VmxVmWrite(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);
        VmxVmWrite(VMCS_GUEST_GDTR_BASE, gdtr.BaseAddress);
        VmxVmWrite(VMCS_GUEST_IDTR_BASE, idtr.BaseAddress);

        VmxVmWrite(VMCS_GUEST_VMCS_LINK_POINTER, MAXULONG_PTR);

        VmxVmWrite(VMCS_GUEST_CR0, __readcr0());
        VmxVmWrite(VMCS_GUEST_CR3, __readcr3());
        VmxVmWrite(VMCS_GUEST_CR4, __readcr4());

        VmxVmWrite(VMCS_GUEST_RFLAGS, __readeflags());
        VmxVmWrite(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
        VmxVmWrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
        VmxVmWrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
        VmxVmWrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
        VmxVmWrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

        /*
         * Since the goal of this hypervisor is to virtualise and already
         * running operating system, once we initiate VMX, we want to set the
         * RIP and RSP set to the values they were before the core was
         * interrupted by our inter process interrupt. This means once vmx has
         * been initiated, guest operation will continue as normal as if nothing
         * happened.
         */
        VmxVmWrite(VMCS_GUEST_RSP, StackPointer);
        VmxVmWrite(VMCS_GUEST_RIP, VmxRestoreState);
}

BOOLEAN
IsLocalApicPresent()
{
        CPUID_EAX_01 features = {0};
        __cpuid((INT*)&features, CPUID_VERSION_INFORMATION);
        return features.CpuidFeatureInformationEdx.ApicOnChip ? TRUE : FALSE;
}

STATIC
BOOLEAN
IsApicInX2ApicMode()
{
        IA32_APIC_BASE_REGISTER apic = {.AsUInt = __readmsr(IA32_APIC_BASE)};
        return apic.EnableX2ApicMode ? TRUE : FALSE;
}

#define QWORD_BIT_COUNT 64

STATIC
VOID
SetBitInBitmap(_Inout_ PUINT64 Bitmap, _In_ UINT32 Bit)
{
        UINT32 index  = Bit / QWORD_BIT_COUNT;
        UINT32 offset = Bit % QWORD_BIT_COUNT;
        Bitmap[index] |= (1ull << offset);
}

STATIC
VOID
VmcsWriteControlStateFields(_In_ PVIRTUAL_MACHINE_STATE Vcpu)
{
        IA32_APIC_BASE_REGISTER apic = {.AsUInt = __readmsr(IA32_APIC_BASE)};

        /*
         * ActivateSecondaryControls activates the secondary processor-based
         * VM-execution controls. If UseMsrBitmaps is not set, all RDMSR and
         * WRMSR instructions cause vm-exits.
         */
        Vcpu->proc_ctls.ActivateSecondaryControls = TRUE;
        Vcpu->proc_ctls.UseMsrBitmaps             = TRUE;
        Vcpu->proc_ctls.Cr3LoadExiting            = FALSE;
        Vcpu->proc_ctls.Cr3StoreExiting           = FALSE;
        Vcpu->proc_ctls.UnconditionalIoExiting    = FALSE;
        Vcpu->proc_ctls.MovDrExiting              = FALSE;

        /*
         * TPR shadowing is still quite buggy, so to allow us to work on further
         * apic features we enable it aswell. (This is because TPR shadowing is
         * required for further APIC virtualisation features.
         */
#if APIC
        /*
         * Currently LoadExiting is failing when false, StoreExiting works when
         * false.
         */
        Vcpu->proc_ctls.Cr8LoadExiting  = FALSE;
        Vcpu->proc_ctls.Cr8StoreExiting = FALSE;
#endif

#if APIC
        if (IsLocalApicPresent()) {
                Vcpu->proc_ctls.UseTprShadow = TRUE;
                VmxVmWrite(VMCS_CTRL_VIRTUAL_APIC_ADDRESS,
                           Vcpu->virtual_apic_pa);
                VmxVmWrite(VMCS_CTRL_TPR_THRESHOLD, VMX_APIC_TPR_THRESHOLD);
        }
#endif
        VmxVmWrite(
            VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            AdjustMsrControl(Vcpu->proc_ctls.AsUInt, IA32_VMX_PROCBASED_CTLS));

        Vcpu->proc_ctls2.EnableRdtscp  = TRUE;
        Vcpu->proc_ctls2.EnableInvpcid = TRUE;
        Vcpu->proc_ctls2.EnableXsaves  = TRUE;

#if APIC
        if (IsLocalApicPresent()) {
                Vcpu->proc_ctls2.ApicRegisterVirtualization = FALSE;
                Vcpu->proc_ctls2.VirtualInterruptDelivery   = FALSE;

                /*
                 * If we are in X2 Apic Mode, disable MMIO apic register
                 * access virtualization, and instead enable X2 Apic
                 * Virtualization.
                 */
                if (IsApicInX2ApicMode()) {
                        Vcpu->proc_ctls2.VirtualizeX2ApicMode = FALSE;
                }
                else {
                        Vcpu->proc_ctls2.VirtualizeApicAccesses = TRUE;
                        VmxVmWrite(VMCS_CTRL_APIC_ACCESS_ADDRESS,
                                   apic.ApicBase);
                }

                // VmxVmWrite(VMCS_CTRL_EOI_EXIT_BITMAP_0, 0);
                // VmxVmWrite(VMCS_CTRL_EOI_EXIT_BITMAP_1, 0);
                // VmxVmWrite(VMCS_CTRL_EOI_EXIT_BITMAP_2, 0);
                // VmxVmWrite(VMCS_CTRL_EOI_EXIT_BITMAP_3, 0);
        }
#endif

        VmxVmWrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                   AdjustMsrControl(Vcpu->proc_ctls2.AsUInt,
                                    IA32_VMX_PROCBASED_CTLS2));

        Vcpu->pin_ctls.NmiExiting = FALSE;
#if APIC
        Vcpu->pin_ctls.ProcessPostedInterrupts = FALSE;
#endif

        VmxVmWrite(
            VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
            AdjustMsrControl(Vcpu->pin_ctls.AsUInt, IA32_VMX_PINBASED_CTLS));

        Vcpu->exit_ctls.AcknowledgeInterruptOnExit = TRUE;
        Vcpu->exit_ctls.HostAddressSpaceSize       = TRUE;
        Vcpu->exit_ctls.SaveDebugControls          = TRUE;

        VmxVmWrite(
            VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS,
            AdjustMsrControl(Vcpu->exit_ctls.AsUInt, IA32_VMX_EXIT_CTLS));

        Vcpu->entry_ctls.Ia32EModeGuest    = TRUE;
        Vcpu->entry_ctls.LoadDebugControls = TRUE;

        VmxVmWrite(
            VMCS_CTRL_VMENTRY_CONTROLS,
            AdjustMsrControl(Vcpu->entry_ctls.AsUInt, IA32_VMX_ENTRY_CTLS));

        Vcpu->exception_bitmap |= EXCEPTION_DIVIDED_BY_ZERO;

        VmxVmWrite(VMCS_CTRL_EXCEPTION_BITMAP, Vcpu->exception_bitmap);
        VmxVmWrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, Vcpu->msr_bitmap_pa);
}

NTSTATUS
SetupVmcs(_In_ PVIRTUAL_MACHINE_STATE GuestState, _In_ PVOID StackPointer)
{
        UCHAR status = 0;

        status = __vmx_vmclear(&GuestState->vmcs_region_pa);

        if (!VMX_OK(status)) {
                DEBUG_ERROR("__vmx_vmclear failed with status %x", status);
                return STATUS_UNSUCCESSFUL;
        }

        status = __vmx_vmptrld(&GuestState->vmcs_region_pa);

        if (!VMX_OK(status)) {
                if (status == VMX_STATUS_OPERATION_FAILED) {
                        DEBUG_ERROR("__vmx_vmptrld failed with status: %llx",
                                    VmxVmRead(VMCS_VM_INSTRUCTION_ERROR));
                        return STATUS_UNSUCCESSFUL;
                }
                else {
                        DEBUG_ERROR("__vmx_vmptrld failed with no status.");
                        return STATUS_UNSUCCESSFUL;
                }
        }

        VmcsWriteControlStateFields(GuestState);
        VmcsWriteGuestStateFields(StackPointer, GuestState);
        VmcsWriteHostStateFields(GuestState);

        return STATUS_SUCCESS;
}