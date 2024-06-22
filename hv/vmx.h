#ifndef VMX_H
#define VMX_H

#include "driver.h"
#include "ia32.h"
#include "lock.h"

typedef struct _DPC_CALL_CONTEXT {
        EPT_POINTER* eptp;
        PVOID        guest_stack;
        NTSTATUS*    status;
        UINT32       status_count;

} DPC_CALL_CONTEXT, *PDPC_CALL_CONTEXT;

typedef struct _CPUID_CACHE {
        INT32            value[4];
        volatile BOOLEAN active;

} CPUID_CACHE, *PCPUID_CACHE;

/*
 * This structure will act as the per-cpu cache for commonly accessed items
 * such as CPUID result as this won't change.
 */
typedef struct _VMM_CACHE {
        CPUID_CACHE cpuid;

} VMM_CACHE, *PVMM_CACHE;

/*
 * Stores information related to exiting vmx operation
 */
typedef struct _EXIT_STATE {
        UINT64  guest_rip;
        UINT64  guest_rsp;
        UINT64  guest_debug_ctl;
        BOOLEAN exit_vmx;

} EXIT_STATE, *PEXIT_STATE;

#define VMX_VCPU_STATE_OFF        0
#define VMX_VCPU_STATE_RUNNING    1
#define VMX_VCPU_STATE_TERMINATED 2

typedef enum _VCPU_STATE { off, running, terminated } VCPU_STATE;

#define VMX_LOG_BUFFER_SIZE          0x100000
#define VMX_INIDIVIDUAL_LOG_MAX_SIZE 0x100
#define VMX_MAX_LOG_ENTRIES_COUNT \
        VMX_LOG_BUFFER_SIZE / VMX_INIDIVIDUAL_LOG_MAX_SIZE
#define VMX_LOG_BUFFER_POOL_TAG 'rgol'

#define VMX_APIC_TPR_THRESHOLD 0

typedef struct _VCPU_LOG_STATE {
        volatile HIGH_IRQL_LOCK lock;
        /*
         * Given that our core flushing mechanism only flushes when the buffer
         * is full, lets create a timer that flushes the logs every X period
         * regardless of the state of the buffer.
         */
        KTIMER          timer;
        KDPC            dpc;
        PVOID           log_buffer;
        volatile UINT32 current_log_count;

} VCPU_LOG_STATE, *PVCPU_LOG_STATE;

typedef struct _GUEST_CONTEXT {
        UINT64 dr7;
        UINT64 dr6;
        UINT64 dr3;
        UINT64 dr2;
        UINT64 dr1;
        UINT64 dr0;
        M128A  Xmm0;
        M128A  Xmm1;
        M128A  Xmm2;
        M128A  Xmm3;
        M128A  Xmm4;
        M128A  Xmm5;
        M128A  Xmm6;
        M128A  Xmm7;
        M128A  Xmm8;
        M128A  Xmm9;
        M128A  Xmm10;
        M128A  Xmm11;
        M128A  Xmm12;
        M128A  Xmm13;
        M128A  Xmm14;
        M128A  Xmm15;
        UINT64 rax;
        UINT64 rcx;
        UINT64 rdx;
        UINT64 rbx;
        UINT64 rsp;
        UINT64 rbp;
        UINT64 rsi;
        UINT64 rdi;
        UINT64 r8;
        UINT64 r9;
        UINT64 r10;
        UINT64 r11;
        UINT64 r12;
        UINT64 r13;
        UINT64 r14;
        UINT64 r15;
        UINT64 rflags;

} GUEST_CONTEXT, *PGUEST_CONTEXT;

static_assert(sizeof(GUEST_CONTEXT) == 0x01c0, "sizeof(GUEST_CONTEXT) not valid.");

typedef struct _MSR_BITMAP {
        UINT8 msr_low_read[1000];
        UINT8 msr_high_read[1000];
        UINT8 msr_low_write[1000];
        UINT8 msr_high_write[1000];
} MSR_BITMAP, *PMSR_BITMAP;

typedef struct _HOST_DEBUG_STATE {
        UINT64 dr0;
        UINT64 dr1;
        UINT64 dr2;
        UINT64 dr3;
        UINT64 dr6;
        UINT64 dr7;
        UINT64 debug_ctl;

} HOST_DEBUG_STATE, *PHOST_DEBUG_STATE;

typedef struct _VIRTUAL_MACHINE_STATE {
        VCPU_STATE                        state;
        VMM_CACHE                         cache;
        EXIT_STATE                        exit_state;
        PGUEST_CONTEXT                    guest_context;
        UINT64                            vmxon_region_pa;
        UINT64                            vmxon_region_va;
        UINT64                            vmcs_region_pa;
        UINT64                            vmcs_region_va;
        UINT64                            eptp_va;
        UINT64                            vmm_stack_va;
        PMSR_BITMAP                       msr_bitmap_va;
        PMSR_BITMAP                       msr_bitmap_pa;
        UINT64                            virtual_apic_va;
        UINT64                            virtual_apic_pa;
        UINT32                            exception_bitmap;
        UINT32                            exception_bitmap_mask;
        HOST_DEBUG_STATE                  debug_state;
        IA32_VMX_PROCBASED_CTLS_REGISTER  proc_ctls;
        IA32_VMX_PROCBASED_CTLS2_REGISTER proc_ctls2;
        IA32_VMX_PINBASED_CTLS_REGISTER   pin_ctls;
        IA32_VMX_EXIT_CTLS_REGISTER       exit_ctls;
        IA32_VMX_ENTRY_CTLS_REGISTER      entry_ctls;
#ifdef DEBUG
        VCPU_LOG_STATE log_state;
#endif

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

#define SET_FLAG_U32(n) (1U << (n))

extern PVIRTUAL_MACHINE_STATE vmm_state;

typedef struct _DRIVER_STATE {
        PVOID             power_callback;
        PCALLBACK_OBJECT  power_callback_object;
        //EPT_CONFIGURATION ept_configuration;

} DRIVER_STATE, *PDRIVER_STATE;

typedef union {
        struct {
                UINT32 TaskPriorityRegisterThreshold : 4;
                UINT32 VirtualTaskPriorityRegister : 7;
                UINT32 Unused2 : 32;
        };

        UINT32 AsUInt;
} VTPR, *PVTPR;

VOID
InitialiseVmxOperation(_In_ PKDPC*    Dpc,
                       _In_opt_ PVOID DeferredContext,
                       _In_opt_ PVOID SystemArgument1,
                       _In_opt_ PVOID SystemArgument2);

NTSTATUS
BeginVmxOperation(_In_ PDPC_CALL_CONTEXT Context);

NTSTATUS
BroadcastVmxTermination();

VOID
VirtualizeCore(_In_ PDPC_CALL_CONTEXT Context, _In_ PVOID StackPointer);

NTSTATUS
SetupVmxOperation();

NTSTATUS
InitialisePowerCallback();

NTSTATUS
AllocateDriverState();

VOID
FreeVmxState();

VOID
FreeGlobalVmmState();

VOID
FreeGlobalDriverState();

VOID
UnregisterPowerCallback();

#endif