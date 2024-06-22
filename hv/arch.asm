title  "Arch"

; Module Name:
;
;   arch.asm
;
; Abstract:
;
;	Implements a variety of Intel x86 specific functions, ranging from custom intrinsic
;	functions to core vmx operations such as exit handling, vmx initiation and vmx 
;	termination.
;

;	The list of custom instrinsic functions. These are required if the Microsoft included
;	intrin.h file does not provide an equivalent intrinsic.

PUBLIC __readcs
PUBLIC __readds
PUBLIC __reades
PUBLIC __readss
PUBLIC __readfs
PUBLIC __readgs
PUBLIC __readldtr
PUBLIC __readtr
PUBLIC __writemsr
PUBLIC __lgdt
PUBLIC __lar
PUBLIC __sgdt

; Wrapper function for the vmcall instruction. 

PUBLIC __vmx_vmcall

; Core vmx handler functions, which include the initiation of vmx operation, handling of 
; vm-exits and termination of vmx operation.

PUBLIC SaveStateAndVirtualizeCore
PUBLIC VmExitHandler
PUBLIC VmxRestoreState

; External functions required to be linked against this file.

EXTERN VmExitDispatcher:PROC
EXTERN VirtualizeCore:PROC
EXTERN VmmReadGuestRip:PROC
EXTERN VmmReadGuestRsp:PROC
EXTERN VmmGetCoresVcpu:PROC
EXTERN LoadHostDebugRegisterState:PROC
EXTERN StoreHostDebugRegisterState:PROC

;	The states that a vcpu can be at.

VMX_VCPU_STATE_OFF        EQU 0
VMX_VCPU_STATE_RUNNING    EQU 1
VMX_VCPU_STATE_TERMINATED EQU 2

.code _text

; 
;	Save general purpose registers to the stack, matching our GUEST_CONTEXT structure
;

SAVE_GP macro

	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8        
	push rdi
	push rsi
	push rbp
	push rbp
	push rbx
	push rdx
	push rcx
	push rax

endm

; 
;	Restores general purpose registers, previously saved via the SAVE_GP macro
;

RESTORE_GP macro

	pop rax
	pop rcx
	pop rdx
	pop rbx
	pop rbp
	pop rbp
	pop rsi
	pop rdi 
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15

endm

;
;	Save the floating point registers to the stack
;
;	Note: Currently we use vmovups which allows us to move an xmm register into an
;		  unaligned memory location which is inefficient. We should align the stack
;		  and use movaps instead.
;

SAVE_FP macro

    sub     rsp, 256
    vmovups xmmword ptr [rsp +  0h], xmm0
    vmovups xmmword ptr [rsp + 10h], xmm1
    vmovups xmmword ptr [rsp + 20h], xmm2
    vmovups xmmword ptr [rsp + 30h], xmm3
    vmovups xmmword ptr [rsp + 40h], xmm4
    vmovups xmmword ptr [rsp + 50h], xmm5
    vmovups xmmword ptr [rsp + 60h], xmm6
    vmovups xmmword ptr [rsp + 70h], xmm7
    vmovups xmmword ptr [rsp + 80h], xmm8
    vmovups xmmword ptr [rsp + 90h], xmm9
    vmovups xmmword ptr [rsp + 160], xmm10
    vmovups xmmword ptr [rsp + 176], xmm11
    vmovups xmmword ptr [rsp + 192], xmm12
    vmovups xmmword ptr [rsp + 208], xmm13
    vmovups xmmword ptr [rsp + 224], xmm14
    vmovups xmmword ptr [rsp + 240], xmm15

endm

;
;	Restore the previously saved floating point registers.
;

RESTORE_FP macro

    vmovups xmm0, xmmword ptr [rsp +  0h]
    vmovups xmm1, xmmword ptr [rsp + 10h]
    vmovups xmm2, xmmword ptr [rsp + 20h]
    vmovups xmm3, xmmword ptr [rsp + 30h]
    vmovups xmm4, xmmword ptr [rsp + 40h]
    vmovups xmm5, xmmword ptr [rsp + 50h]
    vmovups xmm6, xmmword ptr [rsp + 60h]
    vmovups xmm7, xmmword ptr [rsp + 70h]
    vmovups xmm8, xmmword ptr [rsp + 80h]
    vmovups xmm9, xmmword ptr [rsp + 90h]
    vmovups xmm10, xmmword ptr [rsp + 160]
    vmovups xmm11, xmmword ptr [rsp + 176]
    vmovups xmm12, xmmword ptr [rsp + 192]
    vmovups xmm13, xmmword ptr [rsp + 208]
    vmovups xmm14, xmmword ptr [rsp + 224]
    vmovups xmm15, xmmword ptr [rsp + 240]
    add     rsp, 256

endm

;
;	Saves the debug registers
;

SAVE_DEBUG macro

	mov rax, dr7
	push rax
	mov rax, dr6
	push rax
	mov rax, dr3
	push rax
	mov rax, dr2
	push rax
	mov rax, dr1
	push rax
	mov rax, dr0
	push rax

endm

;
;	Restore the debug registers
;

RESTORE_DEBUG macro

	pop rax
	mov dr7, rax
	pop rax
	mov dr6, rax
	pop rax
	mov dr3, rax
	pop rax
	mov dr2, rax
	pop rax
	mov dr1, rax
	pop rax
	mov dr0, rax

endm

;++
;
; VOID
; VmExitHandler ()
;
; Routine Description:
;
;	This routine is jumped to by the CPU on a vm-exit. It handles the saving of
;	guest state, handling of the vm-exit and restoring the guest state. It also 
;	optionally exits vmx operation.
;
; Arguments:
;
;	None.
;
; Return Value:
;
;   None.
;
;--

VmExitHandler PROC

	pushfq
	SAVE_GP	
	SAVE_FP
	SAVE_DEBUG

	; Load the saved host debug register state after saving the guest 
	; debug register state. This ensures 2 things:
	;
	;	1. The guest does not receive leaked host values
	;	2. The continuous debug state remains valid across vmexits
	;	   and entries. (mostly)

	sub rsp, 20h
	call LoadHostDebugRegisterState
	add rsp, 20h

	; first argument for our exit handler is the guest register state, 
	; so store the base of the stack in rcx

	mov rcx, rsp
	sub rsp, 20h			
	CALL VmExitDispatcher		
	add rsp, 20h			

	; check if the return value from our exit dispatcher is 1 (true)

	cmp al, 1			
	je ExitVmx	
	
	; Store the final values of the host debug register state before we restore
	; the guests debug register state. This will allow us to reload the host
	; debug state on the next vmexit.

	sub rsp, 20h
	call StoreHostDebugRegisterState
	add rsp, 20h

	RESTORE_DEBUG
	RESTORE_FP
	RESTORE_GP			
	popfq			

	vmresume					
	
VmExitHandler ENDP

;++
;
; VOID
; ExitVmx (
;	IN PGUEST_CONTEXT Context 
;	)
;
; Routine Description:
;
;	Routine is invoked by our exit handler if we are to exit vmx operation. Will
;	restore the guest state using the Context structure aswell as additional
;	information stored before __vmx_off() was called.
;
; Arguments:
;
;	Context - Guest context structure.
;
; Return Value:
;
;   None.
;
;--

ExitVmx PROC

	push rax	

	; Ensure we set the vcpus status to TERMINATED

	sub rsp, 020h
	call VmmGetCoresVcpu
	add rsp, 020h
	mov [rax], dword ptr VMX_VCPU_STATE_TERMINATED
	pop rax

	; On vmentry, the processor will set the guests RSP and RIP to what
	; was stored in the vmcs at vmexit. Since we have turned off vmx
	; operation this will not occur, hence we must do it manually from
	; state we stored from the vmcs before we exited vmx operation.

	sub rsp, 020h 
	call VmmReadGuestRsp
	add rsp, 020h
	mov [rsp+01c0h], rax

	sub rsp, 020h
	call VmmReadGuestRip
	add rsp, 020h
	mov rdx, rsp
	mov rbx, [rsp+01c0h]
	mov rsp, rbx
	push rax

	; Restore the guests state from the host stack before finally 
	; loading the guests stack back and continuing execution.

	mov rsp, rdx			                 
	sub rbx,08h			
	mov [rsp+01c0h], rbx	

	RESTORE_DEBUG
	RESTORE_FP
	RESTORE_GP			
	popfq		
	pop rsp		
	
	ret				

ExitVmx ENDP

;++
;
; VOID
; SaveStateAndVirtualizeCore ()
;
; Routine Description:
;
;	Store the guests current state and call VirtualizeCore, which will
;	initiate vmx operation on the current core. This routine is executed
;	at IRQL = IPI_LEVEL.
;
; Arguments:
;
;	None.
;
; Return Value:
;
;   None.
;
;--

SaveStateAndVirtualizeCore PROC PUBLIC

	SAVE_GP
	SAVE_FP
	SAVE_DEBUG

	sub rsp, 28h
	mov rdx, rsp
	call VirtualizeCore	

	; We should never reach this ret instruction. If we do, VirtualizeCore will
	; log the error and set the vcpu's vmm_state->state to terminated.

	ret

SaveStateAndVirtualizeCore ENDP 

;++
;
; VOID
; VmxRestoreState ()
;
; Routine Description:
;
;	Restores the initial guest state previously saved via 
;	SaveStateAndVirtualizeCore. At this point we are executing as the guest.
;
; Arguments:
;
;	None.
;
; Return Value:
;
;   None.
;
;--

VmxRestoreState PROC

	add rsp, 28h
	call VmmGetCoresVcpu
	mov [rax], dword ptr VMX_VCPU_STATE_RUNNING

	RESTORE_DEBUG
	RESTORE_FP
	RESTORE_GP
	ret
	
VmxRestoreState ENDP

;++
;
; UINT64
; __readcs ()
;
; Routine Description:
;
;   Reads the value of the CS (Code Segment) register.
;
; Arguments:
;
;   None.
;
; Return Value:
;
;   rax - The value of the CS register.
;
;--

__readcs PROC

    mov rax, cs        
    ret                

__readcs ENDP

;++
;
; UINT64
; __readds ()
;
; Routine Description:
;
;   Reads the value of the DS (Data Segment) register.
;
; Arguments:
;
;   None.
;
; Return Value:
;
;   rax - The value of the DS register.
;
;--

__readds PROC

    mov rax, ds        
    ret                

__readds ENDP

;++
;
; UINT64
; __reades ()
;
; Routine Description:
;
;   Reads the value of the ES (Extra Segment) register.
;
; Arguments:
;
;   None.
;
; Return Value:
;
;	rax - The value of the ES register.
;
;--

__reades PROC

    mov rax, es     
    ret                

__reades ENDP

;++
;
; UINT64
; __readss ()
;
; Routine Description:
;
;   Reads the value of the SS (Stack Segment) register.
;
; Arguments:
;
;   None.
;
; Return Value:
;
;   The value of the SS register.
;
;--

__readss PROC

    mov rax, ss        
    ret                

__readss ENDP

;++
;
; UINT64
; __readfs ()
;
; Routine Description:
;
;   Reads the value of the FS (FS Segment) register.
;
; Arguments:
;
;   None.
;
; Return Value:
;
;   The value of the FS register.
;
;--

__readfs PROC

    mov rax, fs        
    ret               

__readfs ENDP

;++
;
; UINT64
; __readgs ()
;
; Routine Description:
;
;   Reads the value of the GS (GS Segment) register.
;
; Arguments:
;
;   None.
;
; Return Value:
;
;   The value of the GS register.
;
;--

__readgs PROC

    mov rax, gs        
    ret               

__readgs ENDP

;++
;
; UINT64
; __readldtr ()
;
; Routine Description:
;
;   Reads the value of the LDTR (Local Descriptor Table Register) register.
;
; Arguments:
;
;   None.
;
; Return Value:
;
;   The value of the LDTR register.
;
;--

__readldtr PROC

    sldt rax            ; Load the value of the LDTR register into RAX
    ret                ; Return to the caller

__readldtr ENDP

;++
;
; UINT64
; __readtr ()
;
; Routine Description:
;
;   Reads the value of the TR (Task Register) register.
;
; Arguments:
;
;   None.
;
; Return Value:
;
;   The value of the TR register.
;
;--

__readtr PROC

    str rax            
    ret                

__readtr ENDP

;++
;
; VOID
; __writemsr (IN UINT64 Value)
;
; Routine Description:
;
;   Writes the value specified in RDX:RAX to the specified Model-Specific 
;	Register (MSR).
;
; Arguments:
;
;   Value - The value to write to the MSR.
;
; Return Value:
;
;   None.
;
;--

__writemsr PROC

    mov rax, rdx        
    shr rdx, 32        
    wrmsr               
    ret                 

__writemsr ENDP

;++
;
; VOID
; __lgdt (IN PVOID BaseAddress)
;
; Routine Description:
;
;   Loads the Global Descriptor Table (GDT) register with the descriptor table 
;	located at the specified address.
;
; Arguments:
;
;   BaseAddress - The address of the GDT descriptor table.
;
; Return Value:
;
;   None.
;
;--

__lgdt PROC

    lgdt fword ptr [rcx]    
    ret                    

__lgdt ENDP


;++
;
; NTSTATUS INLINE
; __vmx_vmcall(_In_ UINT64 VmCallNumber,
;              _In_ UINT64 OptionalParam1,
;              _In_ UINT64 OptionalParam2,
;              _In_ UINT64 OptionalParam3);
;
; Routine Description:
;
;   Executes a VM call instruction (VMCALL) to transition from VMX non-root operation 
;	to VMX root operation.
;
; Arguments:
;
;   VmcallNumber   - The number specifying the VM call to be made.
;   OptionalParam1 - The first optional parameter for the VM call.
;   OptionalParam2 - The second optional parameter for the VM call.
;   OptionalParam3 - The third optional parameter for the VM call.
;
; Return Value:
;
;   NTSTATUS - The status of the VM call execution.
;
;--

__vmx_vmcall PROC
    
    pushfq      
    vmcall      
    popfq      
    ret         

__vmx_vmcall ENDP

;++
;
; UINT64
; __lar (IN UINT64 Selector)
;
; Routine Description:
;
;   Loads Access Rights byte (AR byte) of a segment descriptor into RAX based 
;	on the selector in RCX.
;
; Arguments:
;
;   Selector - The segment selector to load the access rights rom
;
; Return Value:
;
;   The AR byte of the segment descriptor.
;
;--

__lar PROC

    lar rax, rcx     
    ret              

__lar ENDP

;++
;
; VOID
; __sgdt (IN PVOID BaseAddress)
;
; Routine Description:
;
;   Stores the contents of the Global Descriptor Table (GDT) register at the 
;	specified address.
;
; Arguments:
;
;   BaseAddress - The address where the GDT contents will be stored.
;
; Return Value:
;
;   None.
;
;--

__sgdt PROC
    
    sgdt [rcx]   
    ret           

__sgdt ENDP


END