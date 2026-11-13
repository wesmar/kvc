; AbiTramp.asm - Windows x64 ABI transition trampoline for direct syscalls
; Provides syscall argument marshaling and execution for security operations
; Implements position-independent syscall invocation with proper stack management

.code
ALIGN 16
PUBLIC AbiTramp

; Direct syscall execution trampoline with argument marshaling
; Parameters: SYSCALL_ENTRY* (RCX), followed by up to 10 additional syscall arguments
; Returns: NTSTATUS from kernel syscall execution
AbiTramp PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 88h              ; Allocate stack space: shadow space (0x20) + argument buffer (0x68) -> RSP % 16 == 0
    .ENDPROLOG

    mov     rbx, rcx              ; Preserve SYSCALL_ENTRY* pointer in non-volatile register

    ; Marshal register-based arguments for kernel transition (Windows x64 calling convention)
    mov     r10, rdx              ; Syscall-Arg1 <- Function-Arg2 (first syscall parameter)
    mov     rdx, r8               ; Syscall-Arg2 <- Function-Arg3 (second syscall parameter)
    mov     r8, r9                ; Syscall-Arg3 <- Function-Arg4 (third syscall parameter)

    ; Only read 4th syscall argument from caller stack if nArgs >= 4
    cmp     dword ptr [rbx+8], 3  ; Check if nArgs > 3
    jbe     no_stack_args
    mov     r9, [rbp+30h]         ; Syscall-Arg4 <- Function-Arg5 (fourth syscall parameter from caller stack)

    ; Check if there are stack arguments (nArgs > 4)
    cmp     dword ptr [rbx+8], 4
    jbe     no_stack_args

    ; Marshal only missing arguments 5..N (nArgs - 4 qwords)
    mov     ecx, dword ptr [rbx+8]
    sub     ecx, 4                ; Number of stack arguments to copy
    lea     rsi, [rbp+38h]        ; Source: Function-Arg6 position in caller's stack frame
    lea     rdi, [rsp+20h]        ; Destination: Shadow space + syscall stack arguments area
    rep     movsq                 ; Copy only required arguments

no_stack_args:
    ; Prepare for kernel mode transition
    movzx   eax, word ptr [rbx+12] ; Load System Service Number (SSN) from SYSCALL_ENTRY structure
    mov     r11, [rbx]             ; Load syscall gadget address from SYSCALL_ENTRY structure

    call    r11                    ; Execute syscall gadget (syscall; ret instruction sequence)

    ; Function epilogue: restore stack frame and non-volatile registers
    add     rsp, 88h              ; Deallocate local stack space (symmetric to sub rsp, 88h)
    pop     rsi                   ; Restore non-volatile registers in reverse order
    pop     rdi
    pop     rbx
    pop     rbp
    ret                           ; Return NTSTATUS in RAX to caller
AbiTramp ENDP
END