; RuntimeStr.asm - Thread-safe runtime string configuration provider by WESMAR
; Provides configuration strings for kernel operations with atomic initialization
; Uses XOR encoding to avoid static string detection in binary analysis
; Thread-safe: First caller decodes, others wait via spinlock

.data
ALIGN 8
; XOR-encoded wide string data (key: 0ABh)
; Decoded at runtime to prevent static analysis detection
g_EncodedData    dw 00F9h, 00FFh, 00E8h, 00C4h, 00D9h, 00CEh, 009Dh, 009Fh, 00ABh

; XOR decoding key for runtime string reconstruction
g_XorKey         dw 00ABh

; Static buffer for decoded wide string (9 wide chars including null terminator)
g_DecodedBuffer  dw 9 dup(0)

; Atomic initialization flag for thread-safe decode
; States: 0 = not initialized, 1 = initialization in progress, 2 = initialization complete
g_Flag           db 0
ALIGN 8

.code
ALIGN 16
PUBLIC GetServiceNameRaw

; Runtime string decoder for kernel driver service configuration
; Decodes XOR-obfuscated wide string to prevent static string analysis
; Returns: RAX = Pointer to decoded null-terminated wide string (const wchar_t*)
; Thread-safety: Atomic compare-and-swap ensures single initialization, spinlock for waiters
; Performance: First call decodes, subsequent calls return immediately
GetServiceNameRaw PROC
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 20h              ; Allocate shadow space for x64 calling convention

    ; Atomic attempt to acquire initialization (compare-and-swap 0->1)
    xor     eax, eax              ; Expected value = 0 (not initialized)
    mov     cl, 1                 ; New value = 1 (in progress)
    lock cmpxchg byte ptr g_Flag, cl
    jz      do_decode             ; ZF=1: we won the race, perform decode

    ; Another thread is initializing - spin until complete
wait_init:
    cmp     byte ptr g_Flag, 2
    je      done
    pause                         ; CPU hint for spinlock efficiency
    jmp     wait_init

do_decode:
    ; XOR decode operation (only one thread executes this)
    lea     rsi, g_EncodedData      ; Source: encoded data
    lea     rdi, g_DecodedBuffer    ; Destination: decoded buffer
    mov     rcx, 9                   ; String length including null terminator
    movzx   ebx, word ptr g_XorKey  ; Load XOR key into register

decode_loop:
    ; XOR decode: encoded_char XOR key = original_char
    movzx   eax, word ptr [rsi]     ; Load encoded wide character
    xor     ax, bx                   ; Apply XOR decoding
    mov     word ptr [rdi], ax       ; Store decoded character
    
    ; Advance pointers to next wide character
    add     rsi, 2                   ; Next wide char (2 bytes)
    add     rdi, 2
    dec     rcx
    jnz     decode_loop              ; Continue until all characters decoded

    ; Optional: Memory fence for strict memory ordering guarantee
    ; mfence
    
    ; Mark initialization as complete (atomic store)
    mov     byte ptr g_Flag, 2

done:
    ; Return pointer to decoded string
    lea     rax, g_DecodedBuffer

    ; Restore stack and non-volatile registers
    add     rsp, 20h
    pop     rsi
    pop     rdi
    pop     rbx
    ret
GetServiceNameRaw ENDP
END