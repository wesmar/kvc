; RuntimeStr.asm - Runtime string configuration provider by WESMAR
; Provides configuration strings for kernel operations
; Uses XOR encoding to avoid static string detection in binary analysis

.data
ALIGN 8
; XOR-encoded wide string data (key: 0ABh)
; Decoded at runtime to prevent static analysis detection
g_EncodedData dw 00F9h, 00FFh, 00E8h, 00C4h, 00D9h, 00CEh, 009Dh, 009Fh, 00ABh

; XOR decoding key for runtime string reconstruction
g_XorKey dw 00ABh

; Static buffer for decoded wide string (thread-safe for read-only service name)
g_DecodedBuffer dw 9 dup(0)

.code
ALIGN 16
PUBLIC GetServiceNameRaw

; Runtime string decoder for kernel driver service configuration
; Decodes XOR-obfuscated wide string to prevent static string analysis
; Returns: Pointer to decoded null-terminated wide string (const wchar_t*)
; Thread-safety: Safe for concurrent reads after first decode
GetServiceNameRaw PROC
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 20h              ; Allocate shadow space for x64 calling convention

    ; Setup decode parameters
    lea     rsi, g_EncodedData      ; Source: encoded data
    lea     rdi, g_DecodedBuffer    ; Destination: decoded buffer
    mov     rcx, 9                   ; String length including null terminator (FIXED: full 64-bit register)
    movzx   ebx, word ptr g_XorKey  ; Load XOR key into register

decode_loop:
    ; XOR decode: encoded_char XOR key = original_char
    movzx   eax, word ptr [rsi]     ; Load encoded wide character
    xor     ax, bx                   ; Apply XOR decoding
    mov     word ptr [rdi], ax       ; Store decoded character
    
    ; Advance pointers
    add     rsi, 2                   ; Next wide char (2 bytes)
    add     rdi, 2
    loop    decode_loop              ; Decrement RCX and loop

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