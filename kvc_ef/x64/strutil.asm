; ==============================================================================
; ExplorerFrame DLL - Wide-Character String Utilities
;
; Author: Marek Wesołowski (wesmar)
; Purpose: CRT-free wide string helpers. No external dependencies.
;
; Exported routines:
;   wcslen_p     - length of null-terminated wide string (in WCHARs)
;   wcscpy_p     - copy null-terminated wide string
;   WideStrFind  - find wide substring inside wide string
; ==============================================================================

option casemap:none

.code

; ==============================================================================
; wcslen_p - Wide string length
;
; RCX = source string (LPCWSTR)
; Returns RAX = character count (excluding null terminator)
; ==============================================================================
PUBLIC wcslen_p
wcslen_p proc
    xor     rax, rax
@@:
    cmp     word ptr [rcx + rax*2], 0
    je      @F
    inc     rax
    jmp     @B
@@:
    ret
wcslen_p endp

; ==============================================================================
; wcscpy_p - Wide string copy
;
; RCX = destination buffer (LPWSTR)
; RDX = source string (LPCWSTR)
; Returns nothing
; Modifies: RAX, RDI, RSI (saved/restored)
; ==============================================================================
PUBLIC wcscpy_p
wcscpy_p proc
    push    rsi
    push    rdi
    mov     rdi, rcx
    mov     rsi, rdx
@@:
    mov     ax, word ptr [rsi]
    mov     word ptr [rdi], ax
    test    ax, ax
    jz      @F
    add     rsi, 2
    add     rdi, 2
    jmp     @B
@@:
    pop     rdi
    pop     rsi
    ret
wcscpy_p endp

; ==============================================================================
; WideStrFind - Find wide substring in wide string
;
; Naive O(n*m) search. Used only on short strings, so performance is fine.
;
; RCX  = haystack (LPCWSTR)
; EDX  = haystackLen (INT, in WCHARs)
; R8   = needle (LPCWSTR) - pointer to start of substring to find
; R9D  = needleLen (INT, in WCHARs)
;
; Returns EAX = 0 if found, -1 (0xFFFFFFFF) if not found
;   (mirrors: found → true, not found → false for the caller)
;
; Modifies: RAX, RBX, RCX, RSI, RDI (RBX, RSI, RDI saved/restored)
; ==============================================================================
PUBLIC WideStrFind
WideStrFind proc
    push    rbx
    push    rsi
    push    rdi
    ; 3 pushes (odd) → rsp%16=0 after pushes. No further calls → leaf, no sub rsp.

    ; Trivial rejection
    test    r9d, r9d
    jz      @wsf_found              ; empty needle → always found
    test    edx, edx
    jz      @wsf_notfound
    cmp     r9d, edx
    jg      @wsf_notfound           ; needle longer than haystack

    mov     rdi, rcx               ; rdi = haystack base
    mov     rsi, r8                ; rsi = needle base
    movsxd  rbx, edx               ; rbx = haystackLen (sign-extend INT→QWORD)
    movsxd  rcx, r9d               ; rcx = needleLen

    sub     rbx, rcx               ; rbx = haystackLen - needleLen (max start idx)

    xor     eax, eax               ; eax = outer index i

@wsf_outer:
    cmp     rax, rbx
    jg      @wsf_notfound

    ; Compute base pointer for haystack[i] to avoid double-index addressing.
    ; x86-64 allows only one scaled index register per memory operand.
    lea     r10, [rdi + rax*2]     ; r10 = &haystack[i]   (r10 is volatile)

    xor     edx, edx               ; edx = inner index j

@wsf_inner:
    cmp     rdx, rcx               ; j >= needleLen?
    jge     @wsf_found             ; all characters matched

    movzx   r8d, word ptr [r10 + rdx*2]   ; haystack[i+j]
    movzx   r9d, word ptr [rsi + rdx*2]   ; needle[j]
    cmp     r8d, r9d
    jne     @wsf_next_i            ; mismatch → try next i

    inc     rdx
    jmp     @wsf_inner

@wsf_next_i:
    inc     rax
    jmp     @wsf_outer

@wsf_found:
    xor     eax, eax               ; 0 = found
    pop     rdi
    pop     rsi
    pop     rbx
    ret

@wsf_notfound:
    or      eax, -1                ; -1 = not found
    pop     rdi
    pop     rsi
    pop     rbx
    ret
WideStrFind endp

end
