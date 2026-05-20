; ==============================================================================
; ExplorerFrame DLL - Branding Pattern Initialization
;
; Author: Marek Wesołowski (wesmar)
; Purpose: Allocates heap buffers for 14 pattern slots, then populates them:
;   [0]   BrandingLoadString(L"Basebrd", 12, ...)  from winbrand.dll
;         Falls back to L"Windows " on failure.
;   [1-13] LoadStringW(hShell32, resource_id, ...) for IDs:
;         33088 33089 33108 33109 33111 33117
;         33094 33110 33112 33118 33120 33121 33123
;         Falls back to L"Build " on failure.
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN GetProcessHeap        :PROC
EXTRN HeapAlloc             :PROC
EXTRN LoadLibraryW          :PROC
EXTRN FreeLibrary           :PROC
EXTRN GetProcAddress        :PROC
EXTRN LoadStringW           :PROC
EXTRN wcscpy_p              :PROC

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

str_winbrand        dw 'w','i','n','b','r','a','n','d','.','d','l','l',0
str_basebrd         dw 'B','a','s','e','b','r','d',0
str_BrandLoadStr    db 'BrandingLoadString',0  ; ASCII for GetProcAddress
str_defWindows      dw 'W','i','n','d','o','w','s',' ',0
str_defBuild        dw 'B','u','i','l','d',' ',0

; ==============================================================================
; INITIALIZED DATA
; ==============================================================================
.data
    align 4

; Shell32 resource IDs for patterns[1..13]
shell32_ids     dd SHELL32_ID_0,  SHELL32_ID_1,  SHELL32_ID_2
                dd SHELL32_ID_3,  SHELL32_ID_4,  SHELL32_ID_5
                dd SHELL32_ID_6,  SHELL32_ID_7,  SHELL32_ID_8
                dd SHELL32_ID_9,  SHELL32_ID_10, SHELL32_ID_11
                dd SHELL32_ID_12

; Buffer sizes in WCHARs for all 14 pattern slots
pat_wcssizes    dd PBUFSZ_0,  PBUFSZ_1,  PBUFSZ_2,  PBUFSZ_3
                dd PBUFSZ_4,  PBUFSZ_5,  PBUFSZ_6,  PBUFSZ_7
                dd PBUFSZ_8,  PBUFSZ_9,  PBUFSZ_10, PBUFSZ_11
                dd PBUFSZ_12, PBUFSZ_13

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; HAlloc - Heap allocation helper
;
; RCX = byte count
; Returns RAX = pointer, or NULL on failure
; ==============================================================================
HAlloc proc
    push    rbx
    sub     rsp, 20h

    mov     rbx, rcx            ; save byte count
    call    GetProcessHeap
    mov     rcx, rax            ; hHeap
    xor     edx, edx            ; dwFlags = 0
    mov     r8, rbx             ; dwBytes
    call    HeapAlloc

    add     rsp, 20h
    pop     rbx
    ret
HAlloc endp

; ==============================================================================
; InitializeBrandingPatterns
;
; RCX = hShell32 (HMODULE)  - may be NULL if shell32 not available
;
; Non-volatile registers:
;   rbx = scratch
;   rsi = &pat_wcssizes
;   rdi = &g_brandingPatterns
;   r12 = hShell32
;   r13 = loop counter
;   r14 = hWinBrand
;   r15 = pfnBrandingLoadString
;
; Stack: 7 pushes + sub 20h: entry rsp%16=8, 7×8=56 → 0 mod16, sub 20h → 0 ✓
; ==============================================================================
PUBLIC InitializeBrandingPatterns
InitializeBrandingPatterns proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h

    mov     r12, rcx                        ; r12 = hShell32
    lea     rsi, pat_wcssizes               ; rsi = WCHAR-size table
    lea     rdi, g_brandingPatterns         ; rdi = pattern pointer table

    ; ------------------------------------------------------------------
    ; Phase 1: allocate heap buffers for all 7 slots
    ; ------------------------------------------------------------------
    xor     r13d, r13d

@ibp_alloc:
    cmp     r13d, BRANDING_PATTERN_COUNT
    jge     @ibp_winbrand

    mov     ecx, [rsi + r13*4]             ; WCHAR count
    shl     ecx, 1                          ; → byte count (* 2)
    call    HAlloc
    mov     [rdi + r13*8], rax              ; store (NULL if allocation failed)

    inc     r13d
    jmp     @ibp_alloc

    ; ------------------------------------------------------------------
    ; Phase 2: load patterns[0] from winbrand.dll BrandingLoadString
    ; ------------------------------------------------------------------
@ibp_winbrand:
    lea     rcx, str_winbrand
    sub     rsp, 20h
    call    LoadLibraryW
    add     rsp, 20h
    test    rax, rax
    jz      @ibp_no_winbrand
    mov     r14, rax                        ; r14 = hWinBrand

    mov     rcx, r14
    lea     rdx, str_BrandLoadStr           ; ASCII proc name
    sub     rsp, 20h
    call    GetProcAddress
    add     rsp, 20h
    test    rax, rax
    jz      @ibp_winbrand_free
    mov     r15, rax                        ; r15 = pfnBrandingLoadString

    mov     rbx, [rdi]                      ; g_brandingPatterns[0]
    test    rbx, rbx
    jz      @ibp_winbrand_free              ; buffer not allocated

    ; BrandingLoadString(L"Basebrd", 12, buf, 128)
    lea     rcx, str_basebrd
    mov     edx, BRANDING_COMPONENT_ID      ; 12
    mov     r8, rbx                         ; output buffer
    mov     r9d, PBUFSZ_0                   ; 128 WCHARs max
    sub     rsp, 20h
    call    r15
    add     rsp, 20h
    test    eax, eax
    jnz     @ibp_winbrand_free              ; non-zero = success

    ; BrandingLoadString failed → copy default L"Windows "
    mov     rcx, [rdi]
    lea     rdx, str_defWindows
    call    wcscpy_p
    jmp     @ibp_winbrand_free

@ibp_no_winbrand:
    ; winbrand.dll unavailable → default for slot 0
    mov     rcx, [rdi]
    test    rcx, rcx
    jz      @ibp_shell32
    lea     rdx, str_defWindows
    call    wcscpy_p
    jmp     @ibp_shell32

@ibp_winbrand_free:
    mov     rcx, r14
    sub     rsp, 20h
    call    FreeLibrary
    add     rsp, 20h

    ; ------------------------------------------------------------------
    ; Phase 3: load patterns[1..6] from shell32.dll resources
    ; ------------------------------------------------------------------
@ibp_shell32:
    test    r12, r12
    jz      @ibp_fallback_all               ; no shell32 → defaults

    xor     r13d, r13d                      ; shell32 slot index 0..5
    lea     rbx, shell32_ids

@ibp_shell32_loop:
    cmp     r13d, SHELL32_PATTERN_COUNT
    jge     @ibp_done

    ; g_brandingPatterns[r13+1] = target buffer
    mov     rax, r13
    inc     rax
    mov     r15, [rdi + rax*8]
    test    r15, r15
    jz      @ibp_shell32_next               ; slot not allocated

    ; LoadStringW(hShell32, shell32_ids[r13], buf, WCHAR_count)
    mov     rcx, r12
    mov     edx, [rbx + r13*4]             ; resource ID
    mov     r8, r15                         ; buffer
    mov     rax, r13
    inc     rax
    mov     r9d, [rsi + rax*4]             ; WCHAR count for this slot
    sub     rsp, 20h
    call    LoadStringW
    add     rsp, 20h
    test    eax, eax
    jnz     @ibp_shell32_next               ; loaded OK

    ; LoadStringW returned 0 → fill default L"Build "
    mov     rax, r13
    inc     rax
    mov     rcx, [rdi + rax*8]
    lea     rdx, str_defBuild
    call    wcscpy_p

@ibp_shell32_next:
    inc     r13d
    jmp     @ibp_shell32_loop

    ; no shell32 → fill all 6 remaining slots with L"Build "
@ibp_fallback_all:
    xor     r13d, r13d

@ibp_fallback_loop:
    cmp     r13d, SHELL32_PATTERN_COUNT
    jge     @ibp_done

    mov     rax, r13
    inc     rax
    mov     rcx, [rdi + rax*8]
    test    rcx, rcx
    jz      @ibp_fallback_next
    lea     rdx, str_defBuild
    call    wcscpy_p

@ibp_fallback_next:
    inc     r13d
    jmp     @ibp_fallback_loop

@ibp_done:
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
InitializeBrandingPatterns endp

end
