; ==============================================================================
; ExplorerFrame DLL - Entry Point and Global Pattern Table
;
; Author: Marek Wesołowski (wesmar)
; Purpose: DllMain coordinates initialization on first process attach:
;          allocates branding pattern buffers, loads strings, patches IAT.
;          g_brandingPatterns holds the 7 QWORD pointers used by intercept.asm.
; ==============================================================================

option casemap:none

include consts.inc
; globals.inc not included here - this module IS the definition of g_brandingPatterns

EXTRN DisableThreadLibraryCalls         :PROC
EXTRN GetModuleHandleW                  :PROC
EXTRN InitializeBrandingPatterns        :PROC
EXTRN PatchShell32Imports               :PROC

; ==============================================================================
; INITIALIZED DATA
; ==============================================================================
.data
    align 8

; Seven QWORD pointers - NULL until InitializeBrandingPatterns fills them.
PUBLIC g_brandingPatterns
g_brandingPatterns  dq BRANDING_PATTERN_COUNT dup(0)

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

str_shell32     dw 's','h','e','l','l','3','2','.','d','l','l',0

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; DllMain - DLL Entry Point
;
; RCX = hModule
; EDX = ul_reason_for_call
; R8  = lpReserved
;
; Returns EAX = TRUE (1) always.
; ==============================================================================
PUBLIC DllMain
DllMain proc frame
    push    rbx
    .pushreg rbx
    sub     rsp, 20h        ; 1 push (odd) → rsp%16=0; sub 20h (32%16=0) → rsp%16=0 ✓
    .allocstack 20h
    .endprolog

    mov     rbx, rcx                        ; save hModule
    cmp     edx, DLL_PROCESS_ATTACH
    jne     @dm_done

    ; Suppress DLL_THREAD_ATTACH / DETACH notifications
    mov     rcx, rbx
    sub     rsp, 20h
    call    DisableThreadLibraryCalls
    add     rsp, 20h

    ; Locate shell32.dll (already loaded in explorer.exe)
    lea     rcx, str_shell32
    sub     rsp, 20h
    call    GetModuleHandleW
    add     rsp, 20h
    test    rax, rax
    jz      @dm_done

    ; Allocate buffers and fill branding patterns
    mov     rcx, rax
    sub     rsp, 20h
    call    InitializeBrandingPatterns
    add     rsp, 20h

    ; Hook LoadStringW and ExtTextOutW in shell32.dll's IAT
    sub     rsp, 20h
    call    PatchShell32Imports
    add     rsp, 20h

@dm_done:
    mov     eax, 1
    add     rsp, 20h
    pop     rbx
    ret
DllMain endp

end
