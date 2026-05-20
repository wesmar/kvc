; ==============================================================================
; ExplorerFrame DLL - COM Entry Point Forwarding Thunks
;
; Author: Marek Wesołowski (wesmar)
; Purpose: Exports DllGetClassObject and DllCanUnloadNow, which are required
;          by COM when our DLL is loaded in place of the system explorerframe.dll
;          (e.g., via DLL search-order hijacking). On first COM call, loads the
;          real System32\explorerframe.dll using the full path obtained from
;          GetSystemDirectoryW, then delegates via tail call.
; ==============================================================================

option casemap:none

include consts.inc

EXTRN GetSystemDirectoryW   :PROC
EXTRN LoadLibraryW          :PROC
EXTRN GetProcAddress        :PROC

E_FAIL                      equ 80004005h   ; generic COM failure HRESULT

; ==============================================================================
; INITIALIZED DATA
; ==============================================================================
.data
    align 8

g_hRealModule   dq 0        ; HMODULE to System32\explorerframe.dll (lazy-loaded)
g_pfnDllGetCO   dq 0        ; DllGetClassObject pointer
g_pfnDllCanUN   dq 0        ; DllCanUnloadNow pointer

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

; Filename appended to system dir (starts with backslash)
str_expframe_dll    dw '\','e','x','p','l','o','r','e','r','f','r','a','m','e','.','d','l','l',0

; ASCII proc names for GetProcAddress
str_DllGetCO        db 'DllGetClassObject',0
str_DllCanUN        db 'DllCanUnloadNow',0

; ==============================================================================
; UNINITIALIZED DATA
; ==============================================================================
.data?
    align 2

; Buffer for GetSystemDirectoryW + "\explorerframe.dll" (300 WCHARs = 600 bytes)
g_sysDirBuf     dw 300 dup(?)

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; EnsureRealModule - Lazy-load System32\explorerframe.dll
;
; Builds full path via GetSystemDirectoryW, calls LoadLibraryW, then resolves
; both COM function pointers. Idempotent: returns immediately if already done.
;
; No parameters. Returns EAX = 1 on success, 0 on failure.
;
; Non-volatile saved: rbx, rsi, rdi
; 3 pushes (odd) → rsp%16=0; sub 20h → rsp%16=0 ✓
; ==============================================================================
EnsureRealModule proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    ; Already initialized?
    cmp     qword ptr [g_hRealModule], 0
    jne     @erm_resolve_ptrs

    ; GetSystemDirectoryW(buf, 260) → char count (without null)
    lea     rcx, g_sysDirBuf
    mov     edx, 260
    call    GetSystemDirectoryW
    test    eax, eax
    jz      @erm_fail

    ; Append \explorerframe.dll at end of system dir string
    movsxd  rbx, eax                   ; rbx = char count of sys dir
    lea     rdi, g_sysDirBuf
    lea     rdi, [rdi + rbx*2]         ; rdi → where null terminator is
    lea     rsi, str_expframe_dll

@erm_cat:
    mov     ax, word ptr [rsi]
    mov     word ptr [rdi], ax
    test    ax, ax
    jz      @erm_load
    add     rsi, 2
    add     rdi, 2
    jmp     @erm_cat

@erm_load:
    ; LoadLibraryW(full_path) - full path bypasses search order
    ; so we always get the System32 copy, not ourselves again
    lea     rcx, g_sysDirBuf
    call    LoadLibraryW
    test    rax, rax
    jz      @erm_fail
    mov     qword ptr [g_hRealModule], rax

@erm_resolve_ptrs:
    ; Resolve DllGetClassObject
    cmp     qword ptr [g_pfnDllGetCO], 0
    jne     @erm_check_canun
    mov     rcx, qword ptr [g_hRealModule]
    lea     rdx, str_DllGetCO
    call    GetProcAddress
    mov     qword ptr [g_pfnDllGetCO], rax

@erm_check_canun:
    ; Resolve DllCanUnloadNow
    cmp     qword ptr [g_pfnDllCanUN], 0
    jne     @erm_ok
    mov     rcx, qword ptr [g_hRealModule]
    lea     rdx, str_DllCanUN
    call    GetProcAddress
    mov     qword ptr [g_pfnDllCanUN], rax

@erm_ok:
    mov     eax, 1
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret

@erm_fail:
    xor     eax, eax
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
EnsureRealModule endp

; ==============================================================================
; DllGetClassObject - COM class factory entry point
;
; RCX = rclsid (REFCLSID)
; RDX = riid (REFIID)
; R8  = ppv (LPVOID*)
;
; Returns HRESULT in EAX.
; On success: tail-calls real DllGetClassObject with params intact.
;
; Non-volatile saved: rbx, r12, r13
; 3 pushes (odd) → rsp%16=0; sub 20h → rsp%16=0 ✓
; ==============================================================================
PUBLIC DllGetClassObject
DllGetClassObject proc
    push    rbx
    push    r12
    push    r13
    sub     rsp, 20h

    ; Save incoming COM parameters across EnsureRealModule call
    mov     rbx, rcx                    ; rbx = rclsid
    mov     r12, rdx                    ; r12 = riid
    mov     r13, r8                     ; r13 = ppv

    call    EnsureRealModule
    test    eax, eax
    jz      @dgco_fail

    mov     rax, qword ptr [g_pfnDllGetCO]
    test    rax, rax
    jz      @dgco_fail

    ; Restore params and tail-call real DllGetClassObject
    mov     rcx, rbx
    mov     rdx, r12
    mov     r8,  r13
    add     rsp, 20h
    pop     r13
    pop     r12
    pop     rbx
    jmp     rax                         ; tail call → real DllGetClassObject

@dgco_fail:
    mov     eax, E_FAIL
    add     rsp, 20h
    pop     r13
    pop     r12
    pop     rbx
    ret
DllGetClassObject endp

; ==============================================================================
; DllCanUnloadNow - COM in-process server unload check
;
; No parameters.
; Returns HRESULT: S_OK (0) = can unload, S_FALSE (1) = cannot.
;
; On success: tail-calls real DllCanUnloadNow.
;
; Non-volatile saved: rbx
; 1 push (odd) → rsp%16=0; sub 20h → rsp%16=0 ✓
; ==============================================================================
PUBLIC DllCanUnloadNow
DllCanUnloadNow proc
    push    rbx
    sub     rsp, 20h

    call    EnsureRealModule
    test    eax, eax
    jz      @dcun_fail

    mov     rax, qword ptr [g_pfnDllCanUN]
    test    rax, rax
    jz      @dcun_fail

    ; Tail-call real DllCanUnloadNow (no params to restore)
    add     rsp, 20h
    pop     rbx
    jmp     rax

@dcun_fail:
    mov     eax, 1              ; S_FALSE = cannot unload (safe default)
    add     rsp, 20h
    pop     rbx
    ret
DllCanUnloadNow endp

end
