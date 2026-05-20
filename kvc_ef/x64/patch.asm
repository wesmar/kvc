; ==============================================================================
; ExplorerFrame DLL - Import Address Table Patching
;
; Author: Marek Wesołowski (wesmar)
; Purpose: Locates and replaces function pointers in shell32.dll's IAT.
;          Redirects LoadStringW and ExtTextOutW to our interceptors so
;          watermark text is suppressed before it reaches the screen.
;
; Public routines:
;   PatchShell32Imports     - entry point; patches both functions
;   ReplaceImportedFunction - generic IAT slot replacement
;
; Private helpers:
;   GetImportDescriptor     - walk PE headers to find a named import DLL
;   LocateFunctionInThunk   - scan FirstThunk for a specific function address
; ==============================================================================

option casemap:none

include consts.inc

EXTRN GetModuleHandleW          :PROC
EXTRN GetProcAddress            :PROC
EXTRN VirtualProtect            :PROC
EXTRN lstrcmpiA                 :PROC

EXTRN InterceptedLoadStringW                :PROC
EXTRN InterceptedExtTextOutW               :PROC
EXTRN InterceptedDrawTextW                 :PROC
EXTRN InterceptedBrandingLoadStringForEdition :PROC
EXTRN InterceptedDrawTextWithGlow            :PROC

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

str_shell32_a   db 'shell32.dll',0
str_gdi32_a     db 'gdi32.dll',0
str_user32_a    db 'user32.dll',0
str_winbrand_a  db 'winbrand.dll',0
str_uxtheme_a   db 'UxTheme.dll',0
str_loader20    db 'api-ms-win-core-libraryloader-l1-2-0.dll',0
str_loader11    db 'api-ms-win-core-libraryloader-l1-1-1.dll',0
str_ExtTextOutW                   db 'ExtTextOutW',0
str_DrawTextW                     db 'DrawTextW',0
str_LoadStringW                   db 'LoadStringW',0
str_BrandingLoadStringForEdition  db 'BrandingLoadStringForEdition',0

str_loader20_w  dw 'a','p','i','-','m','s','-','w','i','n','-','c','o','r','e','-'
                dw 'l','i','b','r','a','r','y','l','o','a','d','e','r','-','l','1','-'
                dw '2','-','0','.','d','l','l',0
str_loader11_w  dw 'a','p','i','-','m','s','-','w','i','n','-','c','o','r','e','-'
                dw 'l','i','b','r','a','r','y','l','o','a','d','e','r','-','l','1','-'
                dw '1','-','1','.','d','l','l',0
str_shell32_w   dw 's','h','e','l','l','3','2','.','d','l','l',0
str_gdi32_w     dw 'g','d','i','3','2','.','d','l','l',0
str_user32_w    dw 'u','s','e','r','3','2','.','d','l','l',0
str_winbrand_w  dw 'w','i','n','b','r','a','n','d','.','d','l','l',0

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; GetImportDescriptor - Find named DLL in a module's import directory
;
; RCX = module base (HMODULE)
; RDX = DLL name to find (LPCSTR, ASCII, case-insensitive)
;
; Returns RAX = pointer to IMAGE_IMPORT_DESCRIPTOR, or NULL
;
; Stack: 3 pushes → rsp%16=0; sub 20h → rsp%16=0 ✓
; ==============================================================================
GetImportDescriptor proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    test    rcx, rcx
    jz      @gid_null
    test    rdx, rdx
    jz      @gid_null

    mov     rbx, rcx            ; rbx = moduleBase
    mov     rsi, rdx            ; rsi = target module name

    ; NT headers = base + base[60]  (e_lfanew)
    mov     eax, dword ptr [rbx + IMDOS_e_lfanew]
    add     rax, rbx            ; rax = IMAGE_NT_HEADERS64*

    ; Import directory RVA is at fixed offset 144 within NT headers
    mov     ecx, dword ptr [rax + IMNT_ImportDirectory_VA]
    test    ecx, ecx
    jz      @gid_null

    lea     rdi, [rbx + rcx]    ; rdi = first IMAGE_IMPORT_DESCRIPTOR

@gid_walk:
    cmp     dword ptr [rdi + IMID_Name], 0
    je      @gid_null           ; end-of-table sentinel

    ; name = base + descriptor.Name  (ASCII string)
    mov     ecx, dword ptr [rdi + IMID_Name]
    lea     rcx, [rbx + rcx]
    mov     rdx, rsi
    call    lstrcmpiA
    test    eax, eax
    jz      @gid_found

    add     rdi, IMID_SIZE
    jmp     @gid_walk

@gid_found:
    mov     rax, rdi
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret

@gid_null:
    xor     rax, rax
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GetImportDescriptor endp

; ==============================================================================
; LocateFunctionInThunk - Scan IAT for a given function address
;
; RCX = moduleBase (QWORD)
; RDX = IMAGE_IMPORT_DESCRIPTOR* (importDesc)
; R8  = target function address (FARPROC)
;
; Returns RAX = address of the matching QWORD slot in IAT, or NULL
;
; Pure computation - no calls, only saves RBX/RSI.
; 2 pushes → rsp%16=8; no sub needed (leaf, no further calls).
; ==============================================================================
LocateFunctionInThunk proc
    push    rbx
    push    rsi

    ; thunkPtr = moduleBase + importDesc.FirstThunk
    mov     eax, dword ptr [rdx + IMID_FirstThunk]
    lea     rbx, [rcx + rax]   ; rbx = &IAT[0]
    mov     rsi, r8             ; rsi = targetFunction

@lft_walk:
    mov     rax, qword ptr [rbx]
    test    rax, rax
    jz      @lft_null           ; end of thunk array

    cmp     rax, rsi
    je      @lft_found

    add     rbx, 8
    jmp     @lft_walk

@lft_found:
    mov     rax, rbx
    pop     rsi
    pop     rbx
    ret

@lft_null:
    xor     rax, rax
    pop     rsi
    pop     rbx
    ret
LocateFunctionInThunk endp

; ==============================================================================
; ReplaceImportedFunction - Patch one IAT slot with a replacement function
;
; RCX = targetModule (HMODULE)         - module whose IAT we patch
; RDX = importModuleName (LPCSTR)      - ASCII name of the imported DLL
; R8  = originalFunction (FARPROC)     - current IAT value to find
; R9  = replacementFunction (FARPROC)  - new value to write
;
; Returns EAX = 1 (patched), 0 (failed)
;
; Locals (after 5 pushes + sub 30h):
;   [rsp+20h] = DWORD oldProtect
;
; Stack: 5 pushes → rsp%16=0; sub 30h → rsp%16=0 ✓
; ==============================================================================
PUBLIC ReplaceImportedFunction
ReplaceImportedFunction proc
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 30h            ; shadow(20h) + oldProtect(4)+pad(4) = 28h... use 30h

    test    rcx, rcx
    jz      @rif_false
    test    rdx, rdx
    jz      @rif_false
    test    r8, r8
    jz      @rif_false
    test    r9, r9
    jz      @rif_false

    mov     r12, rcx            ; r12 = targetModule (base)
    mov     r13, rdx            ; r13 = importModuleName
    mov     r14, r8             ; r14 = originalFunction
    mov     r15, r9             ; r15 = replacementFunction

    ; GetImportDescriptor(targetModule, importModuleName)
    mov     rcx, r12
    mov     rdx, r13
    call    GetImportDescriptor
    test    rax, rax
    jz      @rif_false

    mov     rbx, rax            ; rbx = importDescriptor

    ; LocateFunctionInThunk(moduleBase, importDesc, originalFunction)
    mov     rcx, r12
    mov     rdx, rbx
    mov     r8, r14
    call    LocateFunctionInThunk
    test    rax, rax
    jz      @rif_false

    mov     rbx, rax            ; rbx = address of IAT slot (QWORD*)

    ; VirtualProtect(slot, 8, PAGE_EXECUTE_READWRITE, &oldProtect)
    mov     rcx, rbx
    mov     edx, 8
    mov     r8d, PAGE_EXECUTE_READWRITE
    lea     r9, [rsp+20h]       ; &oldProtect local
    call    VirtualProtect
    test    eax, eax
    jz      @rif_false

    ; Overwrite the IAT slot
    mov     qword ptr [rbx], r15

    ; Restore protection - reuse oldProtect as both in and out param
    mov     rcx, rbx
    mov     edx, 8
    mov     r8d, dword ptr [rsp+20h]    ; oldProtect value
    lea     r9, [rsp+20h]               ; &dummy (discarded)
    call    VirtualProtect

    mov     eax, 1
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

@rif_false:
    xor     eax, eax
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
ReplaceImportedFunction endp

; ==============================================================================
; GetDelayImportDescriptor - Find named DLL in a module's delay-load import dir
;
; RCX = module base (HMODULE)
; RDX = DLL name to find (LPCSTR, ASCII, case-insensitive)
;
; Returns RAX = pointer to ImgDelayDescr, or NULL
;
; Stack: 3 pushes → rsp%16=0; sub 20h → rsp%16=0 ✓
; ==============================================================================
GetDelayImportDescriptor proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    test    rcx, rcx
    jz      @gdid_null
    test    rdx, rdx
    jz      @gdid_null

    mov     rbx, rcx            ; rbx = moduleBase
    mov     rsi, rdx            ; rsi = target DLL name

    ; NT headers = base + base[60]
    mov     eax, dword ptr [rbx + IMDOS_e_lfanew]
    add     rax, rbx            ; rax = IMAGE_NT_HEADERS64*

    ; Delay import directory RVA at fixed offset 240 within NT headers
    mov     ecx, dword ptr [rax + IMNT_DelayImportDirectory_VA]
    test    ecx, ecx
    jz      @gdid_null

    lea     rdi, [rbx + rcx]    ; rdi = first ImgDelayDescr

@gdid_walk:
    cmp     dword ptr [rdi + IMDD_Name], 0
    je      @gdid_null          ; end-of-table sentinel

    mov     ecx, dword ptr [rdi + IMDD_Name]
    lea     rcx, [rbx + rcx]    ; DLL name string (RVA → VA)
    mov     rdx, rsi
    call    lstrcmpiA
    test    eax, eax
    jz      @gdid_found

    add     rdi, IMDD_SIZE
    jmp     @gdid_walk

@gdid_found:
    mov     rax, rdi
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret

@gdid_null:
    xor     rax, rax
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GetDelayImportDescriptor endp

; ==============================================================================
; LocateFunctionInDelayThunk - Scan delay-load IAT for a function address
;
; RCX = moduleBase (QWORD)
; RDX = ImgDelayDescr* (delayDesc)
; R8  = target function address (FARPROC)
;
; Returns RAX = address of matching QWORD slot, or NULL
;
; Pure computation - no calls. 2 pushes → rsp%16=8; leaf.
; ==============================================================================
LocateFunctionInDelayThunk proc
    push    rbx
    push    rsi

    ; thunkPtr = moduleBase + delayDesc.rvaIAT
    mov     eax, dword ptr [rdx + IMDD_IAT]
    lea     rbx, [rcx + rax]    ; rbx = &DelayIAT[0]
    mov     rsi, r8             ; rsi = targetFunction

@lfidt_walk:
    mov     rax, qword ptr [rbx]
    test    rax, rax
    jz      @lfidt_null

    cmp     rax, rsi
    je      @lfidt_found

    add     rbx, 8
    jmp     @lfidt_walk

@lfidt_found:
    mov     rax, rbx
    pop     rsi
    pop     rbx
    ret

@lfidt_null:
    xor     rax, rax
    pop     rsi
    pop     rbx
    ret
LocateFunctionInDelayThunk endp

; ==============================================================================
; ReplaceDelayImportedFunction - Patch one delay-load IAT slot
;
; Same signature as ReplaceImportedFunction but walks the delay import table.
;
; RCX = targetModule (HMODULE)
; RDX = importModuleName (LPCSTR, ASCII)
; R8  = originalFunction (FARPROC)
; R9  = replacementFunction (FARPROC)
;
; Returns EAX = 1 (patched), 0 (failed)
;
; Stack: 5 pushes → rsp%16=0; sub 30h → rsp%16=0 ✓
; [rsp+20h] = DWORD oldProtect
; ==============================================================================
PUBLIC ReplaceDelayImportedFunction
ReplaceDelayImportedFunction proc
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 30h

    test    rcx, rcx
    jz      @rdif_false
    test    rdx, rdx
    jz      @rdif_false
    test    r8, r8
    jz      @rdif_false
    test    r9, r9
    jz      @rdif_false

    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8
    mov     r15, r9

    mov     rcx, r12
    mov     rdx, r13
    call    GetDelayImportDescriptor
    test    rax, rax
    jz      @rdif_false

    mov     rbx, rax

    mov     rcx, r12
    mov     rdx, rbx
    mov     r8, r14
    call    LocateFunctionInDelayThunk
    test    rax, rax
    jz      @rdif_false

    mov     rbx, rax

    mov     rcx, rbx
    mov     edx, 8
    mov     r8d, PAGE_EXECUTE_READWRITE
    lea     r9, [rsp+20h]
    call    VirtualProtect
    test    eax, eax
    jz      @rdif_false

    mov     qword ptr [rbx], r15

    mov     rcx, rbx
    mov     edx, 8
    mov     r8d, dword ptr [rsp+20h]
    lea     r9, [rsp+20h]
    call    VirtualProtect

    mov     eax, 1
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

@rdif_false:
    xor     eax, eax
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
ReplaceDelayImportedFunction endp

; ==============================================================================
; ReplaceDelayImportedFunctionByName - Patch delay-load IAT by scanning INT
;
; Scans the INT (Import Name Table) by function name so the patch works even
; before the delay-loaded DLL has been resolved (IAT still holds thunk stubs).
;
; RCX = targetModule (HMODULE)         - module whose delay IAT we patch
; RDX = importModuleName (LPCSTR)      - ASCII name of the delay-imported DLL
; R8  = functionName (LPCSTR)          - ASCII name of the function to hook
; R9  = replacementFunction (FARPROC)  - new value to write into the IAT slot
;
; Returns EAX = 1 (patched), 0 (failed)
;
; Locals: [rsp+20h] = DWORD oldProtect
; Stack: 7 pushes (rbx/rsi/rdi/r12-r15) → rsp%16=0; sub 30h → rsp%16=0 ✓
; ==============================================================================
ReplaceDelayImportedFunctionByName proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 30h

    test    rcx, rcx
    jz      @rdifbn_false
    test    rdx, rdx
    jz      @rdifbn_false
    test    r8, r8
    jz      @rdifbn_false
    test    r9, r9
    jz      @rdifbn_false

    mov     r12, rcx            ; r12 = targetModule
    mov     r13, rdx            ; r13 = importModuleName
    mov     r14, r8             ; r14 = functionName
    mov     r15, r9             ; r15 = replacementFunction

    ; Find delay descriptor for the named DLL
    mov     rcx, r12
    mov     rdx, r13
    call    GetDelayImportDescriptor
    test    rax, rax
    jz      @rdifbn_false

    mov     rbx, rax            ; rbx = ImgDelayDescr*

    ; rsi = &INT[0]  (rvaINT at IMDD_INT = 16)
    mov     eax, dword ptr [rbx + IMDD_INT]
    lea     rsi, [r12 + rax]

    ; rdi = &IAT[0]  (rvaIAT at IMDD_IAT = 12)
    mov     eax, dword ptr [rbx + IMDD_IAT]
    lea     rdi, [r12 + rax]

@rdifbn_walk:
    mov     rax, qword ptr [rsi]
    test    rax, rax
    jz      @rdifbn_false       ; null terminator = end of table
    js      @rdifbn_next        ; bit 63 set = ordinal import, no name

    ; lower 32 bits = RVA to IMAGE_IMPORT_BY_NAME; +2 skips WORD Hint
    mov     eax, eax            ; zero-extend 32-bit RVA to 64-bit
    lea     rcx, [r12 + rax + 2]
    mov     rdx, r14
    call    lstrcmpiA
    test    eax, eax
    jz      @rdifbn_found

@rdifbn_next:
    add     rsi, 8
    add     rdi, 8
    jmp     @rdifbn_walk

@rdifbn_found:
    ; rdi = matching IAT slot
    mov     rcx, rdi
    mov     edx, 8
    mov     r8d, PAGE_EXECUTE_READWRITE
    lea     r9, [rsp+20h]
    call    VirtualProtect
    test    eax, eax
    jz      @rdifbn_false

    mov     qword ptr [rdi], r15

    mov     rcx, rdi
    mov     edx, 8
    mov     r8d, dword ptr [rsp+20h]
    lea     r9, [rsp+20h]
    call    VirtualProtect

    mov     eax, 1
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

@rdifbn_false:
    xor     eax, eax
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ReplaceDelayImportedFunctionByName endp

; ==============================================================================
; ReplaceDelayImportedFunctionByOrdinal - Patch delay-load IAT by ordinal number
;
; Same as ReplaceDelayImportedFunctionByName but matches ordinal entries
; (INT entries with bit 63 = 1, ordinal in bits 15:0).
;
; RCX = targetModule (HMODULE)
; RDX = importModuleName (LPCSTR)
; R8  = ordinal (WORD, zero-extended)
; R9  = replacementFunction (FARPROC)
;
; Returns EAX = 1 (patched), 0 (failed)
; Stack: 7 pushes + sub 30h → rsp%16=0 ✓
; ==============================================================================
ReplaceDelayImportedFunctionByOrdinal proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 30h

    test    rcx, rcx
    jz      @rdifbo_false
    test    rdx, rdx
    jz      @rdifbo_false
    test    r9, r9
    jz      @rdifbo_false

    mov     r12, rcx            ; r12 = targetModule
    mov     r13, rdx            ; r13 = importModuleName
    mov     r14, r8             ; r14 = target ordinal (low WORD)
    mov     r15, r9             ; r15 = replacementFunction

    mov     rcx, r12
    mov     rdx, r13
    call    GetDelayImportDescriptor
    test    rax, rax
    jz      @rdifbo_false

    mov     rbx, rax            ; rbx = ImgDelayDescr*

    mov     eax, dword ptr [rbx + IMDD_INT]
    lea     rsi, [r12 + rax]    ; rsi = &INT[0]

    mov     eax, dword ptr [rbx + IMDD_IAT]
    lea     rdi, [r12 + rax]    ; rdi = &IAT[0]

@rdifbo_walk:
    mov     rax, qword ptr [rsi]
    test    rax, rax
    jz      @rdifbo_false       ; null terminator
    jns     @rdifbo_next        ; bit 63 clear = by-name entry, skip

    ; ordinal entry: bits 15:0 = ordinal number
    movzx   rax, ax             ; zero-extend ordinal to 64-bit
    cmp     rax, r14
    je      @rdifbo_found

@rdifbo_next:
    add     rsi, 8
    add     rdi, 8
    jmp     @rdifbo_walk

@rdifbo_found:
    mov     rcx, rdi
    mov     edx, 8
    mov     r8d, PAGE_EXECUTE_READWRITE
    lea     r9, [rsp+20h]
    call    VirtualProtect
    test    eax, eax
    jz      @rdifbo_false

    mov     qword ptr [rdi], r15

    mov     rcx, rdi
    mov     edx, 8
    mov     r8d, dword ptr [rsp+20h]
    lea     r9, [rsp+20h]
    call    VirtualProtect

    mov     eax, 1
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

@rdifbo_false:
    xor     eax, eax
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ReplaceDelayImportedFunctionByOrdinal endp

; ==============================================================================
; PatchShell32Imports - Hook LoadStringW and ExtTextOutW in shell32.dll's IAT
;
; No parameters. Returns EAX = 1 if at least one hook succeeded, else 0.
;
; Strategy for LoadStringW:
;   Windows 11 ships api-ms-win-core-libraryloader-l1-2-0.dll as the
;   canonical source; older builds use the l1-1-1 variant. We try both.
;
; Stack: 7 pushes → rsp%16=0; sub 20h → rsp%16=0 ✓
; ==============================================================================
PUBLIC PatchShell32Imports
PatchShell32Imports proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h

    xor     r15d, r15d              ; r15d = patched-any flag
    xor     r12d, r12d              ; r12 = hShell32, known NULL until set

    ; hShell32
    lea     rcx, str_shell32_w
    call    GetModuleHandleW
    test    rax, rax
    jz      @psi_exttext            ; no shell32 → skip LoadString patch
    mov     r12, rax                ; r12 = hShell32

    ; --- Patch LoadStringW ---
    ; Try api-ms-win-core-libraryloader-l1-2-0.dll first
    lea     rcx, str_loader20_w
    call    GetModuleHandleW
    test    rax, rax
    jz      @psi_try_loader11
    mov     rbx, rax                ; rbx = hLoader20

    mov     rcx, rbx
    lea     rdx, str_LoadStringW    ; ASCII
    call    GetProcAddress
    test    rax, rax
    jz      @psi_try_loader11
    mov     r13, rax                ; r13 = pfnLoadStringW from l1-2-0

    ; ReplaceImportedFunction(hShell32, "l1-2-0.dll", pfnLS, InterceptedLoadStringW)
    mov     rcx, r12
    lea     rdx, str_loader20
    mov     r8, r13
    lea     r9, InterceptedLoadStringW
    call    ReplaceImportedFunction
    or      r15d, eax               ; accumulate success
    jmp     @psi_exttext

@psi_try_loader11:
    lea     rcx, str_loader11_w
    call    GetModuleHandleW
    test    rax, rax
    jz      @psi_exttext
    mov     rbx, rax                ; rbx = hLoader11

    mov     rcx, rbx
    lea     rdx, str_LoadStringW
    call    GetProcAddress
    test    rax, rax
    jz      @psi_exttext
    mov     r13, rax

    mov     rcx, r12
    lea     rdx, str_loader11
    mov     r8, r13
    lea     r9, InterceptedLoadStringW
    call    ReplaceImportedFunction
    or      r15d, eax

    ; --- Patch ExtTextOutW ---
@psi_exttext:
    lea     rcx, str_gdi32_w
    call    GetModuleHandleW
    test    rax, rax
    jz      @psi_drawtext

    mov     rcx, rax
    lea     rdx, str_ExtTextOutW    ; ASCII
    call    GetProcAddress
    test    rax, rax
    jz      @psi_drawtext

    mov     r14, rax                ; r14 = pfnExtTextOutW

    ; Need hShell32 - re-fetch if we didn't get it earlier
    test    r12, r12
    jnz     @psi_patch_eto
    lea     rcx, str_shell32_w
    call    GetModuleHandleW
    test    rax, rax
    jz      @psi_done
    mov     r12, rax

@psi_patch_eto:
    mov     rcx, r12
    lea     rdx, str_gdi32_a
    mov     r8, r14
    lea     r9, InterceptedExtTextOutW
    call    ReplaceImportedFunction
    or      r15d, eax

    ; --- Patch DrawTextW ---
@psi_drawtext:
    test    r12, r12
    jnz     @psi_drawtext_have_shell32
    lea     rcx, str_shell32_w
    call    GetModuleHandleW
    test    rax, rax
    jz      @psi_done
    mov     r12, rax

@psi_drawtext_have_shell32:
    lea     rcx, str_user32_w
    call    GetModuleHandleW
    test    rax, rax
    jz      @psi_brand              ; no user32 → skip DrawTextW, still do brand hook

    mov     rcx, rax
    lea     rdx, str_DrawTextW
    call    GetProcAddress
    test    rax, rax
    jz      @psi_brand              ; no DrawTextW → skip, still do brand hook

    mov     rcx, r12
    lea     rdx, str_user32_a
    mov     r8, rax
    lea     r9, InterceptedDrawTextW
    call    ReplaceImportedFunction
    or      r15d, eax

    ; --- Patch BrandingLoadStringForEdition ---
    ; Shell32 imports this from winbrand.dll to get activation/edition strings.
    ; Returning 0 (empty) makes s_DesktopBuildPaint exit before any drawing call.
@psi_brand:
    test    r12, r12
    jnz     @psi_brand_have_shell32
    lea     rcx, str_shell32_w
    call    GetModuleHandleW
    test    rax, rax
    jz      @psi_done
    mov     r12, rax

@psi_brand_have_shell32:
    ; Scan INT by name — works even if WINBRAND not yet delay-loaded
    mov     rcx, r12
    lea     rdx, str_winbrand_a
    lea     r8, str_BrandingLoadStringForEdition
    lea     r9, InterceptedBrandingLoadStringForEdition
    call    ReplaceDelayImportedFunctionByName
    or      r15d, eax

    ; --- Patch DrawTextWithGlow (UxTheme ordinal 126) ---
    ; Shell32 renders all watermark strings (Test Mode, Build string) via this
    ; function. Imported by ordinal — must scan INT by ordinal value.
    mov     rcx, r12
    lea     rdx, str_uxtheme_a
    mov     r8d, 126
    lea     r9, InterceptedDrawTextWithGlow
    call    ReplaceDelayImportedFunctionByOrdinal
    or      r15d, eax

@psi_done:
    mov     eax, r15d
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PatchShell32Imports endp

end
