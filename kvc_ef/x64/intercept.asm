; ==============================================================================
; ExplorerFrame DLL - Intercepted WinAPI Functions
;
; Author: Marek Wesołowski (wesmar)
; Purpose: Replacement functions for LoadStringW and ExtTextOutW in
;          shell32.dll's IAT. LoadStringW suppresses activation watermark
;          resource IDs 62000/62001. ExtTextOutW suppresses text rendering
;          when the string matches any loaded branding pattern.
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN LoadStringW           :PROC
EXTRN ExtTextOutW           :PROC
EXTRN DrawTextW             :PROC
EXTRN wcslen_p              :PROC
EXTRN wcscpy_p              :PROC
EXTRN WideStrFind           :PROC

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; ContainsBrandingWatermark - Check if text matches any watermark pattern
;
; RCX = text (LPCWSTR)
; Returns EAX = 1 if watermark found, 0 otherwise
;
; For patterns[0..2, 4..6]: straight substring search.
; For patterns[3]: %xxx%middle%suffix format - extract the segment between
;   the first and second '%' characters starting at offset 4, search for it.
;
; Non-volatile: rbx, rsi, rdi, r12, r13, r14, r15
; Entry rsp%16=8; 7 pushes → 0 mod16; sub 20h → 0 mod16 ✓
; ==============================================================================
PUBLIC ContainsBrandingWatermark
ContainsBrandingWatermark proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h

    ; reject NULL or empty
    test    rcx, rcx
    jz      @cbw_false
    cmp     word ptr [rcx], 0
    je      @cbw_false

    mov     r12, rcx                        ; r12 = text

    ; textLen = wcslen_p(text)
    call    wcslen_p
    test    rax, rax
    jz      @cbw_false
    mov     r13d, eax                       ; r13d = textLen

    lea     r14, g_brandingPatterns         ; r14 = &pattern table
    xor     r15d, r15d                      ; r15d = pattern index

@cbw_loop:
    cmp     r15d, BRANDING_PATTERN_COUNT
    jge     @cbw_false

    mov     rsi, [r14 + r15*8]             ; rsi = pattern ptr
    test    rsi, rsi
    jz      @cbw_next                       ; NULL slot
    cmp     word ptr [rsi], 0
    je      @cbw_next                       ; empty string

    ; patternLen = wcslen_p(pattern)
    mov     rcx, rsi
    call    wcslen_p
    mov     edi, eax                        ; edi = patternLen

    ; --- Special case: pattern[3] in %xxx%middle%... format ---
    cmp     r15d, 3
    jne     @cbw_plain

    cmp     word ptr [rsi], WILDCARD_MARKER ; pattern[0] == '%'?
    jne     @cbw_plain
    cmp     edi, 4
    jle     @cbw_next                       ; pattern too short

    ; Find the second '%' starting from index 5 (skip %xxx%, 4 chars + %)
    ; segStart = 4, scan forward from index 5 until '%' or end
    mov     ecx, 5                          ; ecx = scan index
@cbw_scan:
    cmp     ecx, edi
    jge     @cbw_seg_done                   ; hit end without second %
    movzx   eax, word ptr [rsi + rcx*2]
    cmp     eax, WILDCARD_MARKER
    je      @cbw_seg_done
    inc     ecx
    jmp     @cbw_scan

@cbw_seg_done:
    ; segment: pattern+4, length = ecx-4
    mov     ebx, ecx
    sub     ebx, 4                          ; ebx = segment length
    test    ebx, ebx
    jz      @cbw_next

    ; WideStrFind(text, textLen, pattern+4, segLen)
    ; needle = rsi+8 (offset 4 WCHARs = 8 bytes)
    mov     rcx, r12
    mov     edx, r13d
    lea     r8, [rsi + 8]                  ; pattern + 4 WCHARs
    mov     r9d, ebx
    call    WideStrFind
    test    eax, eax                        ; 0 = found, -1 = not found
    jz      @cbw_true
    jmp     @cbw_next

@cbw_plain:
    ; WideStrFind(text, textLen, pattern, patternLen)
    mov     rcx, r12
    mov     edx, r13d
    mov     r8, rsi
    mov     r9d, edi
    call    WideStrFind
    test    eax, eax
    jz      @cbw_true

@cbw_next:
    inc     r15d
    jmp     @cbw_loop

@cbw_true:
    mov     eax, 1
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

@cbw_false:
    xor     eax, eax
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ContainsBrandingWatermark endp

; ==============================================================================
; InterceptedLoadStringW - Hook for LoadStringW in shell32.dll's IAT
;
; Blocks resource IDs 62000 and 62001 (activation watermarks).
; All other IDs are forwarded to the real LoadStringW in our own IAT.
;
; RCX = hInstance, EDX = uID, R8 = lpBuffer, R9D = nBufferMax
; Returns EAX = INT (character count, or 0 if blocked/failed)
; ==============================================================================
PUBLIC InterceptedLoadStringW
InterceptedLoadStringW proc
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h

    mov     r12d, edx                       ; r12d = resource ID
    mov     r13, r8                         ; r13 = output buffer

    ; Block the two watermark resource IDs
    cmp     edx, BLOCKED_RESOURCE_ID_1
    je      @ils_block
    cmp     edx, BLOCKED_RESOURCE_ID_2
    je      @ils_block

    ; Forward to the real LoadStringW (resolved via our DLL's own IAT).
    call    LoadStringW
    mov     ebx, eax                        ; preserve return count
    test    eax, eax
    jle     @ils_return
    test    r13, r13
    jz      @ils_return

    ; shell32 may resolve localized resources differently at runtime than during
    ; DllMain. Learn the actual strings that shell32 just loaded and use them as
    ; live watermark patterns.
    lea     r14, g_brandingPatterns

    cmp     r12d, SHELL32_ID_0
    je      @ils_slot1
    cmp     r12d, SHELL32_ID_1
    je      @ils_slot2
    cmp     r12d, SHELL32_ID_2
    je      @ils_slot3
    cmp     r12d, SHELL32_ID_3
    je      @ils_slot4
    cmp     r12d, SHELL32_ID_4
    je      @ils_slot5
    cmp     r12d, SHELL32_ID_5
    je      @ils_slot6
    cmp     r12d, SHELL32_ID_6
    je      @ils_slot7
    cmp     r12d, SHELL32_ID_7
    je      @ils_slot8
    cmp     r12d, SHELL32_ID_8
    je      @ils_slot9
    cmp     r12d, SHELL32_ID_9
    je      @ils_slot10
    cmp     r12d, SHELL32_ID_10
    je      @ils_slot11
    cmp     r12d, SHELL32_ID_11
    je      @ils_slot12
    cmp     r12d, SHELL32_ID_12
    je      @ils_slot13
    jmp     @ils_return

@ils_slot1:
    mov     r15d, 1
    jmp     @ils_update
@ils_slot2:
    mov     r15d, 2
    jmp     @ils_update
@ils_slot3:
    mov     r15d, 3
    jmp     @ils_update
@ils_slot4:
    mov     r15d, 4
    jmp     @ils_update
@ils_slot5:
    mov     r15d, 5
    jmp     @ils_update
@ils_slot6:
    mov     r15d, 6
    jmp     @ils_update
@ils_slot7:
    mov     r15d, 7
    jmp     @ils_update
@ils_slot8:
    mov     r15d, 8
    jmp     @ils_update
@ils_slot9:
    mov     r15d, 9
    jmp     @ils_update
@ils_slot10:
    mov     r15d, 10
    jmp     @ils_update
@ils_slot11:
    mov     r15d, 11
    jmp     @ils_update
@ils_slot12:
    mov     r15d, 12
    jmp     @ils_update
@ils_slot13:
    mov     r15d, 13

@ils_update:
    mov     rcx, [r14 + r15*8]             ; destination pattern buffer
    test    rcx, rcx
    jz      @ils_return
    mov     rdx, r13                        ; source: LoadStringW output buffer
    call    wcscpy_p
    jmp     @ils_return

@ils_block:
    xor     eax, eax
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

@ils_return:
    mov     eax, ebx
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
InterceptedLoadStringW endp

; ==============================================================================
; InterceptedExtTextOutW - Hook for ExtTextOutW in shell32.dll's IAT
;
; Suppresses text rendering when the string matches a branding watermark.
;
; x64 calling convention - 8 parameters total:
;   RCX  = hdc
;   EDX  = x
;   R8D  = y
;   R9D  = options
;   [RSP+28h] = lprc   (const RECT*)
;   [RSP+30h] = lpString (LPCWSTR)
;   [RSP+38h] = c      (UINT) - character count
;   [RSP+40h] = lpDx   (const INT*)
;
; Returns EAX = BOOL
; ==============================================================================
PUBLIC InterceptedExtTextOutW
InterceptedExtTextOutW proc
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h            ; 5 pushes: entry rsp%16=8 → after pushes: 0, sub 20h: 0 ✓

    ; Save volatile register arguments across ContainsBrandingWatermark.
    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8
    mov     r15, r9

    ; Fetch lpString from stack (above our saved frame)
    ; Original stack layout when called:
    ;   [original_rsp+28h] = lprc
    ;   [original_rsp+30h] = lpString
    ; After 5 pushes + sub 20h: rsp = original_rsp - 48h
    ;   lpString now at [rsp+78h]
    mov     rbx, [rsp+78h]                  ; rbx = lpString

    test    rbx, rbx
    jz      @iet_forward                    ; NULL → forward (draw nothing)

    ; ContainsBrandingWatermark(lpString) → suppresses if match
    mov     rcx, rbx
    call    ContainsBrandingWatermark
    test    eax, eax
    jnz     @iet_suppress

@iet_forward:
    mov     rcx, r12
    mov     rdx, r13
    mov     r8,  r14
    mov     r9,  r15
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ; Tail-call the real ExtTextOutW with original register and stack args.
    jmp     ExtTextOutW

@iet_suppress:
    mov     eax, 1                          ; return TRUE (pretend success)
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
InterceptedExtTextOutW endp

; ==============================================================================
; InterceptedDrawTextW - Hook for DrawTextW in shell32.dll's IAT
;
; Some newer shell32 builds route desktop branding text through USER32 DrawTextW
; instead of calling GDI ExtTextOutW directly. Suppress the same strings here.
;
; RCX = hdc
; RDX = lpchText
; R8D = cchText
; R9  = lprc
; [RSP+28h] = format
;
; Returns EAX = INT
; ==============================================================================
PUBLIC InterceptedDrawTextW
InterceptedDrawTextW proc
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h

    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8
    mov     r15, r9

    test    r13, r13
    jz      @idt_forward

    mov     rcx, r13
    call    ContainsBrandingWatermark
    test    eax, eax
    jnz     @idt_suppress

@idt_forward:
    mov     rcx, r12
    mov     rdx, r13
    mov     r8,  r14
    mov     r9,  r15
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    jmp     DrawTextW

@idt_suppress:
    xor     eax, eax
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
InterceptedDrawTextW endp

; ==============================================================================
; InterceptedBrandingLoadStringForEdition - Hook for BrandingLoadStringForEdition
;
; Shell32!CDesktopWatermark::s_DesktopBuildPaint calls this to get the activation
; watermark text. Returning 0 causes shell32 to jump past all rendering calls
; (confirmed via disasm: `test eax,eax / je +0x9ed` immediately after the call).
;
; RCX = brandingName (LPCWSTR)
; EDX = id
; R8D = languageId
; R9  = outputBuffer (LPWSTR)
; [rsp+20h] = bufferMax
; [rsp+28h] = flags
; Returns: EAX = 0 (empty string)
;
; Leaf function - no calls, no sub rsp needed.
; ==============================================================================
PUBLIC InterceptedBrandingLoadStringForEdition
InterceptedBrandingLoadStringForEdition proc
    test    r9, r9
    jz      @iblsfe_ret
    mov     word ptr [r9], 0        ; L'\0' → empty string in output buffer
@iblsfe_ret:
    xor     eax, eax
    ret
InterceptedBrandingLoadStringForEdition endp

; ==============================================================================
; InterceptedDrawTextWithGlow - Hook for UxTheme!DrawTextWithGlow (ordinal 126)
;
; Shell32!CDesktopWatermark::s_DesktopBuildPaint uses this to render all
; watermark strings with a glow effect (Test Mode, Build string, etc.).
; Returning S_OK without drawing suppresses all glow-rendered watermark text.
;
; Signature (x64):
;   RCX = HDC
;   RDX = pszText (LPCWSTR)
;   R8  = cchText (int)
;   R9  = prc (RECT*)
;   [rsp+20h] = dwFlags
;   [rsp+28h] = crText
;   [rsp+30h] = crGlow
;   [rsp+38h] = nGlowRadius
;   [rsp+40h] = nGlowIntensity
;   [rsp+48h] = bPreMultiply
;   [rsp+50h] = pfnCallback
;   [rsp+58h] = lParam
; Returns: HRESULT S_OK = 0
;
; Leaf function.
; ==============================================================================
PUBLIC InterceptedDrawTextWithGlow
InterceptedDrawTextWithGlow proc
    xor     eax, eax    ; S_OK — text "drawn" (suppressed)
    ret
InterceptedDrawTextWithGlow endp

end
