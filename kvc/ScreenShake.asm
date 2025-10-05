; ============================================================================
; ScreenShake.asm - x64 Windows Assembly
; ============================================================================
; Desktop shake effect using GDI BitBlt operation
; 
; Description:
;   Creates a horizontal screen shake effect by repeatedly copying the desktop
;   device context with alternating left/right offsets. The effect applies to
;   the entire desktop, not just the calling application window.
;
; Calling Convention:
;   Microsoft x64 calling convention (fastcall)
;   extern "C" void ScreenShake(int intensity, int shakes);
;
; Parameters:
;   RCX (intensity) - Horizontal offset in pixels for shake effect
;   RDX (shakes)    - Number of shake iterations to perform
;
; Returns:
;   void
;
; Notes:
;   - Uses desktop DC (GetDC(NULL)) to affect entire screen
;   - Each shake takes ~10ms (Sleep duration)
;   - User can abort by pressing SPACE key
;   - Screen is restored to original position on exit
; ============================================================================

.code

; External Win32 API functions
extern GetDC:proc              ; Retrieve device context handle
extern ReleaseDC:proc          ; Release device context handle
extern BitBlt:proc             ; Bit block transfer (copy pixels)
extern GetAsyncKeyState:proc   ; Check key state (for abort)
extern Sleep:proc              ; Suspend thread execution

; Export function for C++ linkage
public ScreenShake

; API Constants
SRCCOPY  equ 00CC0020h        ; BitBlt raster operation: direct copy
VK_SPACE equ 20h              ; Virtual key code for spacebar

; ============================================================================
; Main Function: ScreenShake
; ============================================================================
ScreenShake proc
    ; Function parameters (Microsoft x64 fastcall convention):
    ; RCX = intensity (int) - pixel offset for shake
    ; RDX = shakes (int)    - number of shake cycles
    
    ; -------------------------------------------------------------------------
    ; Prologue: Preserve non-volatile registers per calling convention
    ; -------------------------------------------------------------------------
    push rbx                   ; Save rbx (used for counter)
    push rsi                   ; Save rsi (reserved but unused)
    push rdi                   ; Save rdi (used for direction)
    push r12                   ; Save r12 (intensity storage)
    push r13                   ; Save r13 (shake count storage)
    push r14                   ; Save r14 (reserved but unused)
    push r15                   ; Save r15 (DC handle storage)
    sub rsp, 40h               ; Allocate shadow space (32 bytes) + alignment
    
    ; -------------------------------------------------------------------------
    ; Store input parameters in non-volatile registers
    ; -------------------------------------------------------------------------
    mov r12d, ecx              ; r12 = intensity (preserve across calls)
    mov r13d, edx              ; r13 = total shakes to perform
    
    ; -------------------------------------------------------------------------
    ; Acquire desktop device context
    ; -------------------------------------------------------------------------
    xor ecx, ecx               ; Parameter: hWnd = NULL (desktop window)
    call GetDC                 ; Returns HDC in RAX
    mov r15, rax               ; r15 = DC handle (preserved throughout)
    
    ; -------------------------------------------------------------------------
    ; Initialize loop variables
    ; -------------------------------------------------------------------------
    mov edi, r12d              ; edi = current direction (starts at +intensity)
    xor ebx, ebx               ; ebx = counter (initialize to 0)

; =============================================================================
; Main shake loop: Perform alternating left/right screen copies
; =============================================================================
shake_loop:
    ; -------------------------------------------------------------------------
    ; Check if we've completed all shake iterations
    ; -------------------------------------------------------------------------
    cmp ebx, r13d              ; Compare counter with total shakes
    jge end_shake              ; Exit if counter >= shakes
    
    ; -------------------------------------------------------------------------
    ; Check for user abort (SPACE key)
    ; -------------------------------------------------------------------------
    mov ecx, VK_SPACE          ; Parameter: virtual key code
    call GetAsyncKeyState      ; Returns key state in AX
    test ax, 8000h             ; Test high bit (key currently pressed?)
    jnz end_shake              ; Exit immediately if SPACE pressed
    
    ; -------------------------------------------------------------------------
    ; Prepare BitBlt parameters
    ; -------------------------------------------------------------------------
    ; BitBlt prototype:
    ; BOOL BitBlt(
    ;   HDC   hdc,      [RCX]  Destination DC
    ;   int   x,        [RDX]  Destination X coordinate
    ;   int   y,        [R8]   Destination Y coordinate
    ;   int   cx,       [R9]   Width to copy
    ;   int   cy,       [stack+20h] Height to copy
    ;   HDC   hdcSrc,   [stack+28h] Source DC
    ;   int   x1,       [stack+30h] Source X coordinate
    ;   int   y1,       [stack+38h] Source Y coordinate
    ;   DWORD rop       [stack+40h] Raster operation code
    ; );
    
    mov rcx, r15               ; Param 1: destination DC (desktop)
    movsxd rdx, edi            ; Param 2: x offset (sign-extend direction)
    xor r8, r8                 ; Param 3: y = 0 (no vertical offset)
    mov r9, 800h               ; Param 4: width = 2048 pixels
    
    ; Stack parameters (5-9) - must be in shadow space + params area
    mov dword ptr [rsp+20h], 800h     ; Param 5: height = 2048 pixels
    mov qword ptr [rsp+28h], r15      ; Param 6: source DC (same as dest)
    mov dword ptr [rsp+30h], 0        ; Param 7: source x1 = 0
    mov dword ptr [rsp+38h], 0        ; Param 8: source y1 = 0
    mov dword ptr [rsp+40h], SRCCOPY  ; Param 9: raster op (direct copy)
    
    call BitBlt                ; Execute screen copy with offset
    
    ; -------------------------------------------------------------------------
    ; Reverse direction for next iteration (creates shake effect)
    ; -------------------------------------------------------------------------
    neg edi                    ; Invert sign: +intensity -> -intensity
    
    ; -------------------------------------------------------------------------
    ; Increment shake counter
    ; -------------------------------------------------------------------------
    inc ebx                    ; counter++
    
    ; -------------------------------------------------------------------------
    ; Delay before next shake (makes effect visible)
    ; -------------------------------------------------------------------------
    mov ecx, 10                ; Parameter: 10 milliseconds
    call Sleep                 ; Suspend execution
    
    jmp shake_loop             ; Continue to next shake iteration

; =============================================================================
; Cleanup: Restore screen and release resources
; =============================================================================
end_shake:
    ; -------------------------------------------------------------------------
    ; Restore screen to original position (BitBlt with zero offset)
    ; -------------------------------------------------------------------------
    mov rcx, r15               ; Destination DC
    xor rdx, rdx               ; x = 0 (no offset)
    xor r8, r8                 ; y = 0
    mov r9, 800h               ; width = 2048
    
    mov dword ptr [rsp+20h], 800h     ; height = 2048
    mov qword ptr [rsp+28h], r15      ; source DC
    mov dword ptr [rsp+30h], 0        ; source x1 = 0
    mov dword ptr [rsp+38h], 0        ; source y1 = 0
    mov dword ptr [rsp+40h], SRCCOPY  ; raster op
    
    call BitBlt                ; Final restoration blit
    
    ; -------------------------------------------------------------------------
    ; Release desktop device context
    ; -------------------------------------------------------------------------
    xor ecx, ecx               ; Parameter: hWnd = NULL
    mov rdx, r15               ; Parameter: HDC to release
    call ReleaseDC             ; Free DC resource
    
    ; -------------------------------------------------------------------------
    ; Epilogue: Restore registers and return
    ; -------------------------------------------------------------------------
    add rsp, 40h               ; Deallocate shadow space
    pop r15                    ; Restore r15
    pop r14                    ; Restore r14
    pop r13                    ; Restore r13
    pop r12                    ; Restore r12
    pop rdi                    ; Restore rdi
    pop rsi                    ; Restore rsi
    pop rbx                    ; Restore rbx
    ret                        ; Return to caller
    
ScreenShake endp

end