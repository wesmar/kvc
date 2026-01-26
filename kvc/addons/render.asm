INCLUDE data.inc
INCLUDE proto.inc

.CONST
; Rendering layout constants
BLOCK_SIZE equ 25                    ; Pixel size of each tetromino block
BOARD_X equ 20                       ; Board top-left X position
BOARD_Y equ 20                       ; Board top-left Y position
INFO_X equ 300                       ; Info panel X position
INFO_Y equ 50                        ; Info panel Y position
GAME_AREA_HEIGHT equ 520             ; Separation line between game and controls

.DATA
ALIGN 16
; String constants for UI rendering
szSegoeUI db "Segoe UI", 0
szScore db "Score: %d", 0
szLines db "Lines: %d", 0
szLevel db "Level: %d", 0
szRecord db "Record: %d", 0
szNext db "Next:", 0
szAuthor db "Author:", 0
szName db "Marek Wesolowski", 0
szEmail db "marek@wesolowski.eu.org", 0
szWebsite db "https://kvc.pl", 0
szControls db "Controls:", 0
szCtrlF2 db "F2 - New Game", 0
szCtrlP db "P - Pause/Resume", 0
szCtrlArrows db "Arrows - Move/Rotate", 0
szCtrlSpace db "Space - Hard Drop", 0
szCtrlEsc db "ESC - Exit", 0
szPaused db "PAUSED", 0
szGameOver db "GAME OVER!", 0

ALIGN 16
; Color palette (BGR format for Windows GDI)
; TRAP: Windows GDI uses BGR order, not RGB! (00BBGGRR)
colorTable dd 00000000h              ; 0: Empty cell (black)
    dd 00FFFF00h                     ; 1: Cyan (I-piece)
    dd 0000FFFFh                     ; 2: Yellow (O-piece)
    dd 000000FFh                     ; 3: Red (Z-piece)
    dd 0000FF00h                     ; 4: Green (S-piece)
    dd 00800080h                     ; 5: Purple (T-piece)
    dd 000080FFh                     ; 6: Orange (L-piece)
    dd 00FF8000h                     ; 7: Blue (J-piece)

.CODE
ALIGN 16

; Initialize renderer state and create GDI resources
; TRAP x64: Args are RCX=pRenderer, RDX=hwnd (not stack!)
; TRAP: CreateFontA takes 14 params - use stack for params 5-14
InitRenderer PROC pRenderer:QWORD, hwnd:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16                     ; TRAP: 16-byte stack alignment before call
    sub rsp, 0A0h                    ; Large shadow space for CreateFont calls

    ; Save non-volatile registers (x64 calling convention)
    mov [rsp+80h], rsi
    mov [rsp+88h], rbx

    mov rsi, rcx                     ; RSI = pRenderer
    mov [rsi].RENDERER_STATE.hwnd, rdx
    mov QWORD PTR [rsi].RENDERER_STATE.hdcMem, 0
    mov QWORD PTR [rsi].RENDERER_STATE.hbmMem, 0
    mov QWORD PTR [rsi].RENDERER_STATE.hbmOld, 0
    mov DWORD PTR [rsi].RENDERER_STATE.wWidth, 0
    mov DWORD PTR [rsi].RENDERER_STATE.wHeight, 0
    mov DWORD PTR [rsi].RENDERER_STATE.pausePulse, 0

    ; Create normal font (20pt, bold) for game stats
    ; TRAP: CreateFontA parameters: height, width, escapement, orientation,
    ;       weight, italic, underline, strikeout, charset, outprecision,
    ;       clipprecision, quality, pitchandfamily, facename
    mov ecx, 20                      ; nHeight
    xor edx, edx                     ; nWidth = 0 (auto)
    xor r8d, r8d                     ; nEscapement = 0
    xor r9d, r9d                     ; nOrientation = 0
    mov DWORD PTR [rsp+20h], 700     ; fnWeight = FW_BOLD
    mov DWORD PTR [rsp+28h], 0       ; fdwItalic = FALSE
    mov DWORD PTR [rsp+30h], 0       ; fdwUnderline = FALSE
    mov DWORD PTR [rsp+38h], 0       ; fdwStrikeOut = FALSE
    mov DWORD PTR [rsp+40h], 0       ; fdwCharSet = DEFAULT_CHARSET
    mov DWORD PTR [rsp+48h], 0       ; fdwOutputPrecision
    mov DWORD PTR [rsp+50h], 0       ; fdwClipPrecision
    mov DWORD PTR [rsp+58h], 0       ; fdwQuality
    mov DWORD PTR [rsp+60h], 0       ; fdwPitchAndFamily
    lea rax, szSegoeUI
    mov QWORD PTR [rsp+68h], rax     ; lpszFace = "SegoeUI"
    call CreateFontA
    mov [rsi].RENDERER_STATE.hFontNormal, rax
    
    mov ecx, 14
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov DWORD PTR [rsp+20h], 400
    mov DWORD PTR [rsp+28h], 0
    mov DWORD PTR [rsp+30h], 0
    mov DWORD PTR [rsp+38h], 0
    mov DWORD PTR [rsp+40h], 0
    mov DWORD PTR [rsp+48h], 0
    mov DWORD PTR [rsp+50h], 0
    mov DWORD PTR [rsp+58h], 0
    mov DWORD PTR [rsp+60h], 0
    lea rax, szSegoeUI
    mov QWORD PTR [rsp+68h], rax
    call CreateFontA
    mov [rsi].RENDERER_STATE.hFontSmall, rax
    
    mov ecx, 26
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov DWORD PTR [rsp+20h], 700
    mov DWORD PTR [rsp+28h], 0
    mov DWORD PTR [rsp+30h], 0
    mov DWORD PTR [rsp+38h], 0
    mov DWORD PTR [rsp+40h], 0
    mov DWORD PTR [rsp+48h], 0
    mov DWORD PTR [rsp+50h], 0
    mov DWORD PTR [rsp+58h], 0
    mov DWORD PTR [rsp+60h], 0
    lea rax, szSegoeUI
    mov QWORD PTR [rsp+68h], rax
    call CreateFontA
    mov [rsi].RENDERER_STATE.hFontPause, rax
    
    mov ecx, 30
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov DWORD PTR [rsp+20h], 700
    mov DWORD PTR [rsp+28h], 0
    mov DWORD PTR [rsp+30h], 0
    mov DWORD PTR [rsp+38h], 0
    mov DWORD PTR [rsp+40h], 0
    mov DWORD PTR [rsp+48h], 0
    mov DWORD PTR [rsp+50h], 0
    mov DWORD PTR [rsp+58h], 0
    mov DWORD PTR [rsp+60h], 0
    lea rax, szSegoeUI
    mov QWORD PTR [rsp+68h], rax
    call CreateFontA
    mov [rsi].RENDERER_STATE.hFontGameOver, rax
    
    ; Create brushes for all 8 colors (0-7)
    ; TRAP: R8 is volatile, must save before function calls
    xor r8d, r8d
@@create_brushes:
    mov [rsp+90h], r8                ; Save loop counter

    ; Get color from colorTable
    ; TRAP: Each entry is DWORD (4 bytes), so multiply by 4
    mov eax, r8d
    shl eax, 2                       ; *4 for DWORD indexing
    lea rdx, colorTable
    mov ecx, DWORD PTR [rdx + rax]   ; BGR color value
    call CreateSolidBrush

    ; Store brush handle in array
    ; TRAP: Handles are 64-bit (QWORD), so multiply by 8
    mov r8, [rsp+90h]
    mov QWORD PTR [rsi + RENDERER_STATE.colorBrushes + r8*8], rax
    inc r8d
    cmp r8d, 8
    jl @@create_brushes

    ; Restore non-volatile registers
    mov rsi, [rsp+80h]
    mov rbx, [rsp+88h]

    mov rsp, rbp
    pop rbp
    ret
InitRenderer ENDP

; Release all GDI resources (fonts, brushes, DC, bitmap)
; Must be called before application exit to prevent resource leaks
; RCX = pRenderer
CleanupRenderer PROC pRenderer:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 40h

    mov [rsp+30h], rsi
    mov rsi, rcx

    cmp QWORD PTR [rsi].RENDERER_STATE.hFontNormal, 0
    je @@skip_font1
    mov rcx, [rsi].RENDERER_STATE.hFontNormal
    call DeleteObject
@@skip_font1:
    
    cmp QWORD PTR [rsi].RENDERER_STATE.hFontSmall, 0
    je @@skip_font2
    mov rcx, [rsi].RENDERER_STATE.hFontSmall
    call DeleteObject
@@skip_font2:
    
    cmp QWORD PTR [rsi].RENDERER_STATE.hFontPause, 0
    je @@skip_font3
    mov rcx, [rsi].RENDERER_STATE.hFontPause
    call DeleteObject
@@skip_font3:
    
    cmp QWORD PTR [rsi].RENDERER_STATE.hFontGameOver, 0
    je @@skip_font4
    mov rcx, [rsi].RENDERER_STATE.hFontGameOver
    call DeleteObject
@@skip_font4:
    
    xor r8d, r8d
@@delete_brushes:
    mov rax, QWORD PTR [rsi + RENDERER_STATE.colorBrushes + r8*8]
    test rax, rax
    jz @@skip_brush
    mov rcx, rax
    mov [rsp+20h], r8 
    call DeleteObject
    mov r8, [rsp+20h]
@@skip_brush:
    inc r8d
    cmp r8d, 8
    jl @@delete_brushes
    
    cmp QWORD PTR [rsi].RENDERER_STATE.hdcMem, 0
    je @@skip_dc
    
    cmp QWORD PTR [rsi].RENDERER_STATE.hbmOld, 0
    je @@skip_select
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsi].RENDERER_STATE.hbmOld
    call SelectObject
@@skip_select:
    
    cmp QWORD PTR [rsi].RENDERER_STATE.hbmMem, 0
    je @@skip_bitmap
    mov rcx, [rsi].RENDERER_STATE.hbmMem
    call DeleteObject
@@skip_bitmap:
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    call DeleteDC
@@skip_dc:
    
    mov rsi, [rsp+30h]
    mov rsp, rbp
    pop rbp
    ret
CleanupRenderer ENDP

; Create or recreate offscreen bitmap for double buffering
; Releases old bitmap if exists, creates new one matching window size
; RCX = pRenderer
CreateBackBuffer PROC pRenderer:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 40h

    mov [rsp+30h], rsi
    mov rsi, rcx

    cmp QWORD PTR [rsi].RENDERER_STATE.hdcMem, 0
    je @@create_new
    
    cmp QWORD PTR [rsi].RENDERER_STATE.hbmOld, 0
    je @@skip_old
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsi].RENDERER_STATE.hbmOld
    call SelectObject
@@skip_old:
    
    cmp QWORD PTR [rsi].RENDERER_STATE.hbmMem, 0
    je @@skip_bmp
    mov rcx, [rsi].RENDERER_STATE.hbmMem
    call DeleteObject
@@skip_bmp:
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    call DeleteDC
    
@@create_new:
    mov rcx, [rsi].RENDERER_STATE.hwnd
    call GetDC
    mov [rsp+28h], rax ; Save hdc (20h is stack arg slot)
    
    mov rcx, rax
    call CreateCompatibleDC
    mov [rsi].RENDERER_STATE.hdcMem, rax
    
    mov rcx, [rsp+28h] 
    mov edx, [rsi].RENDERER_STATE.wWidth
    mov r8d, [rsi].RENDERER_STATE.wHeight
    call CreateCompatibleBitmap
    mov [rsi].RENDERER_STATE.hbmMem, rax
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, rax
    call SelectObject
    mov [rsi].RENDERER_STATE.hbmOld, rax
    
    mov rcx, [rsi].RENDERER_STATE.hwnd
    mov rdx, [rsp+28h]
    call ReleaseDC
    
    mov rsi, [rsp+30h]
    mov rsp, rbp
    pop rbp
    ret
CreateBackBuffer ENDP

; Update renderer dimensions and recreate backbuffer
; Called on window resize or initial setup
; RCX = pRenderer, EDX = width, R8D = height
ResizeRenderer PROC pRenderer:QWORD, wWidth:DWORD, wHeight:DWORD
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 40h

    mov [rsp+30h], rsi
    mov rsi, rcx
    mov [rsi].RENDERER_STATE.wWidth, edx
    mov [rsi].RENDERER_STATE.wHeight, r8d
    
    mov rcx, rsi
    call CreateBackBuffer
    
    mov rsi, [rsp+30h]
    mov rsp, rbp
    pop rbp
    ret
ResizeRenderer ENDP

; Main render function - draws entire game frame to backbuffer then blits to screen
; Clears background, draws board/pieces/UI, then copies to window DC
; RCX = pRenderer, RDX = pGame, R8 = hdc (window device context)
RenderGame PROC pRenderer:QWORD, pGame:QWORD, hdc:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 80h

    mov [rsp+50h], rsi
    mov [rsp+58h], rdi
    mov [rsp+60h], rbx
    mov [rsp+68h], r12

    mov rsi, rcx
    mov rdi, rdx
    mov r12, r8

    cmp QWORD PTR [rsi].RENDERER_STATE.hdcMem, 0
    je @@exit
    
    mov DWORD PTR [rsp+28h], 0
    mov DWORD PTR [rsp+2Ch], 0
    mov eax, [rsi].RENDERER_STATE.wWidth
    mov DWORD PTR [rsp+30h], eax
    mov DWORD PTR [rsp+34h], GAME_AREA_HEIGHT
    
    mov ecx, 00141414h
    call CreateSolidBrush
    mov rbx, rax
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    lea rdx, [rsp+28h]
    mov r8, rax
    call FillRect
    
    mov rcx, rbx
    call DeleteObject
    
    mov DWORD PTR [rsp+28h], 0
    mov DWORD PTR [rsp+2Ch], GAME_AREA_HEIGHT
    mov eax, [rsi].RENDERER_STATE.wWidth
    mov DWORD PTR [rsp+30h], eax
    mov eax, [rsi].RENDERER_STATE.wHeight
    mov DWORD PTR [rsp+34h], eax
    
    mov ecx, 00F0F0F0h
    call CreateSolidBrush
    mov rbx, rax
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    lea rdx, [rsp+28h]
    mov r8, rax
    call FillRect
    
    mov rcx, rbx
    call DeleteObject
    
    mov rcx, rsi
    mov rdx, rdi
    call DrawBoard
    
    mov rcx, rsi
    mov rdx, rdi
    call DrawGhostPiece
    
    mov rcx, rsi
    lea rdx, [rdi].GAME_STATE.currentPiece
    call DrawPiece
    
    mov rcx, rsi
    mov rdx, rdi
    call DrawInfo
    
    mov rcx, rsi
    lea rdx, [rdi].GAME_STATE.nextPiece
    call DrawNextPiece
    
    mov rcx, r12 ; hdc
    xor edx, edx
    xor r8d, r8d
    mov r9d, [rsi].RENDERER_STATE.wWidth
    mov DWORD PTR [rsp+20h], GAME_AREA_HEIGHT
    mov rax, [rsi].RENDERER_STATE.hdcMem
    mov QWORD PTR [rsp+28h], rax
    mov DWORD PTR [rsp+30h], 0
    mov DWORD PTR [rsp+38h], 0
    mov DWORD PTR [rsp+40h], 00CC0020h ; SRCCOPY
    call BitBlt
    
@@exit:
    mov rsi, [rsp+50h]
    mov rdi, [rsp+58h]
    mov rbx, [rsp+60h]
    mov r12, [rsp+68h]
    
    mov rsp, rbp
    pop rbp
    ret
RenderGame ENDP

; Draw board grid lines and filled cells with line clear animation overlay
; Iterates through board array and draws colored rectangles for occupied cells
; RCX = pRenderer, RDX = pGame
DrawBoard PROC pRenderer:QWORD, pGame:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 80h

    mov [rsp+60h], rsi
    mov [rsp+68h], rdi
    mov [rsp+70h], rbx

    mov rsi, rcx
    mov rdi, rdx

    mov ecx, 0
    mov edx, 1
    mov r8d, 00323232h
    call CreatePen
    mov rbx, rax 
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, rax
    call SelectObject
    mov [rsp+50h], rax 
    
    mov eax, [rdi].GAME_STATE.boardHeight
    inc eax
    mov [rsp+58h], eax 
    
    mov eax, [rdi].GAME_STATE.boardWidth
    inc eax
    mov [rsp+5Ch], eax 
    
    xor r8d, r8d 
    mov [rsp+40h], r8d
    
@@hline_loop:
    mov r8d, [rsp+40h]
    cmp r8d, [rsp+58h]
    jge @@hline_done
    
    imul r9d, r8d, BLOCK_SIZE
    add r9d, BOARD_Y
    
    mov eax, [rdi].GAME_STATE.boardWidth
    imul eax, BLOCK_SIZE
    add eax, BOARD_X
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, BOARD_X
    
    mov r8d, r9d ; Y
    xor r9, r9
    
    mov [rsp+48h], rax
    
    call MoveToEx
    
    mov rax, [rsp+48h]
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, eax ; X
    mov r8d, [rsp+40h]
    imul r8d, BLOCK_SIZE
    add r8d, BOARD_Y ; Y 
    
    call LineTo
    
    mov r8d, [rsp+40h]
    inc r8d
    mov [rsp+40h], r8d
    jmp @@hline_loop
    
@@hline_done:
    mov DWORD PTR [rsp+40h], 0
    
@@vline_loop:
    mov r8d, [rsp+40h]
    cmp r8d, [rsp+5Ch]
    jge @@vline_done
    
    imul r9d, r8d, BLOCK_SIZE
    add r9d, BOARD_X ; X
    
    mov eax, [rdi].GAME_STATE.boardHeight
    imul eax, BLOCK_SIZE
    add eax, BOARD_Y ; Target Y
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, r9d ; X
    mov r8d, BOARD_Y ; Y
    xor r9, r9
    
    mov [rsp+48h], rax ; Save Target Y
    
    call MoveToEx
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov r8d, [rsp+40h]
    imul r8d, BLOCK_SIZE
    add r8d, BOARD_X ; X
    mov edx, r8d
    
    mov r8d, [rsp+48h] ; Y
    
    call LineTo
    
    mov r8d, [rsp+40h]
    inc r8d
    mov [rsp+40h], r8d
    jmp @@vline_loop
    
@@vline_done:
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+50h] 
    call SelectObject
    
    mov rcx, rbx 
    call DeleteObject
    
    mov DWORD PTR [rsp+40h], 0 ; y
    
@@outer_loop:
    mov eax, [rsp+40h]
    cmp eax, [rdi].GAME_STATE.boardHeight
    jge @@outer_done
    
    mov DWORD PTR [rsp+44h], 0 ; x
    
@@inner_loop:
    mov eax, [rsp+44h]
    cmp eax, [rdi].GAME_STATE.boardWidth
    jge @@inner_done
    
    mov eax, [rsp+40h]
    imul eax, [rdi].GAME_STATE.boardWidth
    add eax, [rsp+44h]
    lea r10, [rdi].GAME_STATE.board
    movzx r8d, byte ptr [r10 + rax]
    
    test r8d, r8d
    jz @@skip_block
    
    mov eax, [rsp+44h]
    imul eax, BLOCK_SIZE
    add eax, BOARD_X
    inc eax
    mov DWORD PTR [rsp+20h], eax ; Left
    
    mov eax, [rsp+40h]
    imul eax, BLOCK_SIZE
    add eax, BOARD_Y
    inc eax
    mov DWORD PTR [rsp+24h], eax ; Top
    
    mov eax, [rsp+20h]
    add eax, BLOCK_SIZE - 2
    mov DWORD PTR [rsp+28h], eax ; Right
    
    mov eax, [rsp+24h]
    add eax, BLOCK_SIZE - 2
    mov DWORD PTR [rsp+2Ch], eax ; Bottom
    
    and r8d, 7
    mov rax, QWORD PTR [rsi + RENDERER_STATE.colorBrushes + r8*8]
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    lea rdx, [rsp+20h]
    mov r8, rax
    call FillRect
    
@@skip_block:
    inc DWORD PTR [rsp+44h]
    jmp @@inner_loop
    
@@inner_done:
    inc DWORD PTR [rsp+40h]
    jmp @@outer_loop
    
@@outer_done:
    ; Draw smooth fade-out overlay for clearing lines
    cmp BYTE PTR [rdi].GAME_STATE.clearActive, 0
    je @@no_overlay

    ; Calculate fade color: gold (255,215,0) -> black (0,0,0)
    ; intensity = (300 - timer) / 300  (sync with CLEAR_ANIM_MS in game.asm)
    ; R = 255 * intensity, G = 215 * intensity, B = 0
    mov eax, [rdi].GAME_STATE.clearTimer
    mov ecx, 300                     ; Must match CLEAR_ANIM_MS in game.asm
    sub ecx, eax                     ; ECX = 300 - timer (remaining intensity)
    jle @@no_overlay                 ; Safety: skip if timer >= 300

    ; Calculate R component: 255 * (300-timer) / 300
    mov eax, 255
    imul eax, ecx                    ; EAX = 255 * (300-timer)
    xor edx, edx
    mov r8d, 300                     ; Must match CLEAR_ANIM_MS in game.asm
    div r8d                          ; EAX = R component
    mov r9d, eax                     ; R9D = R (save)

    ; Calculate G component: 215 * (300-timer) / 300
    mov eax, 215
    imul eax, ecx                    ; EAX = 215 * (300-timer)
    xor edx, edx
    div r8d                          ; EAX = G component

    ; Compose BGR color: (0 << 16) | (G << 8) | R
    shl eax, 8                       ; G << 8
    or eax, r9d                      ; | R
    mov ecx, eax                     ; ECX = final BGR color

    call CreateSolidBrush

@@brush_created:
    mov [rsp+78h], rax               ; Save brush handle

    ; Iterate through rows and draw overlay for rows in clearMask
    xor ebx, ebx                     ; Row counter

@@overlay_loop:
    cmp ebx, [rdi].GAME_STATE.boardHeight
    jge @@overlay_done

    ; Check if this row is in clearMask
    mov eax, 1
    mov ecx, ebx
    shl eax, cl                      ; EAX = 1 << row
    test eax, [rdi].GAME_STATE.clearMask
    jz @@next_overlay_row

    ; Calculate row rectangle
    mov DWORD PTR [rsp+20h], BOARD_X + 1              ; Left
    mov eax, ebx
    imul eax, BLOCK_SIZE
    add eax, BOARD_Y + 1
    mov DWORD PTR [rsp+24h], eax                      ; Top

    mov eax, [rdi].GAME_STATE.boardWidth
    imul eax, BLOCK_SIZE
    add eax, BOARD_X - 1
    mov DWORD PTR [rsp+28h], eax                      ; Right

    mov eax, ebx
    imul eax, BLOCK_SIZE
    add eax, BOARD_Y + BLOCK_SIZE - 1
    mov DWORD PTR [rsp+2Ch], eax                      ; Bottom

    ; Draw overlay rectangle
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    lea rdx, [rsp+20h]
    mov r8, [rsp+78h]
    mov [rsp+30h], rbx               ; Save row counter
    call FillRect
    mov rbx, [rsp+30h]               ; Restore row counter

@@next_overlay_row:
    inc ebx
    jmp @@overlay_loop

@@overlay_done:
    ; Delete the brush
    mov rcx, [rsp+78h]
    call DeleteObject

@@no_overlay:
    mov rsi, [rsp+60h]
    mov rdi, [rsp+68h]
    mov rbx, [rsp+70h]

    mov rsp, rbp
    pop rbp
    ret
DrawBoard ENDP

; Draw ghost piece preview at landing position
; TRAP x64: Must preserve RSI, RDI, RBX (non-volatile)
; Shows where the piece will land with semi-transparent hatch pattern
DrawGhostPiece PROC pRenderer:QWORD, pGame:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16                     ; 16-byte alignment
    sub rsp, 0B0h                    ; Shadow space + 48-byte local PIECE copy

    ; Save non-volatile registers
    mov [rsp+90h], rsi
    mov [rsp+98h], rdi
    mov [rsp+0A0h], rbx

    mov rsi, rcx                     ; RSI = pRenderer
    mov rdi, rdx                     ; RDI = pGame

    ; Skip if game over, paused, or ghost disabled
    mov al, [rdi].GAME_STATE.gameOver
    test al, al
    jnz @@exit

    mov al, [rdi].GAME_STATE.paused
    test al, al
    jnz @@exit

    mov al, [rdi].GAME_STATE.showGhost
    test al, al
    jz @@exit
    
    ; Copy currentPiece to local stack variable (48 bytes)
    ; TRAP: Manual byte-by-byte copy to preserve exact structure
    lea r8, [rsp+60h]                ; Local ghost piece on stack
    lea r9, [rdi].GAME_STATE.currentPiece
    mov ecx, 48                      ; sizeof(PIECE)

@@copy_loop:
    mov al, [r9]
    mov [r8], al
    inc r8
    inc r9
    dec ecx
    jnz @@copy_loop

    lea rbx, [rsp+60h]               ; RBX = &ghostPiece

    ; Find landing position by moving down until collision
@@find_landing:
    inc DWORD PTR [rbx+8]            ; ghostPiece.y++

    mov rcx, rdi                     ; pGame
    mov rdx, rbx                     ; &ghostPiece
    call CheckCollision

    test eax, eax
    jz @@find_landing

    ; Back up one row to last valid position
    dec DWORD PTR [rbx+8]            ; ghostPiece.y--
    
    lea rax, [rdi].GAME_STATE.currentPiece
    mov edx, [rax+8] 
    cmp edx, [rbx+8] 
    jge @@exit
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 1
    call SetBkMode
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 00181818h
    call SetBkColor
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 00484848h
    call SetTextColor
    
    mov ecx, 5 
    mov edx, 00484848h
    call CreateHatchBrush
    mov [rsp+50h], rax 
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, rax
    call SelectObject
    mov [rsp+58h], rax 
    
    mov eax, [rbx+4] ; x
    mov [rsp+40h], eax ; px
    mov eax, [rbx+8] ; y
    mov [rsp+44h], eax ; py
    
    xor r10d, r10d 
@@loop_blocks:
    cmp r10d, 4
    jge @@loop_done
    
    mov eax, DWORD PTR [rbx + 16 + r10*8]
    add eax, [rsp+40h]
    mov edx, DWORD PTR [rbx + 16 + r10*8 + 4]
    add edx, [rsp+44h]
    
    cmp edx, 0
    jl @@skip_draw
    
    imul eax, BLOCK_SIZE
    add eax, BOARD_X
    inc eax
    mov DWORD PTR [rsp+20h], eax ; left
    
    imul edx, BLOCK_SIZE
    add edx, BOARD_Y
    inc edx
    mov DWORD PTR [rsp+24h], edx ; top
    
    mov eax, DWORD PTR [rsp+20h]
    add eax, BLOCK_SIZE - 2
    mov DWORD PTR [rsp+28h], eax ; right
    
    mov eax, DWORD PTR [rsp+24h]
    add eax, BLOCK_SIZE - 2
    mov DWORD PTR [rsp+2Ch], eax ; bottom
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    lea rdx, [rsp+20h]
    mov r8, [rsp+50h]

    mov [rsp+30h], r10 ; Save loop (safe slot)
    call FillRect
    mov r10, [rsp+30h]
    
@@skip_draw:
    inc r10d
    jmp @@loop_blocks
    
@@loop_done:
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+58h]
    call SelectObject
    
    mov rcx, [rsp+50h]
    call DeleteObject
    
@@exit:
    mov rsi, [rsp+90h]
    mov rdi, [rsp+98h]
    mov rbx, [rsp+0A0h]
    
    mov rsp, rbp
    pop rbp
    ret
DrawGhostPiece ENDP

; Draw a tetromino piece at its current board position
; Used for rendering the active falling piece
; RCX = pRenderer, RDX = pPiece
DrawPiece PROC pRenderer:QWORD, pPiece:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 60h

    mov [rsp+40h], rsi
    mov [rsp+48h], rdi
    mov [rsp+50h], rbx

    mov rsi, rcx
    mov rdi, rdx

    movzx eax, byte ptr [rdi+1] ; color
    and eax, 7
    mov rbx, QWORD PTR [rsi + RENDERER_STATE.colorBrushes + rax*8]
    
    mov eax, [rdi+4] ; x
    mov [rsp+30h], eax
    mov eax, [rdi+8] ; y
    mov [rsp+34h], eax
    
    xor r10d, r10d
@@loop_blocks:
    cmp r10d, 4
    jge @@loop_done
    
    mov eax, DWORD PTR [rdi + 16 + r10*8]
    add eax, [rsp+30h]
    mov edx, DWORD PTR [rdi + 16 + r10*8 + 4]
    add edx, [rsp+34h]
    
    cmp edx, 0
    jl @@skip_draw
    
    imul eax, BLOCK_SIZE
    add eax, BOARD_X
    inc eax
    mov DWORD PTR [rsp+20h], eax
    
    imul edx, BLOCK_SIZE
    add edx, BOARD_Y
    inc edx
    mov DWORD PTR [rsp+24h], edx
    
    mov eax, DWORD PTR [rsp+20h]
    add eax, BLOCK_SIZE - 2
    mov DWORD PTR [rsp+28h], eax
    
    mov eax, DWORD PTR [rsp+24h]
    add eax, BLOCK_SIZE - 2
    mov DWORD PTR [rsp+2Ch], eax
    
    movzx r8d, byte ptr [rdi+1] ; color
    and r8d, 7

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    lea rdx, [rsp+20h]
    mov r8, rbx

    mov [rsp+38h], r10 ; Save loop
    call FillRect
    mov r10, [rsp+38h]
    
@@skip_draw:
    inc r10d
    jmp @@loop_blocks
    
@@loop_done:
    mov rsi, [rsp+40h]
    mov rdi, [rsp+48h]
    mov rbx, [rsp+50h]
    
    mov rsp, rbp
    pop rbp
    ret
DrawPiece ENDP

; Draw "Next:" label and preview of upcoming piece in info panel
; RCX = pRenderer, RDX = pPiece (nextPiece)
DrawNextPiece PROC pRenderer:QWORD, pPiece:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 60h

    mov [rsp+40h], rsi
    mov [rsp+48h], rdi
    mov [rsp+50h], rbx

    mov rsi, rcx
    mov rdi, rdx

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 1
    call SetBkMode
    
    movzx eax, byte ptr [rdi+1] ; color
    and eax, 7
    lea rcx, colorTable
    mov eax, DWORD PTR [rcx + rax*4]
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, eax
    call SetTextColor
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsi].RENDERER_STATE.hFontNormal
    call SelectObject
    mov [rsp+30h], rax ; hOldFont
    
    lea rcx, szNext
    call lstrlenA
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 135
    lea r9, szNext
    mov DWORD PTR [rsp+20h], eax
    call TextOutA
    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+30h]
    call SelectObject
    
    movzx eax, byte ptr [rdi+1]
    and eax, 7
    mov rbx, QWORD PTR [rsi + RENDERER_STATE.colorBrushes + rax*8]
    
    xor r10d, r10d
@@loop_next:
    cmp r10d, 4
    jge @@loop_next_done
    
    mov eax, DWORD PTR [rdi + 16 + r10*8]
    imul eax, BLOCK_SIZE
    add eax, INFO_X + 20
    inc eax
    mov DWORD PTR [rsp+20h], eax
    
    mov edx, DWORD PTR [rdi + 16 + r10*8 + 4]
    imul edx, BLOCK_SIZE
    add edx, INFO_Y + 170
    inc edx
    mov DWORD PTR [rsp+24h], edx
    
    mov eax, DWORD PTR [rsp+20h]
    add eax, BLOCK_SIZE - 2
    mov DWORD PTR [rsp+28h], eax
    
    mov eax, DWORD PTR [rsp+24h]
    add eax, BLOCK_SIZE - 2
    mov DWORD PTR [rsp+2Ch], eax
    
    movzx r8d, byte ptr [rdi+1]
    and r8d, 7

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    lea rdx, [rsp+20h]
    mov r8, rbx

    mov [rsp+30h], r10 ; Save loop
    call FillRect
    mov r10, [rsp+30h]
    
    inc r10d
    jmp @@loop_next
    
@@loop_next_done:
    mov rsi, [rsp+40h]
    mov rdi, [rsp+48h]
    mov rbx, [rsp+50h]
    
    mov rsp, rbp
    pop rbp
    ret
DrawNextPiece ENDP

; Draw info panel: score, lines, level, high score, controls, author info
; Also renders PAUSED/GAME OVER overlays when appropriate
; RCX = pRenderer, RDX = pGame
DrawInfo PROC pRenderer:QWORD, pGame:QWORD
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 220h

    mov [rsp+210h], rsi
    mov [rsp+218h], rdi
    mov [rsp+200h], rbx

    mov rsi, rcx
    mov rdi, rdx

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 1
    call SetBkMode

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 00FFFFFFh
    call SetTextColor

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsi].RENDERER_STATE.hFontSmall
    call SelectObject
    mov [rsp+1F0h], rax ; hOldFont

    
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 0080FF80h
    call SetTextColor

    lea rcx, szControls
    call lstrlenA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, 15
    lea r9, szControls
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    mov ecx, 0
    mov edx, 1
    mov r8d, 00323232h
    call CreatePen
    mov rbx, rax

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, rax
    call SelectObject
    mov [rsp+1E8h], rax

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X - 5
    mov r8d, 32
    xor r9, r9
    call MoveToEx

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X + 165
    mov r8d, 32
    call LineTo

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+1E8h]
    call SelectObject

    mov rcx, rbx
    call DeleteObject

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 00C0C0C0h
    call SetTextColor

    lea rcx, szCtrlF2
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X + 5
    mov r8d, 36
    lea r9, szCtrlF2
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, szCtrlP
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X + 5
    mov r8d, 49
    lea r9, szCtrlP
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, szCtrlArrows
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X + 5
    mov r8d, 62
    lea r9, szCtrlArrows
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, szCtrlSpace
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X + 5
    mov r8d, 75
    lea r9, szCtrlSpace
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, szCtrlEsc
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X + 5
    mov r8d, 88
    lea r9, szCtrlEsc
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    mov ecx, 0
    mov edx, 1
    mov r8d, 00323232h
    call CreatePen
    mov rbx, rax

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, rax
    call SelectObject
    mov [rsp+1E0h], rax

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X - 5
    mov r8d, 105
    xor r9, r9
    call MoveToEx

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X + 165
    mov r8d, 105
    call LineTo

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+1E0h]
    call SelectObject

    mov rcx, rbx
    call DeleteObject

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+1F0h]
    call SelectObject

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 00FFFFFFh
    call SetTextColor

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsi].RENDERER_STATE.hFontNormal
    call SelectObject
    mov [rsp+1F0h], rax

    lea rcx, [rsp+100h]
    lea rdx, szScore
    mov r8d, [rdi].GAME_STATE.score
    call wsprintfA

    lea rcx, [rsp+100h]
    call lstrlenA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 60
    lea r9, [rsp+100h]
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, [rsp+100h]
    lea rdx, szLines
    mov r8d, [rdi].GAME_STATE.lines
    call wsprintfA

    lea rcx, [rsp+100h]
    call lstrlenA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 85
    lea r9, [rsp+100h]
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, [rsp+100h]
    lea rdx, szLevel
    mov r8d, [rdi].GAME_STATE.level
    call wsprintfA

    lea rcx, [rsp+100h]
    call lstrlenA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 110
    lea r9, [rsp+100h]
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 0000D7FFh
    call SetTextColor

    lea rcx, [rsp+100h]
    lea rdx, szRecord
    mov r8d, [rdi].GAME_STATE.highScore
    call wsprintfA

    lea rcx, [rsp+100h]
    call lstrlenA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 260
    lea r9, [rsp+100h]
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea r10, [rdi].GAME_STATE.highScoreName
    cmp WORD PTR [r10], 0
    je @@skip_name

    mov rcx, 0
    mov edx, 0
    mov r8, r10
    mov r9d, -1
    lea rax, [rsp+80h]
    mov QWORD PTR [rsp+20h], rax
    mov DWORD PTR [rsp+28h], 128
    mov QWORD PTR [rsp+30h], 0
    mov QWORD PTR [rsp+38h], 0
    call WideCharToMultiByte

    lea rcx, [rsp+80h]
    call lstrlenA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 235
    lea r9, [rsp+80h]
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

@@skip_name:
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 00FFFFFFh
    call SetTextColor

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+1F0h]
    call SelectObject

    mov ecx, 0
    mov edx, 1
    mov r8d, 00323232h
    call CreatePen
    mov rbx, rax

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, rax
    call SelectObject
    mov [rsp+1D8h], rax

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X - 5
    mov r8d, INFO_Y + 305
    xor r9, r9
    call MoveToEx

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X + 165
    mov r8d, INFO_Y + 305
    call LineTo

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+1D8h]
    call SelectObject

    mov rcx, rbx
    call DeleteObject

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsi].RENDERER_STATE.hFontSmall
    call SelectObject
    mov [rsp+1F0h], rax

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 00A0A0A0h
    call SetTextColor

    lea rcx, szAuthor
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 315
    lea r9, szAuthor
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, szName
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 335
    lea r9, szName
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, szEmail
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 355
    lea r9, szEmail
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    lea rcx, szWebsite
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 375
    lea r9, szWebsite
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+1F0h]
    call SelectObject

    mov al, [rdi].GAME_STATE.paused
    test al, al
    jz @@check_gameover
    mov al, [rdi].GAME_STATE.gameOver
    test al, al
    jnz @@check_gameover

    mov eax, [rsi].RENDERER_STATE.pausePulse
    add eax, 4
    and eax, 0FFh
    mov [rsi].RENDERER_STATE.pausePulse, eax

    mov ebx, eax
    sub ebx, 128
    test ebx, ebx
    jns @@pos_pulse
    neg ebx
@@pos_pulse:
    mov eax, 128
    sub eax, ebx
    add eax, 127
    
    mov ebx, eax
    shl ebx, 8
    or eax, ebx

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, eax
    call SetTextColor

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsi].RENDERER_STATE.hFontPause
    call SelectObject
    mov [rsp+1F0h], rax

    lea rcx, szPaused
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X
    mov r8d, INFO_Y + 420
    lea r9, szPaused
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+1F0h]
    call SelectObject

@@check_gameover:
    mov al, [rdi].GAME_STATE.gameOver
    test al, al
    jz @@done_overlays

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, 000000FFh
    call SetTextColor

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsi].RENDERER_STATE.hFontGameOver
    call SelectObject
    mov [rsp+1F0h], rax

    lea rcx, szGameOver
    call lstrlenA
    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov edx, INFO_X - 20
    mov r8d, INFO_Y + 420
    lea r9, szGameOver
    mov DWORD PTR [rsp+20h], eax
    call TextOutA

    mov rcx, [rsi].RENDERER_STATE.hdcMem
    mov rdx, [rsp+1F0h]
    call SelectObject

@@done_overlays:
    mov rsi, [rsp+210h]
    mov rdi, [rsp+218h]
    mov rbx, [rsp+200h]

    mov rsp, rbp
    pop rbp
    ret
DrawInfo ENDP

END
