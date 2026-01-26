INCLUDE data.inc
INCLUDE proto.inc

.CONST
; Window dimensions and constants
WINDOW_WIDTH        EQU 480         ; Main window client width in pixels
WINDOW_HEIGHT       EQU 570         ; Main window client height in pixels
CW_USEDEFAULT       EQU 80000000h   ; Let Windows choose default position

; Window style flags
WS_OVERLAPPED       EQU 00000000h   ; Base overlapped window
WS_CAPTION          EQU 00C00000h   ; Window has title bar
WS_SYSMENU          EQU 00080000h   ; Window has system menu
WS_THICKFRAME       EQU 00040000h   ; Window has sizing border
WS_MINIMIZEBOX      EQU 00020000h   ; Window has minimize button
WS_MAXIMIZEBOX      EQU 00010000h   ; Window has maximize button
WS_OVERLAPPEDWINDOW EQU 00CF0000h   ; Standard window with all decorations
WS_VISIBLE          EQU 10000000h   ; Window is initially visible

; Window class styles
CS_HREDRAW          EQU 0002h       ; Redraw on horizontal resize
CS_VREDRAW          EQU 0001h       ; Redraw on vertical resize
COLOR_BTNFACE       EQU 15          ; System button face color
IDC_ARROW           EQU 32512       ; Standard arrow cursor
SW_SHOWDEFAULT      EQU 10          ; Default show command

; Window messages
WM_CREATE           EQU 0001h       ; Window creation notification
WM_DESTROY          EQU 0002h       ; Window destruction notification
WM_PAINT            EQU 000Fh       ; Window needs repainting
WM_KEYDOWN          EQU 0100h       ; Key pressed
WM_COMMAND          EQU 0111h       ; Control notification or menu command
WM_TIMER            EQU 0113h       ; Timer event
WM_SETFONT          EQU 0030h       ; Set control font

; Virtual key codes
VK_SPACE            EQU 20h         ; Spacebar - hard drop
VK_LEFT             EQU 25h         ; Left arrow - move piece left
VK_UP               EQU 26h         ; Up arrow - rotate piece
VK_RIGHT            EQU 27h         ; Right arrow - move piece right
VK_DOWN             EQU 28h         ; Down arrow - soft drop
VK_P                EQU 50h         ; P key - pause/resume
VK_ESCAPE           EQU 1Bh         ; ESC key - exit application
VK_F2               EQU 71h         ; F2 key - new game

; Game timing
GAME_TIMER_ID       EQU 1           ; Timer identifier
GAME_TICK_MS        EQU 16          ; ~60 FPS (1000ms / 60)
EDIT_TIMER_ID       EQU 2           ; Edit name auto-save timer
EDIT_SAVE_DELAY_MS  EQU 1000        ; 1 second delay before auto-save

; Child window styles
WS_CHILD            EQU 40000000h   ; Child window
WS_BORDER           EQU 00800000h   ; Window has border
WS_CLIPCHILDREN     EQU 02000000h   ; Exclude child areas when drawing
SS_LEFT             EQU 0           ; Left-aligned static text
ES_AUTOHSCROLL      EQU 0080h       ; Auto-scroll text on overflow
BS_PUSHBUTTON       EQU 0           ; Standard push button
WS_EX_CLIENTEDGE    EQU 00000200h   ; 3D sunken edge

; Control IDs
IDC_EDIT_NAME       EQU 1001        ; Player name text input
IDC_BUTTON_CLEAR    EQU 1002        ; Clear high score button
IDC_BUTTON_START    EQU 1003        ; Pause/Resume button
IDC_BUTTON_GHOST    EQU 1004        ; Toggle ghost piece button

; Edit control notifications
EN_CHANGE           EQU 0300h       ; Text content changed
WM_CTLCOLOREDIT     EQU 0133h       ; Edit control color notification

; DWM constants
DWMWA_USE_IMMERSIVE_DARK_MODE EQU 20
DWMWA_SYSTEMBACKDROP_TYPE      EQU 38
DWMSBT_MAINWINDOW              EQU 2

.DATA
; String constants for UI
szClassName     DB "TetrisWindowClass", 0
szWindowTitle   DB "Tetris x64", 0
szSegoeUI       DB "Segoe UI", 0
szShell32       DB "shell32.dll", 0
szStaticClass   DB "STATIC", 0
szEditClass     DB "EDIT", 0
szButtonClass   DB "BUTTON", 0
szPlayerLabel   DB "Player:", 0
szPauseGame     DB "&Pause Game", 0
szResumeGame    DB "&Resume Game", 0
szClearRecord   DB "&Clear Record", 0
szGhostOn       DB "Ghost: ON", 0
szGhostOff      DB "Ghost: OFF", 0

; Global handles (64-bit pointers)
g_hInstance     DQ 0                ; Application instance handle
g_hWnd          DQ 0                ; Main window handle
g_hButtonStart  DQ 0                ; Pause/Resume button handle
g_hButtonClear  DQ 0                ; Clear Record button handle
g_hButtonGhost  DQ 0                ; Ghost toggle button handle
g_hEditName     DQ 0                ; Player name edit control handle
g_hBrushGreen   DQ 0                ; Light green brush for edit control

.DATA?
; Uninitialized data - must be 16-byte aligned for SIMD operations
ALIGN 16
g_game          GAME_STATE <>       ; Global game state
ALIGN 16
g_renderer      RENDERER_STATE <>   ; Global renderer state
ps              DB 80 DUP(?)        ; PAINTSTRUCT buffer for WM_PAINT

.CODE

ALIGN 16
; Window message handler - processes all window events
; CRITICAL x64 TRAP: Win64 calling convention requires:
; - 32 bytes shadow space (20h) for first 4 params (RCX, RDX, R8, R9)
; - Stack must be 16-byte aligned BEFORE call instruction
; - Non-volatile registers (RBX, RSI, RDI, R12-R15, RBP) must be preserved
WindowProc PROC
    push rbp
    mov rbp, rsp
    and rsp, -16                    ; TRAP: Ensure 16-byte stack alignment
    sub rsp, 400h                   ; Allocate shadow space + locals (increased for buffers)

    ; Save parameters (x64 fastcall: RCX=hWnd, RDX=uMsg, R8=wParam, R9=lParam)
    mov [rbp+10h], rcx              ; Store hWnd
    mov [rbp+18h], rdx              ; Store uMsg
    mov [rbp+20h], r8               ; Store wParam
    mov [rbp+28h], r9               ; Store lParam
    
    ; Dispatch message to appropriate handler
    cmp edx, WM_CREATE
    je HandleCreate
    cmp edx, WM_DESTROY
    je HandleDestroy
    cmp edx, WM_PAINT
    je HandlePaint
    cmp edx, WM_COMMAND
    je HandleCommand
    cmp edx, WM_TIMER
    je HandleTimer
    cmp edx, WM_KEYDOWN
    je HandleKeyDown
    cmp edx, WM_CTLCOLOREDIT
    je HandleCtlColorEdit

    ; No specific handler - pass to default Windows procedure
    mov rcx, [rbp+10h]
    mov rdx, [rbp+18h]
    mov r8,  [rbp+20h]
    mov r9,  [rbp+28h]
    call DefWindowProcA
    jmp ExitProc

HandleCreate:
    ; WM_CREATE: Initialize game and renderer, create UI controls
    lea rcx, g_game
    mov edx, 10
    mov r8d, 20
    call InitGame
    
    lea rcx, g_renderer
    mov rdx, [rbp+10h]
    call InitRenderer

    ; Get client area size and setup renderer backbuffer
    mov rcx, [rbp+10h]              ; hwnd
    lea rdx, [rsp+20h]              ; &rect
    call GetClientRect

    ; Extract width and height from RECT
    ; TRAP: RECT members are DWORDs (left, top, right, bottom)
    mov edx, DWORD PTR [rsp+28h]    ; rect.right (width)
    mov r8d, DWORD PTR [rsp+2Ch]    ; rect.bottom (height)
    lea rcx, g_renderer
    call ResizeRenderer

    ; Start initial game
    lea rcx, g_game
    call StartGame

    ; Create light green brush for edit control background
    mov ecx, 00E0FFE0h              ; Light green (BGR format)
    call CreateSolidBrush
    mov g_hBrushGreen, rax

    ; Create "Player:" static label
    ; TRAP: CreateWindowExA takes 12 params - first 4 in regs, rest on stack
    ; Stack params must be placed at [rsp+20h], [rsp+28h], etc.
    xor ecx, ecx                    ; dwExStyle = 0
    lea rdx, szStaticClass          ; lpClassName
    lea r8, szPlayerLabel           ; lpWindowName = "Player:"
    mov r9d, WS_CHILD OR WS_VISIBLE OR SS_LEFT  ; dwStyle
    mov QWORD PTR [rsp+20h], 10     ; x position
    mov QWORD PTR [rsp+28h], 533    ; y position
    mov QWORD PTR [rsp+30h], 100    ; width
    mov QWORD PTR [rsp+38h], 18     ; height
    mov rax, [rbp+10h]
    mov QWORD PTR [rsp+40h], rax    ; hWndParent
    mov QWORD PTR [rsp+48h], 0      ; hMenu
    mov rax, g_hInstance
    mov QWORD PTR [rsp+50h], rax    ; hInstance
    mov QWORD PTR [rsp+58h], 0      ; lpParam
    call CreateWindowExA

    ; Create player name text input box
    mov ecx, WS_EX_CLIENTEDGE       ; dwExStyle = sunken edge
    lea rdx, szEditClass
    xor r8, r8                      ; lpWindowName = NULL (empty initially)
    mov r9d, WS_CHILD OR WS_VISIBLE OR ES_AUTOHSCROLL OR WS_BORDER
    mov QWORD PTR [rsp+20h], 70     ; x
    mov QWORD PTR [rsp+28h], 530    ; y
    mov QWORD PTR [rsp+30h], 90     ; width
    mov QWORD PTR [rsp+38h], 24     ; height
    mov rax, [rbp+10h]
    mov QWORD PTR [rsp+40h], rax    ; hWndParent
    mov QWORD PTR [rsp+48h], IDC_EDIT_NAME  ; Control ID
    mov rax, g_hInstance
    mov QWORD PTR [rsp+50h], rax    ; hInstance
    mov QWORD PTR [rsp+58h], 0      ; lpParam
    call CreateWindowExA
    mov g_hEditName, rax

    ; Set initial text to saved player name (Unicode)
    mov rcx, g_hEditName
    lea rdx, g_game.playerName      ; Unicode string from registry
    call SetWindowTextW

    ; Force edit control to redraw with correct background color
    mov rcx, g_hEditName
    xor edx, edx
    xor r8d, r8d
    call InvalidateRect

    ; Create Pause/Resume game button
    xor ecx, ecx
    lea rdx, szButtonClass
    lea r8, szPauseGame             ; Initial text: "&Pause Game"
    mov r9d, WS_CHILD OR WS_VISIBLE OR BS_PUSHBUTTON
    mov QWORD PTR [rsp+20h], 170
    mov QWORD PTR [rsp+28h], 527
    mov QWORD PTR [rsp+30h], 105
    mov QWORD PTR [rsp+38h], 30
    mov rax, [rbp+10h]
    mov QWORD PTR [rsp+40h], rax
    mov QWORD PTR [rsp+48h], IDC_BUTTON_START
    mov rax, g_hInstance
    mov QWORD PTR [rsp+50h], rax
    mov QWORD PTR [rsp+58h], 0
    call CreateWindowExA
    mov g_hButtonStart, rax

    ; Create Clear Record button
    xor ecx, ecx
    lea rdx, szButtonClass
    lea r8, szClearRecord           ; Text: "&Clear Record"
    mov r9d, WS_CHILD OR WS_VISIBLE OR BS_PUSHBUTTON
    mov QWORD PTR [rsp+20h], 280
    mov QWORD PTR [rsp+28h], 527
    mov QWORD PTR [rsp+30h], 95
    mov QWORD PTR [rsp+38h], 30
    mov rax, [rbp+10h]
    mov QWORD PTR [rsp+40h], rax
    mov QWORD PTR [rsp+48h], IDC_BUTTON_CLEAR
    mov rax, g_hInstance
    mov QWORD PTR [rsp+50h], rax
    mov QWORD PTR [rsp+58h], 0
    call CreateWindowExA
    mov g_hButtonClear, rax

    ; Create Ghost piece toggle button
    xor ecx, ecx
    lea rdx, szButtonClass
    lea r8, szGhostOff              ; Initial text: "Ghost: OFF"
    mov r9d, WS_CHILD OR WS_VISIBLE OR BS_PUSHBUTTON
    mov QWORD PTR [rsp+20h], 380
    mov QWORD PTR [rsp+28h], 527
    mov QWORD PTR [rsp+30h], 90
    mov QWORD PTR [rsp+38h], 30
    mov rax, [rbp+10h]
    mov QWORD PTR [rsp+40h], rax
    mov QWORD PTR [rsp+48h], IDC_BUTTON_GHOST
    mov rax, g_hInstance
    mov QWORD PTR [rsp+50h], rax
    mov QWORD PTR [rsp+58h], 0
    call CreateWindowExA
    mov g_hButtonGhost, rax
	
	; Create smaller font for buttons (default size minus 2)
    mov ecx, -14
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
    mov rbx, rax
    
    mov rcx, g_hButtonStart
    mov edx, 30h
    mov r8, rbx
    mov r9d, 1
    call SendMessageA
    
    mov rcx, g_hButtonClear
    mov edx, 30h
    mov r8, rbx
    mov r9d, 1
    call SendMessageA
    
    mov rcx, g_hButtonGhost
    mov edx, 30h
    mov r8, rbx
    mov r9d, 1
    call SendMessageA

    ; Create game timer for 60 FPS updates
    mov rcx, [rbp+10h]              ; hWnd
    mov edx, GAME_TIMER_ID          ; nIDEvent
    mov r8d, GAME_TICK_MS           ; uElapse (16ms for ~60 FPS)
    xor r9d, r9d                    ; lpTimerFunc = NULL
    call SetTimer

    xor eax, eax                    ; Return 0 (message handled)
    jmp ExitProc

HandlePaint:
    ; WM_PAINT: Redraw game board and UI
    mov rcx, [rbp+10h]
    lea rdx, ps
    call BeginPaint
    
    mov r8, rax
    lea rcx, g_renderer
    lea rdx, g_game
    call RenderGame
    
    mov rcx, [rbp+10h]
    lea rdx, ps
    call EndPaint
    
    xor eax, eax
    jmp ExitProc

HandleCommand:
    mov rax, [rbp+20h]
    mov r10, rax
    and eax, 0FFFFh

    cmp eax, IDC_EDIT_NAME
    je CmdEditName
    cmp eax, IDC_BUTTON_START
    je CmdPauseResume
    cmp eax, IDC_BUTTON_CLEAR
    je CmdClearRecord
    cmp eax, IDC_BUTTON_GHOST
    je CmdToggleGhost
    jmp CmdDone

CmdEditName:
    shr r10, 16
    cmp r10w, EN_CHANGE
    jne CmdDone

    ; Update in-memory player name immediately
    mov rcx, g_hEditName
    lea rdx, [rsp+100h]
    mov r8d, 128
    call GetWindowTextW

    lea rcx, g_game
    lea rdx, [rsp+100h]
    call SetPlayerName

    ; Restart auto-save timer (1 second delay)
    ; Kill old timer if exists
    mov rcx, [rbp+10h]              ; hwnd
    mov edx, EDIT_TIMER_ID
    call KillTimer

    ; Set new timer for 1 second
    mov rcx, [rbp+10h]              ; hwnd
    mov edx, EDIT_TIMER_ID
    mov r8d, EDIT_SAVE_DELAY_MS
    xor r9d, r9d                    ; lpTimerProc = NULL
    call SetTimer

    ; Force edit control to redraw with new background color
    mov rcx, g_hEditName
    xor edx, edx
    xor r8d, r8d
    call InvalidateRect

    jmp CmdDone

CmdPauseResume:
    lea rcx, g_game
    call TogglePause

    mov al, [g_game].GAME_STATE.paused
    test al, al
    jz @@set_pause
    mov rcx, g_hButtonStart
    lea rdx, szResumeGame
    call SetWindowTextA
    jmp @@redraw
@@set_pause:
    mov rcx, g_hButtonStart
    lea rdx, szPauseGame
    call SetWindowTextA
@@redraw:
    mov rcx, [rbp+10h]
    call SetFocus

    mov rcx, [rbp+10h]
    xor edx, edx
    xor r8d, r8d
    call InvalidateRect
    jmp CmdDone

CmdClearRecord:
    mov DWORD PTR [g_game].GAME_STATE.highScore, 0
    lea rax, [g_game].GAME_STATE.highScoreName
    mov WORD PTR [rax], 0

    call ClearRegistry

    ; Restore PlayerName to registry after clearing
    mov rcx, g_hEditName
    lea rdx, [rsp+100h]
    mov r8d, 128
    call GetWindowTextW

    test eax, eax
    jz @@skip_save

    lea rcx, [rsp+100h]
    call SavePlayerName

@@skip_save:
    mov rcx, [rbp+10h]
    call SetFocus

    mov rcx, [rbp+10h]
    xor edx, edx
    xor r8d, r8d
    call InvalidateRect
    jmp CmdDone

CmdToggleGhost:
    mov al, [g_game].GAME_STATE.showGhost
    xor al, 1
    mov [g_game].GAME_STATE.showGhost, al

    test al, al
    jz @@set_off
    mov rcx, g_hButtonGhost
    lea rdx, szGhostOn
    call SetWindowTextA
    jmp @@ghost_redraw
@@set_off:
    mov rcx, g_hButtonGhost
    lea rdx, szGhostOff
    call SetWindowTextA
@@ghost_redraw:
    mov rcx, [rbp+10h]
    call SetFocus

    mov rcx, [rbp+10h]
    xor edx, edx
    xor r8d, r8d
    call InvalidateRect
    jmp CmdDone

CmdDone:
    xor eax, eax
    jmp ExitProc

HandleTimer:
    mov rax, [rbp+20h]              ; wParam = timer ID
    cmp rax, GAME_TIMER_ID
    je @@game_timer
    cmp rax, EDIT_TIMER_ID
    je @@edit_timer
    jmp @@timer_done

@@game_timer:
    lea rcx, g_game
    mov edx, GAME_TICK_MS
    call UpdateGame

    mov rcx, [rbp+10h]
    xor edx, edx
    xor r8d, r8d
    call InvalidateRect
    jmp @@timer_done

@@edit_timer:
    ; Save player name and remove focus from edit control
    mov rcx, g_hEditName
    lea rdx, [rsp+100h]
    mov r8d, 128
    call GetWindowTextW
    mov [rsp+0F8h], eax             ; Save text length

    ; Save to registry if not empty
    test eax, eax
    jz @@skip_save_timer

    lea rcx, [rsp+100h]
    call SavePlayerName

@@skip_save_timer:
    ; Remove focus from edit - set focus to main window
    mov rcx, [rbp+10h]              ; Main window handle
    call SetFocus

    ; Kill the timer
    mov rcx, [rbp+10h]              ; hwnd
    mov edx, EDIT_TIMER_ID
    call KillTimer

@@timer_done:
    xor eax, eax
    jmp ExitProc

HandleKeyDown:
    mov rax, [rbp+20h]
    
    cmp eax, VK_LEFT
    je DoLeft
    cmp eax, VK_RIGHT
    je DoRight
    cmp eax, VK_UP
    je DoRotate
    cmp eax, VK_DOWN
    je DoDown
    cmp eax, VK_SPACE
    je DoDrop
    cmp eax, VK_P
    je DoPause
    cmp eax, VK_F2
    je DoF2
    cmp eax, VK_ESCAPE
    je DoEscape
    jmp KeyDone

DoLeft:
    lea rcx, g_game
    call MoveLeft
    jmp KeyRedraw
DoRight:
    lea rcx, g_game
    call MoveRight
    jmp KeyRedraw
DoRotate:
    lea rcx, g_game
    call RotatePiece
    jmp KeyRedraw
DoDown:
    lea rcx, g_game
    mov edx, 1
    call MoveDown
    jmp KeyRedraw
DoDrop:
    lea rcx, g_game
    call DropPiece
    jmp KeyRedraw
DoPause:
    jmp CmdPauseResume
DoF2:
    lea rcx, g_game
    call StartGame
    
    mov rcx, g_hButtonStart
    lea rdx, szPauseGame
    call SetWindowTextA
    
    jmp KeyRedraw
DoEscape:
    xor ecx, ecx
    call PostQuitMessage
    jmp KeyDone

KeyRedraw:
    mov rcx, [rbp+10h]
    xor edx, edx
    xor r8d, r8d
    call InvalidateRect

KeyDone:
    xor eax, eax
    jmp ExitProc

HandleCtlColorEdit:
    ; WM_CTLCOLOREDIT: Set edit control background color
    ; wParam (R8/[rbp+20h]) = HDC, lParam (R9/[rbp+28h]) = HWND of edit control
    mov rax, [rbp+28h]              ; Get HWND from lParam
    cmp rax, g_hEditName
    jne @@default_color

    ; Check if edit control has text
    mov rcx, g_hEditName
    lea rdx, [rsp+200h]             ; Use different buffer to avoid conflicts
    mov r8d, 128
    call GetWindowTextW

    test eax, eax                   ; Returns length of text
    jz @@default_color              ; No text - use default color

    ; Set light green background for text input
    mov rcx, [rbp+20h]              ; HDC from wParam
    mov edx, 00E0FFE0h              ; Light green (BGR format)
    call SetBkColor

    mov rcx, [rbp+20h]
    mov edx, 1                      ; TRANSPARENT mode
    call SetBkMode

    ; Return global light green brush handle
    mov rax, g_hBrushGreen
    jmp ExitProc

@@default_color:
    ; Return default system color brush
    mov rcx, [rbp+10h]
    mov rdx, [rbp+18h]
    mov r8,  [rbp+20h]
    mov r9,  [rbp+28h]
    call DefWindowProcA
    jmp ExitProc

HandleDestroy:
    ; Clean up brush resource
    mov rcx, g_hBrushGreen
    test rcx, rcx
    jz @@skip_brush
    call DeleteObject
@@skip_brush:
    xor ecx, ecx
    call PostQuitMessage
    xor eax, eax
    jmp ExitProc

ExitProc:
    mov rsp, rbp
    pop rbp
    ret
WindowProc ENDP

; Application entry point - registers window class, creates main window, runs message loop
; Sets up dark mode title bar and Mica backdrop on Windows 11
WinMain PROC
    push r14
    push r15
    sub rsp, 0B8h

    mov DWORD PTR [rsp+60h], 80
    mov DWORD PTR [rsp+64h], CS_HREDRAW OR CS_VREDRAW
    lea rax, WindowProc
    mov QWORD PTR [rsp+68h], rax
    mov DWORD PTR [rsp+70h], 0
    mov DWORD PTR [rsp+74h], 0
    mov rax, g_hInstance
    mov QWORD PTR [rsp+78h], rax
    mov QWORD PTR [rsp+80h], 0
    
    xor ecx, ecx
    mov edx, IDC_ARROW
    call LoadCursorA
    mov QWORD PTR [rsp+88h], rax
    
    mov QWORD PTR [rsp+90h], COLOR_BTNFACE + 1
	
	lea rcx, szShell32
	call LoadLibraryA
	mov [rsp+0B0h], rax ; Save hShell

	mov rcx, g_hInstance
	lea rdx, szShell32
	mov r8d, 80
	call ExtractIconA
	mov QWORD PTR [rsp+80h], rax ; wc.hIcon
	mov QWORD PTR [rsp+0A8h], rax ; wc.hIconSm

	mov rcx, [rsp+0B0h]
	call FreeLibrary

    mov QWORD PTR [rsp+98h], 0
    lea rax, szClassName
    mov QWORD PTR [rsp+0A0h], rax
    mov QWORD PTR [rsp+0A8h], 0
    
    lea rcx, [rsp+60h]
    call RegisterClassExA

    mov DWORD PTR [rsp+20h], 0
    mov DWORD PTR [rsp+24h], 0
    mov DWORD PTR [rsp+28h], WINDOW_WIDTH
    mov DWORD PTR [rsp+2Ch], WINDOW_HEIGHT
    lea rcx, [rsp+20h]
    mov edx, WS_OVERLAPPEDWINDOW AND NOT WS_THICKFRAME AND NOT WS_MAXIMIZEBOX
    xor r8d, r8d
    call AdjustWindowRect

    mov eax, DWORD PTR [rsp+28h]
    sub eax, DWORD PTR [rsp+20h]
    mov r14d, eax

    mov eax, DWORD PTR [rsp+2Ch]
    sub eax, DWORD PTR [rsp+24h]
    mov r15d, eax

    xor ecx, ecx
    lea rdx, szClassName
    lea r8, szWindowTitle
    mov r9d, WS_OVERLAPPEDWINDOW AND NOT WS_THICKFRAME AND NOT WS_MAXIMIZEBOX OR WS_CLIPCHILDREN

    mov rax, CW_USEDEFAULT
    mov QWORD PTR [rsp+20h], rax
    mov QWORD PTR [rsp+28h], rax
    movsxd rax, r14d
    mov QWORD PTR [rsp+30h], rax
    movsxd rax, r15d
    mov QWORD PTR [rsp+38h], rax
    mov QWORD PTR [rsp+40h], 0
    mov QWORD PTR [rsp+48h], 0
    mov rax, g_hInstance
    mov QWORD PTR [rsp+50h], rax
    mov QWORD PTR [rsp+58h], 0
    
    call CreateWindowExA
    mov g_hWnd, rax
    
    test rax, rax
    jz @fail

    ; Enable Dark Mode for title bar
    mov rcx, g_hWnd
    mov edx, DWMWA_USE_IMMERSIVE_DARK_MODE
    lea r8, [rsp+58h]               ; Use stack for attribute value
    mov DWORD PTR [r8], 1           ; TRUE
    mov r9d, 4                      ; sizeof(DWORD)
    call DwmSetWindowAttribute

    ; Enable Mica backdrop effect (Windows 11)
    mov rcx, g_hWnd
    mov edx, DWMWA_SYSTEMBACKDROP_TYPE
    lea r8, [rsp+58h]
    mov DWORD PTR [r8], DWMSBT_MAINWINDOW
    mov r9d, 4
    call DwmSetWindowAttribute
    
    mov rcx, g_hWnd
    mov edx, SW_SHOWDEFAULT
    call ShowWindow
    
    mov rcx, g_hWnd
    call UpdateWindow
    
@msgloop:
    lea rcx, [rsp+60h]
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call GetMessageA
    
    test eax, eax
    jle @exitLoop
    
    lea rcx, [rsp+60h]
    call TranslateMessage
    
    lea rcx, [rsp+60h]
    call DispatchMessageA
    jmp @msgloop

@exitLoop:
    mov eax, [rsp+60h+16]
    jmp @ret

@fail:
    mov eax, 1

@ret:
    add rsp, 0B8h
    pop r15
    pop r14
    ret
WinMain ENDP

; Entry point callable from C++ host application
; Returns: EAX = exit code from WinMain
TetrisMain PROC
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 20h

    xor ecx, ecx
    call GetModuleHandleA
    mov g_hInstance, rax

    mov rcx, rax
    xor edx, edx
    xor r8, r8
    mov r9d, SW_SHOWDEFAULT
    call WinMain

    mov rsp, rbp
    pop rbp
    ret
TetrisMain ENDP

END