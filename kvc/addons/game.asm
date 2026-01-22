INCLUDE data.inc
INCLUDE proto.inc

.DATA
ALIGN 16
; Tetromino shape templates: I, O, Z, S, T, L, J
; Format: x0,y0, x1,y1, x2,y2, x3,y3 (4 blocks per shape)
; TRAP: Each shape is 32 bytes (8 dwords) for 4 blocks
SHAPE_TEMPLATES dd 0,1,1,1,2,1,3,1  ; I-piece (horizontal line)
    dd 0,0,1,0,0,1,1,1              ; O-piece (square)
    dd 1,0,0,1,1,1,2,1              ; Z-piece (left zigzag)
    dd 0,1,1,1,1,0,2,0              ; S-piece (right zigzag)
    dd 0,0,1,0,1,1,2,1              ; T-piece (T-shape)
    dd 0,0,0,1,1,1,2,1              ; L-piece (left L)
    dd 2,0,0,1,1,1,2,1              ; J-piece (right L)

; 7-bag randomizer state for fair piece distribution
bagBytes db 0, 1, 2, 3, 4, 5, 6     ; Bag containing all 7 piece types
ALIGN 4
bagIndex dd 7                        ; Current position in bag (7 = empty, needs reshuffle)

.CODE
ALIGN 16

; Board size safety limits
BOARD_MAX_CELLS equ 400              ; Maximum total cells (prevents buffer overflow)
BOARD_MIN_DIM equ 4                  ; Minimum width/height for playable game

; Initialize game state with board dimensions
; TRAP x64: Args are RCX=pGame, EDX=boardWidth, R8D=boardHeight (not stack!)
; Non-volatile registers (RSI, RDI) must be preserved
InitGame PROC pGame:QWORD, boardWidth:DWORD, boardHeight:DWORD
    push rsi
    push rdi
    sub rsp, 20h                     ; TRAP: Shadow space required for Win64 API

    mov rsi, rcx                     ; RSI = pGame pointer
    mov eax, edx                     ; EAX = boardWidth
    imul eax, r8d                    ; EAX = boardWidth * boardHeight
    cmp eax, BOARD_MAX_CELLS
    jg @@invalid_size
    cmp edx, BOARD_MIN_DIM
    jl @@invalid_size
    cmp r8d, BOARD_MIN_DIM
    jl @@invalid_size

    ; Dimensions are valid - store them
    mov [rsi].GAME_STATE.boardWidth, edx
    mov [rsi].GAME_STATE.boardHeight, r8d
    jmp @@dimensions_ok

@@invalid_size:
    ; Fall back to safe default 10x20 board
    mov DWORD PTR [rsi].GAME_STATE.boardWidth, 10
    mov DWORD PTR [rsi].GAME_STATE.boardHeight, 20

@@dimensions_ok:
    ; Reset game metrics to defaults
    mov DWORD PTR [rsi].GAME_STATE.score, 0
    mov DWORD PTR [rsi].GAME_STATE.lines, 0
    mov DWORD PTR [rsi].GAME_STATE.level, 1
    mov BYTE PTR [rsi].GAME_STATE.gameOver, 0
    mov BYTE PTR [rsi].GAME_STATE.paused, 0
    mov BYTE PTR [rsi].GAME_STATE.showGhost, 0

    ; Clear entire board memory to empty (0)
    lea rax, [rsi].GAME_STATE.board
    mov ecx, [rsi].GAME_STATE.boardHeight
    imul ecx, [rsi].GAME_STATE.boardWidth
    xor edx, edx
@@clear_loop:
    mov byte ptr [rax], dl           ; Write 0 (empty cell)
    inc rax
    dec ecx
    jnz @@clear_loop

    ; Seed RNG with current tick count for random piece generation
    call GetTickCount
    mov [rsi].GAME_STATE.rngSeed, eax
    mov DWORD PTR bagIndex, 7        ; Force bag reshuffle on first piece

    ; Load persistent data from Windows registry
    mov rcx, rsi
    call LoadHighScore

    mov rcx, rsi
    call LoadPlayerName

    ; Generate first two pieces (next + current)
    ; TRAP: LEA gets address, RSI already contains pGame
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.nextPiece
    call GenerateRandomPiece

    mov rcx, rsi
    call SpawnNewPiece

    add rsp, 20h                     ; Clean up shadow space
    pop rdi
    pop rsi
    ret
InitGame ENDP

; Reset game state (new game from Game Over)
; TRAP: Must preserve RSI, RDI (non-volatile in x64 calling convention)
StartGame PROC pGame:QWORD
    push rsi
    push rdi
    sub rsp, 20h                     ; Shadow space

    mov rsi, rcx                     ; RSI = pGame

    ; Clear entire board to empty
    lea rax, [rsi].GAME_STATE.board
    mov ecx, [rsi].GAME_STATE.boardHeight
    imul ecx, [rsi].GAME_STATE.boardWidth
    xor edx, edx
@@clear_loop:
    mov byte ptr [rax], dl
    inc rax
    dec ecx
    jnz @@clear_loop

    ; Reset game state to defaults (keep high score and player name)
    mov DWORD PTR [rsi].GAME_STATE.score, 0
    mov DWORD PTR [rsi].GAME_STATE.lines, 0
    mov DWORD PTR [rsi].GAME_STATE.level, 1
    mov BYTE PTR [rsi].GAME_STATE.gameOver, 0
    mov BYTE PTR [rsi].GAME_STATE.paused, 0

    ; Reset 7-bag randomizer for new game
    mov DWORD PTR bagIndex, 7

    ; Spawn initial pieces
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.nextPiece
    call GenerateRandomPiece

    mov rcx, rsi
    call SpawnNewPiece

    add rsp, 20h
    pop rdi
    pop rsi
    ret
StartGame ENDP

; Generate random piece using 7-bag algorithm (ensures fair distribution)
; TRAP x64: Args are RCX=pGame, RDX=pPiece (output structure)
; The 7-bag algorithm guarantees all 7 pieces appear once every 7 pieces
GenerateRandomPiece PROC pGame:QWORD, pPiece:QWORD
    push rsi
    push rdi
    push rbx
    sub rsp, 28h                     ; Shadow space + local storage

    mov rsi, rcx                     ; RSI = pGame
    mov rdi, rdx                     ; RDI = pPiece (output)

    ; Check if bag needs reshuffling (index >= 7 means empty bag)
    cmp DWORD PTR bagIndex, 7
    jl @@get_from_bag

    ; Fisher-Yates shuffle algorithm for 7-bag
    mov ecx, 6                       ; Start from index 6, shuffle down to 0
@@shuffle_loop:
    mov DWORD PTR [rsp+20h], ecx
    
    mov eax, [rsi].GAME_STATE.rngSeed
    imul eax, 1103515245
    add eax, 12345
    mov [rsi].GAME_STATE.rngSeed, eax
    
    shr eax, 16
    and eax, 7FFFh
    xor edx, edx
    mov ecx, DWORD PTR [rsp+20h]
    inc ecx
    div ecx
    
    mov ecx, DWORD PTR [rsp+20h]
    lea rax, bagBytes
    mov bl, [rax + rcx]
    mov bh, [rax + rdx]
    mov [rax + rcx], bh
    mov [rax + rdx], bl
    
    dec ecx
    jns @@shuffle_loop
    
    mov DWORD PTR bagIndex, 0
    
@@get_from_bag:
    ; Pull next piece type from shuffled bag
    mov eax, bagIndex
    lea rcx, bagBytes
    movzx edx, byte ptr [rcx + rax]  ; EDX = piece type (0-6)
    inc bagIndex                     ; Move to next piece in bag
    mov [rdi].PIECE.shapeType, dl

    ; Center horizontally at top of board
    mov eax, [rsi].GAME_STATE.boardWidth
    shr eax, 1                       ; Divide by 2
    dec eax                          ; Adjust for piece width
    mov [rdi].PIECE.x, eax
    mov DWORD PTR [rdi].PIECE.y, 0
    mov DWORD PTR [rdi].PIECE.yFloat, 0

    ; Copy block template from SHAPE_TEMPLATES
    ; TRAP: Each shape is 32 bytes (8 dwords), so multiply by 32
    movzx eax, dl
    mov ebx, eax
    shl eax, 5                       ; Multiply by 32 (2^5)
    lea rcx, SHAPE_TEMPLATES
    add rcx, rax                     ; RCX = &SHAPE_TEMPLATES[shapeType]

    ; Copy 8 dwords (4 blocks * 2 coords each) to piece structure
    lea rax, [rdi].PIECE.blocks
    mov r8, rcx
    mov ecx, 8
@@copy_blocks:
    mov edx, DWORD PTR [r8]
    mov DWORD PTR [rax], edx
    add r8, 4
    add rax, 4
    dec ecx
    jnz @@copy_blocks

    ; Set color (shapeType + 1)
    inc bl
    mov [rdi].PIECE.color, bl

    add rsp, 28h
    pop rbx
    pop rdi
    pop rsi
    ret
GenerateRandomPiece ENDP

SpawnNewPiece PROC pGame:QWORD
    push rsi
    push rdi
    sub rsp, 20h
    
    mov rsi, rcx
    lea rdi, [rsi].GAME_STATE.currentPiece
    lea rax, [rsi].GAME_STATE.nextPiece
    
    mov ecx, 48 / 8
@@copy_loop:
    mov rdx, QWORD PTR [rax]
    mov QWORD PTR [rdi], rdx
    add rax, 8
    add rdi, 8
    dec ecx
    jnz @@copy_loop
    
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.nextPiece
    call GenerateRandomPiece
    
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    
    test eax, eax
    jz @@no_collision
    mov BYTE PTR [rsi].GAME_STATE.gameOver, 1
    
@@no_collision:
    add rsp, 20h
    pop rdi
    pop rsi
    ret
SpawnNewPiece ENDP

CheckCollision PROC pGame:QWORD, pPiece:QWORD
    push rsi
    push rdi
    
    mov rsi, rcx
    mov rdi, rdx
    
    xor ecx, ecx
@@block_loop:
    movsxd rax, [rdi].PIECE.blocks[rcx*8].x
    add eax, [rdi].PIECE.x
    movsxd rdx, [rdi].PIECE.blocks[rcx*8].y
    add edx, [rdi].PIECE.y
    
    test eax, eax
    jl @@collision
    cmp eax, [rsi].GAME_STATE.boardWidth
    jge @@collision
    
    test edx, edx
    jl @@collision
    cmp edx, [rsi].GAME_STATE.boardHeight
    jge @@collision
    
    imul edx, [rsi].GAME_STATE.boardWidth
    add edx, eax
    movzx eax, BYTE PTR [rsi].GAME_STATE.board[rdx]
    test al, al
    jnz @@collision
    
    inc ecx
    cmp ecx, 4
    jl @@block_loop
    
    xor eax, eax
    jmp @@exit_proc

@@collision:
    mov eax, 1

@@exit_proc:
    pop rdi
    pop rsi
    ret
CheckCollision ENDP

LockPiece PROC pGame:QWORD
    push rsi
    push rdi
    push rbx
    sub rsp, 28h
    
    mov rsi, rcx
    lea rdi, [rsi].GAME_STATE.currentPiece
    movzx ebx, [rdi].PIECE.color
    mov edx, [rdi].PIECE.x
    mov r8d, [rdi].PIECE.y
    
    xor ecx, ecx
@@place_loop:
    cmp ecx, 4
    jge @@place_done
    
    mov eax, [rdi + PIECE.blocks + rcx*8]
    add eax, edx
    mov r9d, [rdi + PIECE.blocks + rcx*8 + 4]
    add r9d, r8d
    
    imul r9d, [rsi].GAME_STATE.boardWidth
    add r9d, eax
    lea rax, [rsi].GAME_STATE.board
    mov byte ptr [rax + r9], bl
    
    inc ecx
    jmp @@place_loop
    
@@place_done:
    mov rcx, rsi
    call ClearFullLines
    
    test eax, eax
    jz @@no_lines
    
    add [rsi].GAME_STATE.lines, eax
    
    mov ecx, eax
    imul ecx, ecx
    imul ecx, 100
    imul ecx, [rsi].GAME_STATE.level
    add [rsi].GAME_STATE.score, ecx
    
    mov eax, [rsi].GAME_STATE.lines
    xor edx, edx
    mov ecx, 10
    div ecx
    inc eax
    mov [rsi].GAME_STATE.level, eax
    
    mov eax, [rsi].GAME_STATE.score
    cmp eax, [rsi].GAME_STATE.highScore
    jle @@no_lines
    
    mov rcx, rsi
    call SaveHighScore
    
@@no_lines:
    mov rcx, rsi
    call SpawnNewPiece

    add rsp, 28h
    pop rbx
    pop rdi
    pop rsi
    ret
LockPiece ENDP

ClearFullLines PROC pGame:QWORD
    push rsi
    push rdi
    push rbx
    sub rsp, 28h
    
    mov rsi, rcx
    xor ebx, ebx
    mov ecx, [rsi].GAME_STATE.boardHeight
    dec ecx
    
@@outer_loop:
    cmp ecx, 0
    jl @@done
    
    mov edi, ecx
    imul edi, [rsi].GAME_STATE.boardWidth
    lea rax, [rsi].GAME_STATE.board
    add rdi, rax
    
    mov edx, 1
    xor r8d, r8d
@@check_row:
    cmp byte ptr [rdi + r8], 0
    je @@not_full
    inc r8d
    cmp r8d, [rsi].GAME_STATE.boardWidth
    jl @@check_row
    jmp @@is_full
    
@@not_full:
    xor edx, edx
    
@@is_full:
    test edx, edx
    jz @@next_row
    
    inc ebx
    mov r9d, ecx
    
@@shift_down:
    cmp r9d, 0
    jle @@clear_top
    
    mov r10d, r9d
    imul r10d, [rsi].GAME_STATE.boardWidth
    dec r9d
    mov r11d, r9d
    imul r11d, [rsi].GAME_STATE.boardWidth
    
    lea rax, [rsi].GAME_STATE.board
    add r10, rax
    add r11, rax
    
    xor r8d, r8d
@@copy_row:
    mov dl, byte ptr [r11 + r8]
    mov byte ptr [r10 + r8], dl
    inc r8d
    cmp r8d, [rsi].GAME_STATE.boardWidth
    jl @@copy_row
    
    jmp @@shift_down
    
@@clear_top:
    lea rdi, [rsi].GAME_STATE.board
    xor r8d, r8d
@@clear_loop:
    mov byte ptr [rdi + r8], 0
    inc r8d
    cmp r8d, [rsi].GAME_STATE.boardWidth
    jl @@clear_loop
    jmp @@outer_loop
    
@@next_row:
    dec ecx
    jmp @@outer_loop
    
@@done:
    mov eax, ebx
    add rsp, 28h
    pop rbx
    pop rdi
    pop rsi
    ret
ClearFullLines ENDP

UpdateGame PROC pGame:QWORD, deltaTimeMs:DWORD
    push rsi
    sub rsp, 28h
    
    mov rsi, rcx
    
    cmp BYTE PTR [rsi].GAME_STATE.gameOver, 0
    jne @@exit_update
    cmp BYTE PTR [rsi].GAME_STATE.paused, 0
    jne @@exit_update
    
    mov eax, [rsi].GAME_STATE.level
    dec eax
    imul eax, 50
    add eax, 300
    imul eax, edx
    shr eax, 3
    add [rsi].GAME_STATE.yFloat, eax
    
@@check_fall:
    cmp DWORD PTR [rsi].GAME_STATE.yFloat, 10000
    jl @@exit_update
    sub DWORD PTR [rsi].GAME_STATE.yFloat, 10000
    
    mov eax, [rsi].GAME_STATE.currentPiece.y
    inc eax
    mov [rsi].GAME_STATE.currentPiece.y, eax
    
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    
    test eax, eax
    jz @@check_fall
    
    dec DWORD PTR [rsi].GAME_STATE.currentPiece.y
    mov DWORD PTR [rsi].GAME_STATE.yFloat, 0
    
    mov rcx, rsi
    call LockPiece
    
@@exit_update:
    add rsp, 28h
    pop rsi
    ret
UpdateGame ENDP

MoveLeft PROC pGame:QWORD
    push rsi
    sub rsp, 28h
    
    mov rsi, rcx
    
    cmp BYTE PTR [rsi].GAME_STATE.gameOver, 0
    jne @@exit
    
    dec DWORD PTR [rsi].GAME_STATE.currentPiece.x
    
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    
    test eax, eax
    jz @@exit
    inc DWORD PTR [rsi].GAME_STATE.currentPiece.x
    
@@exit:
    add rsp, 28h
    pop rsi
    ret
MoveLeft ENDP

MoveRight PROC pGame:QWORD
    push rsi
    sub rsp, 28h
    
    mov rsi, rcx
    
    cmp BYTE PTR [rsi].GAME_STATE.gameOver, 0
    jne @@exit
    
    inc DWORD PTR [rsi].GAME_STATE.currentPiece.x
    
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    
    test eax, eax
    jz @@exit
    dec DWORD PTR [rsi].GAME_STATE.currentPiece.x
    
@@exit:
    add rsp, 28h
    pop rsi
    ret
MoveRight ENDP

MoveDown PROC pGame:QWORD, dy:DWORD
    push rsi
    push rbx
    sub rsp, 28h
    
    mov rsi, rcx
    mov ebx, edx
    
    cmp BYTE PTR [rsi].GAME_STATE.gameOver, 0
    jne @@failed
    cmp BYTE PTR [rsi].GAME_STATE.paused, 0
    jne @@failed
    
    add [rsi].GAME_STATE.currentPiece.y, ebx
    
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    
    test eax, eax
    jz @@success
    
    sub [rsi].GAME_STATE.currentPiece.y, ebx
    
    mov rcx, rsi
    call LockPiece
    
@@failed:
    xor eax, eax
    jmp @@exit
    
@@success:
    mov eax, 1
    
@@exit:
    add rsp, 28h
    pop rbx
    pop rsi
    ret
MoveDown ENDP

RotatePiece PROC pGame:QWORD
    LOCAL backupBlocks[8]:DWORD
    push rsi
    push rdi
    push rbx
    sub rsp, 40h
    
    mov rsi, rcx
    
    cmp BYTE PTR [rsi].GAME_STATE.gameOver, 0
    jne @@exit
    
    lea rdi, [rsi].GAME_STATE.currentPiece
    
    cmp BYTE PTR [rdi].PIECE.shapeType, 1
    je @@exit
    
    lea r8, [rsp+20h]
    lea r9, [rdi + PIECE.blocks]
    mov ecx, 8
@@backup_loop:
    mov eax, DWORD PTR [r9]
    mov DWORD PTR [r8], eax
    add r9, 4
    add r8, 4
    dec ecx
    jnz @@backup_loop
    
    mov ecx, 1
    mov edx, 1
    
    xor r8d, r8d
@@rotate_loop:
    cmp r8d, 4
    jge @@rotate_done
    
    mov eax, [rdi + PIECE.blocks + r8*8]
    sub eax, ecx
    mov r9d, [rdi + PIECE.blocks + r8*8 + 4]
    sub r9d, edx
    
    mov r10d, r9d
    neg r10d
    add r10d, ecx
    mov [rdi + PIECE.blocks + r8*8], r10d
    
    add eax, edx
    mov [rdi + PIECE.blocks + r8*8 + 4], eax
    
    inc r8d
    jmp @@rotate_loop
    
@@rotate_done:
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    
    test eax, eax
    jz @@exit
    
    movzx ebx, BYTE PTR [rdi].PIECE.shapeType
    cmp ebx, 0
    jne @@try_normal
    
    inc DWORD PTR [rsi].GAME_STATE.currentPiece.x
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    test eax, eax
    jz @@exit
    
    sub DWORD PTR [rsi].GAME_STATE.currentPiece.x, 2
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    test eax, eax
    jz @@exit
    
    add DWORD PTR [rsi].GAME_STATE.currentPiece.x, 3
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    test eax, eax
    jz @@exit
    
    sub DWORD PTR [rsi].GAME_STATE.currentPiece.x, 4
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    test eax, eax
    jz @@exit
    
    add DWORD PTR [rsi].GAME_STATE.currentPiece.x, 2
    jmp @@restore
    
@@try_normal:
    inc DWORD PTR [rsi].GAME_STATE.currentPiece.x
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    test eax, eax
    jz @@exit
    
    sub DWORD PTR [rsi].GAME_STATE.currentPiece.x, 2
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    test eax, eax
    jz @@exit
    
    add DWORD PTR [rsi].GAME_STATE.currentPiece.x, 3
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    test eax, eax
    jz @@exit
    
    sub DWORD PTR [rsi].GAME_STATE.currentPiece.x, 2
    
@@restore:
    lea r8, [rsp+20h]
    lea r9, [rdi + PIECE.blocks]
    mov ecx, 8
@@restore_loop:
    mov eax, DWORD PTR [r8]
    mov DWORD PTR [r9], eax
    add r8, 4
    add r9, 4
    dec ecx
    jnz @@restore_loop
    
@@exit:
    add rsp, 40h
    pop rbx
    pop rdi
    pop rsi
    ret
RotatePiece ENDP

DropPiece PROC pGame:QWORD
    push rsi
    sub rsp, 28h
    
    mov rsi, rcx
    
    cmp BYTE PTR [rsi].GAME_STATE.gameOver, 0
    jne @@exit
    cmp BYTE PTR [rsi].GAME_STATE.paused, 0
    jne @@exit
    
@@drop_loop:
    inc DWORD PTR [rsi].GAME_STATE.currentPiece.y
    
    mov rcx, rsi
    lea rdx, [rsi].GAME_STATE.currentPiece
    call CheckCollision
    
    test eax, eax
    jz @@drop_loop
    
    dec DWORD PTR [rsi].GAME_STATE.currentPiece.y
    
    mov rcx, rsi
    call LockPiece
    
@@exit:
    add rsp, 28h
    pop rsi
    ret
DropPiece ENDP

PauseGame PROC pGame:QWORD
    mov rax, rcx
    mov BYTE PTR [rax].GAME_STATE.paused, 1
    ret
PauseGame ENDP

ResumeGame PROC pGame:QWORD
    mov rax, rcx
    mov BYTE PTR [rax].GAME_STATE.paused, 0
    ret
ResumeGame ENDP

TogglePause PROC pGame:QWORD
    mov rax, rcx
    xor BYTE PTR [rax].GAME_STATE.paused, 1
    ret
TogglePause ENDP

SetPlayerName PROC pGame:QWORD, pName:QWORD
    push rsi
    push rdi
    
    mov rsi, rdx
    mov rdi, rcx
    lea rdi, [rdi].GAME_STATE.playerName
    
    xor ecx, ecx
@@copy_loop:
    mov ax, WORD PTR [rsi + rcx*2]
    mov WORD PTR [rdi + rcx*2], ax
    test ax, ax
    jz @@done
    inc ecx
    cmp ecx, 127
    jl @@copy_loop
    
@@done:
    mov WORD PTR [rdi + rcx*2], 0
    
    pop rdi
    pop rsi
    ret
SetPlayerName ENDP

END