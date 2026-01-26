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

; Line clear animation timing
CLEAR_ANIM_MS equ 300               ; Duration of line clear fade-out animation (ms)

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

    ; Initialize line clear animation state
    mov BYTE PTR [rsi].GAME_STATE.clearActive, 0
    mov BYTE PTR [rsi].GAME_STATE.clearCount, 0
    mov DWORD PTR [rsi].GAME_STATE.clearMask, 0
    mov DWORD PTR [rsi].GAME_STATE.clearTimer, 0

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

    ; Reset line clear animation state
    mov BYTE PTR [rsi].GAME_STATE.clearActive, 0
    mov BYTE PTR [rsi].GAME_STATE.clearCount, 0
    mov DWORD PTR [rsi].GAME_STATE.clearMask, 0
    mov DWORD PTR [rsi].GAME_STATE.clearTimer, 0

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

; Move nextPiece to currentPiece and generate a new nextPiece
; Sets gameOver flag if new piece spawns into existing blocks
; RCX = pGame
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

; Check if piece collides with board boundaries or existing blocks
; Returns: EAX = 1 if collision detected, 0 otherwise
; RCX = pGame, RDX = pPiece to test
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

; Lock current piece into the board and trigger line clear check
; Writes piece blocks to board array, then calls ClearFullLines and SpawnNewPiece
; RCX = pGame
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

    ; Always spawn new piece immediately (non-blocking animation)
    ; ApplyClearLines will handle scoring and board compression later
    mov rcx, rsi
    call SpawnNewPiece

    add rsp, 28h
    pop rbx
    pop rdi
    pop rsi
    ret
LockPiece ENDP

; Detect full lines and start clear animation (does not shift rows)
; Returns: EAX = number of full lines detected (0..4)
ClearFullLines PROC pGame:QWORD
    push rsi
    push rdi
    push rbx
    sub rsp, 28h

    mov rsi, rcx

    ; Reset animation state
    mov BYTE PTR [rsi].GAME_STATE.clearCount, 0
    mov DWORD PTR [rsi].GAME_STATE.clearMask, 0

    xor ebx, ebx                     ; EBX = line count
    mov ecx, [rsi].GAME_STATE.boardHeight
    dec ecx                          ; Start from bottom row

@@scan_loop:
    cmp ecx, 0
    jl @@scan_done

    ; Calculate row address: board + y * width
    mov edi, ecx
    imul edi, [rsi].GAME_STATE.boardWidth
    lea rax, [rsi].GAME_STATE.board
    add rdi, rax

    ; Check if row is full
    xor r8d, r8d                     ; Column index
@@check_row:
    cmp byte ptr [rdi + r8], 0
    je @@not_full                    ; Empty cell found, row not full
    inc r8d
    cmp r8d, [rsi].GAME_STATE.boardWidth
    jl @@check_row

    ; Row is full - set bit in clearMask and increment count
    mov eax, 1
    mov r9d, ecx
    shl eax, cl                      ; EAX = 1 << row_index
    or [rsi].GAME_STATE.clearMask, eax
    inc ebx                          ; Increment line count

@@not_full:
    dec ecx
    jmp @@scan_loop

@@scan_done:
    ; If lines found, start animation
    test ebx, ebx
    jz @@no_lines

    mov [rsi].GAME_STATE.clearCount, bl
    mov BYTE PTR [rsi].GAME_STATE.clearActive, 1
    mov DWORD PTR [rsi].GAME_STATE.clearTimer, 0

@@no_lines:
    mov eax, ebx                     ; Return line count
    add rsp, 28h
    pop rbx
    pop rdi
    pop rsi
    ret
ClearFullLines ENDP

; Apply line clear after animation: shift rows down, update score, spawn new piece
; Called when clearTimer >= CLEAR_ANIM_MS
ApplyClearLines PROC pGame:QWORD
    push rsi
    push rdi
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 30h

    mov rsi, rcx

    ; Compress board: copy non-cleared rows from bottom to top
    ; dstY starts at bottom, iterate srcY from bottom to top
    mov r12d, [rsi].GAME_STATE.boardHeight
    dec r12d                         ; R12D = dstY (starts at bottom)
    mov r13d, r12d                   ; R13D = srcY (starts at bottom)

@@compress_loop:
    cmp r13d, 0
    jl @@fill_top

    ; Check if srcY is in clearMask (bit srcY == 1 means skip this row)
    mov eax, 1
    mov ecx, r13d
    shl eax, cl                      ; EAX = 1 << srcY
    test eax, [rsi].GAME_STATE.clearMask
    jnz @@skip_row                   ; Row is being cleared, skip it

    ; Copy row srcY to dstY if they differ
    cmp r13d, r12d
    je @@no_copy                     ; Same row, no copy needed

    ; Calculate source and destination addresses
    mov eax, r13d
    imul eax, [rsi].GAME_STATE.boardWidth
    lea rdi, [rsi].GAME_STATE.board
    add rdi, rax                     ; RDI = &board[srcY * width]

    mov eax, r12d
    imul eax, [rsi].GAME_STATE.boardWidth
    lea rbx, [rsi].GAME_STATE.board
    add rbx, rax                     ; RBX = &board[dstY * width]

    ; Copy row
    xor r8d, r8d
@@copy_row:
    mov al, byte ptr [rdi + r8]
    mov byte ptr [rbx + r8], al
    inc r8d
    cmp r8d, [rsi].GAME_STATE.boardWidth
    jl @@copy_row

@@no_copy:
    dec r12d                         ; dstY--

@@skip_row:
    dec r13d                         ; srcY--
    jmp @@compress_loop

@@fill_top:
    ; Clear remaining rows at top (0 to dstY inclusive)
    cmp r12d, 0
    jl @@update_score

@@clear_top_loop:
    mov eax, r12d
    imul eax, [rsi].GAME_STATE.boardWidth
    lea rdi, [rsi].GAME_STATE.board
    add rdi, rax

    xor r8d, r8d
@@clear_row:
    mov byte ptr [rdi + r8], 0
    inc r8d
    cmp r8d, [rsi].GAME_STATE.boardWidth
    jl @@clear_row

    dec r12d
    cmp r12d, 0
    jge @@clear_top_loop

@@update_score:
    ; Update lines count
    movzx eax, BYTE PTR [rsi].GAME_STATE.clearCount
    add [rsi].GAME_STATE.lines, eax

    ; Calculate score: clearCount^2 * 100 * level
    movzx ecx, BYTE PTR [rsi].GAME_STATE.clearCount
    imul ecx, ecx                    ; clearCount^2
    imul ecx, 100
    imul ecx, [rsi].GAME_STATE.level
    add [rsi].GAME_STATE.score, ecx

    ; Update level: (lines / 10) + 1
    mov eax, [rsi].GAME_STATE.lines
    xor edx, edx
    mov ecx, 10
    div ecx
    inc eax
    mov [rsi].GAME_STATE.level, eax

    ; Check and save high score
    mov eax, [rsi].GAME_STATE.score
    cmp eax, [rsi].GAME_STATE.highScore
    jle @@clear_anim_state

    mov rcx, rsi
    call SaveHighScore

@@clear_anim_state:
    ; Reset animation state
    mov BYTE PTR [rsi].GAME_STATE.clearActive, 0
    mov BYTE PTR [rsi].GAME_STATE.clearCount, 0
    mov DWORD PTR [rsi].GAME_STATE.clearMask, 0
    mov DWORD PTR [rsi].GAME_STATE.clearTimer, 0

    ; Note: new piece already spawned in LockPiece (non-blocking animation)

    add rsp, 30h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rdi
    pop rsi
    ret
ApplyClearLines ENDP

; Main game loop tick - handles gravity, animation, and piece locking
; Accumulates fractional Y movement; locks piece when it hits bottom
; RCX = pGame, EDX = deltaTimeMs (typically 16ms for 60 FPS)
UpdateGame PROC pGame:QWORD, deltaTimeMs:DWORD
    push rsi
    push rbx
    sub rsp, 28h

    mov rsi, rcx
    mov ebx, edx                     ; Save deltaTimeMs in EBX (non-volatile)

    cmp BYTE PTR [rsi].GAME_STATE.gameOver, 0
    jne @@exit_update
    cmp BYTE PTR [rsi].GAME_STATE.paused, 0
    jne @@exit_update

    ; Handle line clear animation in background (non-blocking)
    cmp BYTE PTR [rsi].GAME_STATE.clearActive, 0
    je @@anim_done

    ; Animation active - increment timer
    add [rsi].GAME_STATE.clearTimer, ebx

    ; Check if animation complete
    cmp DWORD PTR [rsi].GAME_STATE.clearTimer, CLEAR_ANIM_MS
    jl @@anim_done

    ; Animation finished - apply line clear (compress board, update score)
    mov rcx, rsi
    call ApplyClearLines

@@anim_done:
    ; Continue normal gameplay (non-blocking animation)
    mov eax, [rsi].GAME_STATE.level
    dec eax
    imul eax, 50
    add eax, 300
    imul eax, ebx
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
    pop rbx
    pop rsi
    ret
UpdateGame ENDP

; Move current piece one cell to the left if no collision
; RCX = pGame
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

; Move current piece one cell to the right if no collision
; RCX = pGame
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

; Move current piece down by dy cells; locks piece on collision
; Returns: EAX = 1 if moved successfully, 0 if blocked (piece locked)
; RCX = pGame, EDX = dy (cells to move down)
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

; Rotate current piece 90 degrees clockwise with wall kick support
; O-piece (type 1) does not rotate; I-piece has extended kick offsets
; Restores original position if rotation fails after all kick attempts
; RCX = pGame
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

; Hard drop: instantly move piece to lowest valid position and lock
; RCX = pGame
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

; Set game to paused state
; RCX = pGame
PauseGame PROC pGame:QWORD
    mov rax, rcx
    mov BYTE PTR [rax].GAME_STATE.paused, 1
    ret
PauseGame ENDP

; Resume game from paused state
; RCX = pGame
ResumeGame PROC pGame:QWORD
    mov rax, rcx
    mov BYTE PTR [rax].GAME_STATE.paused, 0
    ret
ResumeGame ENDP

; Toggle between paused and running states
; RCX = pGame
TogglePause PROC pGame:QWORD
    mov rax, rcx
    xor BYTE PTR [rax].GAME_STATE.paused, 1
    ret
TogglePause ENDP

; Copy Unicode player name to game state (max 127 chars + null)
; RCX = pGame, RDX = pName (pointer to wide string)
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