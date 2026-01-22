INCLUDE data.inc
INCLUDE proto.inc

.CONST
ALIGN 16
; Registry paths and keys (Unicode wide strings)
; TRAP: Unicode strings must be null-terminated with WORD (2 bytes)
; Format: Each char is 2 bytes (L"text" equivalent in C)
szRegPath       DB 'S',0,'o',0,'f',0,'t',0,'w',0,'a',0,'r',0,'e',0,'\',0,'k',0,'v',0,'c',0,'\',0,'T',0,'e',0,'t',0,'r',0,'i',0,'s',0,0,0
szPlayerName    DB 'P',0,'l',0,'a',0,'y',0,'e',0,'r',0,'N',0,'a',0,'m',0,'e',0,0,0
szHighScore     DB 'H',0,'i',0,'g',0,'h',0,'S',0,'c',0,'o',0,'r',0,'e',0,0,0
szHighScoreName DB 'H',0,'i',0,'g',0,'h',0,'S',0,'c',0,'o',0,'r',0,'e',0,'N',0,'a',0,'m',0,'e',0,0,0

.CODE
ALIGN 16
; TRAP: PROLOGUE:NONE and EPILOGUE:NONE disable automatic stack frame generation
; This gives us full control over stack management for optimal code
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; Calculate length of Unicode string (in characters, not bytes)
; TRAP x64: Arg is RCX (not stack), returns in EAX
; TRAP: Wide strings are 2 bytes per char, null terminator is WORD 0
StrLenW PROC
    xor eax, eax                     ; Length counter
    test rcx, rcx                    ; Check for NULL pointer
    jz @@done

@@loop:
    cmp WORD PTR [rcx + rax*2], 0    ; TRAP: Multiply by 2 for wide chars
    je @@done
    inc eax
    jmp @@loop

@@done:
    ret                              ; No epilogue - manual control
StrLenW ENDP

; Save player name to registry (HKCU\Software\Tetris\PlayerName)
; TRAP x64: Arg is RCX=pName (pointer to Unicode string)
; TRAP: RegCreateKeyExW takes 9 params - first 4 in regs, rest on stack
SavePlayerName PROC pName:QWORD
    push rsi
    sub rsp, 60h                     ; Shadow space + locals

    mov rsi, rcx                     ; Save pName pointer

    ; Create or open registry key
    ; TRAP: Win64 API params: RCX, RDX, R8, R9, [stack+20h], [stack+28h], ...
    mov ecx, 80000001h               ; HKEY_CURRENT_USER
    lea rdx, szRegPath               ; "Software\Tetris"
    xor r8d, r8d                     ; Reserved = 0
    xor r9d, r9d                     ; lpClass = NULL

    ; Stack parameters (beyond first 4)
    mov QWORD PTR [rsp+20h], 0       ; Reserved
    mov QWORD PTR [rsp+28h], 20006h  ; KEY_WRITE access
    mov QWORD PTR [rsp+30h], 0       ; lpSecurityAttributes = NULL
    lea rax, [rsp+50h]
    mov QWORD PTR [rsp+38h], rax     ; phkResult = &hKey (local var)
    mov QWORD PTR [rsp+40h], 0       ; lpdwDisposition = NULL

    call RegCreateKeyExW
    test eax, eax                    ; Check return code (0 = success)
    jnz @@fail

    mov rcx, rsi
    call StrLenW
    inc eax
    shl eax, 1
    mov [rsp+58h], eax

    mov rcx, [rsp+50h]
    lea rdx, szPlayerName
    xor r8d, r8d
    mov r9d, 1
    mov [rsp+20h], rsi
    mov eax, [rsp+58h]
    mov [rsp+28h], rax

    call RegSetValueExW
    mov [rsp+5Ch], eax

    mov rcx, [rsp+50h]
    call RegCloseKey
    
    mov eax, [rsp+5Ch]
    test eax, eax
    jnz @@fail
    
    mov eax, 1
    jmp @@exit
    
@@fail:
    xor eax, eax
    
@@exit:
    add rsp, 60h
    pop rsi
    ret
SavePlayerName ENDP

LoadPlayerName PROC pGame:QWORD
    push rsi
    push rdi
    sub rsp, 258h

    mov rsi, rcx

    mov ecx, 80000001h
    lea rdx, szRegPath
    xor r8d, r8d
    mov r9d, 20019h
    lea rax, [rsp+240h]
    mov [rsp+20h], rax

    call RegOpenKeyExW
    test eax, eax
    jnz @@not_found

    mov DWORD PTR [rsp+248h], 512

    mov rcx, [rsp+240h]
    lea rdx, szPlayerName
    xor r8d, r8d
    lea r9, [rsp+24Ch]
    lea rax, [rsp+40h]
    mov [rsp+20h], rax
    lea rax, [rsp+248h]
    mov [rsp+28h], rax

    call RegQueryValueExW
    mov [rsp+238h], eax

    mov rcx, [rsp+240h]
    call RegCloseKey

    mov eax, [rsp+238h]
    test eax, eax
    jnz @@not_found

    cmp DWORD PTR [rsp+24Ch], 1
    jne @@not_found

    lea rdi, [rsi].GAME_STATE.playerName
    lea rdx, [rsp+40h]
    
    xor ecx, ecx
@@copy_loop:
    mov ax, WORD PTR [rdx + rcx*2]
    mov WORD PTR [rdi + rcx*2], ax
    test ax, ax
    jz @@success
    inc ecx
    cmp ecx, 127
    jl @@copy_loop
    
@@success:
    mov WORD PTR [rdi + rcx*2], 0
    mov eax, 1
    jmp @@exit
    
@@not_found:
    lea rdi, [rsi].GAME_STATE.playerName
    mov WORD PTR [rdi], 0
    xor eax, eax
    
@@exit:
    add rsp, 258h
    pop rdi
    pop rsi
    ret
LoadPlayerName ENDP

SaveHighScore PROC pGame:QWORD
    push rsi
    push rdi
    push rbx
    sub rsp, 60h

    mov rsi, rcx

    mov ecx, 80000001h
    lea rdx, szRegPath
    xor r8d, r8d
    xor r9d, r9d
    mov QWORD PTR [rsp+20h], 0
    mov QWORD PTR [rsp+28h], 20006h
    mov QWORD PTR [rsp+30h], 0
    lea rax, [rsp+50h]
    mov QWORD PTR [rsp+38h], rax
    mov QWORD PTR [rsp+40h], 0

    call RegCreateKeyExW
    test eax, eax
    jnz @@fail

    mov eax, [rsi].GAME_STATE.score
    mov [rsp+58h], eax

    mov rcx, [rsp+50h]
    lea rdx, szHighScore
    xor r8d, r8d
    mov r9d, 4
    lea rax, [rsp+58h]
    mov [rsp+20h], rax
    mov QWORD PTR [rsp+28h], 4

    call RegSetValueExW
    test eax, eax
    jnz @@close_fail

    lea rax, [rsi].GAME_STATE.playerName
    cmp WORD PTR [rax], 0
    jne @@use_player

    lea rdi, [rsi].GAME_STATE.highScoreName
    mov WORD PTR [rdi+0], 'A'
    mov WORD PTR [rdi+2], 'n'
    mov WORD PTR [rdi+4], 'o'
    mov WORD PTR [rdi+6], 'n'
    mov WORD PTR [rdi+8], 'y'
    mov WORD PTR [rdi+10], 'm'
    mov WORD PTR [rdi+12], 'o'
    mov WORD PTR [rdi+14], 'u'
    mov WORD PTR [rdi+16], 's'
    mov WORD PTR [rdi+18], 0
    jmp @@save_name

@@use_player:
    lea rdx, [rsi].GAME_STATE.playerName
    lea rdi, [rsi].GAME_STATE.highScoreName
    xor ecx, ecx
@@copy_name:
    mov ax, WORD PTR [rdx + rcx*2]
    mov WORD PTR [rdi + rcx*2], ax
    test ax, ax
    jz @@done_copy
    inc ecx
    cmp ecx, 127
    jl @@copy_name
@@done_copy:
    mov WORD PTR [rdi + rcx*2], 0

@@save_name:
    mov eax, [rsi].GAME_STATE.score
    mov [rsi].GAME_STATE.highScore, eax

    lea rcx, [rsi].GAME_STATE.highScoreName
    call StrLenW
    inc eax
    shl eax, 1
    mov rbx, rax

    mov rcx, [rsp+50h]
    lea rdx, szHighScoreName
    xor r8d, r8d
    mov r9d, 1
    lea rax, [rsi].GAME_STATE.highScoreName
    mov [rsp+20h], rax
    mov [rsp+28h], rbx

    call RegSetValueExW

@@close_fail:
    mov [rsp+5Ch], eax
    mov rcx, [rsp+50h]
    call RegCloseKey
    mov eax, [rsp+5Ch]

    test eax, eax
    jnz @@fail
    
    mov eax, 1
    jmp @@exit

@@fail:
    xor eax, eax

@@exit:
    add rsp, 60h
    pop rbx
    pop rdi
    pop rsi
    ret
SaveHighScore ENDP

LoadHighScore PROC pGame:QWORD
    push rsi
    push rdi
    sub rsp, 258h

    mov rsi, rcx

    mov ecx, 80000001h
    lea rdx, szRegPath
    xor r8d, r8d
    mov r9d, 20019h
    lea rax, [rsp+240h]
    mov [rsp+20h], rax

    call RegOpenKeyExW
    test eax, eax
    jnz @@fail_default

    mov DWORD PTR [rsp+248h], 4
    mov rcx, [rsp+240h]
    lea rdx, szHighScore
    xor r8d, r8d
    lea r9, [rsp+24Ch]
    lea rax, [rsp+238h]
    mov [rsp+20h], rax
    lea rax, [rsp+248h]
    mov [rsp+28h], rax

    call RegQueryValueExW
    test eax, eax
    jnz @@read_name

    cmp DWORD PTR [rsp+24Ch], 4
    jne @@read_name

    mov eax, [rsp+238h]
    mov [rsi].GAME_STATE.highScore, eax

@@read_name:
    mov DWORD PTR [rsp+248h], 512
    mov rcx, [rsp+240h]
    lea rdx, szHighScoreName
    xor r8d, r8d
    lea r9, [rsp+24Ch]
    lea rax, [rsp+40h]
    mov [rsp+20h], rax
    lea rax, [rsp+248h]
    mov [rsp+28h], rax

    call RegQueryValueExW
    test eax, eax
    jnz @@cleanup

    cmp DWORD PTR [rsp+24Ch], 1
    jne @@cleanup

    lea rdi, [rsi].GAME_STATE.highScoreName
    lea rdx, [rsp+40h]
    xor ecx, ecx
@@copy_loop:
    mov ax, WORD PTR [rdx + rcx*2]
    mov WORD PTR [rdi + rcx*2], ax
    test ax, ax
    jz @@cleanup
    inc ecx
    cmp ecx, 127
    jl @@copy_loop
    mov WORD PTR [rdi + rcx*2], 0
    
@@cleanup:
    mov rcx, [rsp+240h]
    call RegCloseKey
    mov eax, 1
    jmp @@exit

@@fail_default:
    mov DWORD PTR [rsi].GAME_STATE.highScore, 0
    mov WORD PTR [rsi].GAME_STATE.highScoreName, 0
    xor eax, eax

@@exit:
    add rsp, 258h
    pop rdi
    pop rsi
    ret
LoadHighScore ENDP

; Delete entire registry key (clears all saved data)
; TRAP: No parameters - uses RCX, RDX for Win64 API
; TRAP: Shadow space required even with no local vars
ClearRegistry PROC
    sub rsp, 28h                     ; Shadow space (minimum 20h + alignment)

    ; Delete registry key (all values are deleted with key)
    mov ecx, 80000001h               ; HKEY_CURRENT_USER
    lea rdx, szRegPath               ; "Software\Tetris"
    call RegDeleteKeyW

    ; Check result
    test eax, eax
    jz @@ok                          ; ERROR_SUCCESS (0)
    cmp eax, 2                       ; ERROR_FILE_NOT_FOUND
    je @@ok                          ; Key doesn't exist - treat as success
    xor eax, eax                     ; Other error - return 0
    jmp @@exit

@@ok:
    mov eax, 1                       ; Return 1 (success)

@@exit:
    add rsp, 28h
    ret
ClearRegistry ENDP

END
