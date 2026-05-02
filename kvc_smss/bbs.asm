; Build instructions (run in x64 Native Tools Command Prompt):
;   ml64.exe /c /Cx bbs.asm
;   link.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 /ENTRY:main bbs.obj kernel32.lib

extrn LoadLibraryA:proc
extrn GetProcAddress:proc
extrn CreateThread:proc
extrn CreateEventA:proc
extrn SetEvent:proc
extrn WaitForSingleObject:proc
extrn CloseHandle:proc
extrn ExitProcess:proc

.data
    align 8

    ; --- Global state ---
    gSvcStatus          db 28 dup(0)    ; SERVICE_STATUS structure (28 bytes)
    gSvcStatusHandle    dq 0            ; SERVICE_STATUS_HANDLE (8 bytes)
    ghSvcStopEvent      dq 0            ; Stop-event HANDLE (8 bytes)

    ; --- Function pointers resolved at runtime from advapi32.dll ---
    pRegisterServiceCtrlHandlerEx dq 0
    pSetServiceStatus             dq 0
    pStartServiceCtrlDispatcher   dq 0
    pRegOpenKeyExA                dq 0
    pRegQueryValueExA             dq 0
    pRegSetValueExA               dq 0
    pRegCloseKey                  dq 0

    ; --- Function pointer resolved at runtime from ntdll.dll ---
    pNtQuerySystemInformation     dq 0

    ; --- Strings ---
    advapi32_name   db "advapi32.dll", 0
    ntdll_name      db "ntdll.dll", 0
    fn_Register     db "RegisterServiceCtrlHandlerExA", 0
    fn_SetStatus    db "SetServiceStatus", 0
    fn_StartDisp    db "StartServiceCtrlDispatcherA", 0
    fn_RegOpen      db "RegOpenKeyExA", 0
    fn_RegQuery     db "RegQueryValueExA", 0
    fn_RegSet       db "RegSetValueExA", 0
    fn_RegClose     db "RegCloseKey", 0
    fn_NtQuery      db "NtQuerySystemInformation", 0

    svcName         db "HvciShutdownSvc", 0
    regKey          db "SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", 0
    valName                 db "Enabled", 0
    valNameWasEnabledBy     db "WasEnabledBy", 0
    valNameChangedInBootCycle db "ChangedInBootCycle", 0

.code

; ---------------------------------------------------------
; static void DoShutdownAction(void)
;
; Opens the HVCI registry key and sets "Enabled" = 0,
; then closes the key.
;
; Stack layout (after push rbp / mov rbp, rsp / sub rsp, 64):
;
;   [rbp + 8]  -- return address
;   [rbp + 0]  -- saved rbp
;   [rbp -  8] -- hKey  (HKEY, 8 bytes)
;   [rbp - 12] -- val   (DWORD, 4 bytes) = 0
;   [rbp - 16] -- <4-byte pad>
;   [rbp - 32] -- [rsp+32] 5th argument slot
;   [rbp - 24] -- [rsp+40] 6th argument slot
;   ---- rsp is here (rbp - 64) ----
;   [rsp +  0]..[rsp + 31]  -- shadow space for args 1-4
;
; Alignment: before call RSP%16==0, after call RSP%16==8,
; after push rbp RSP%16==0, after sub rsp,64 RSP%16==0. Correct.
; N must be multiple of 16 after push rbp. 64%16==0. OK! :)
; The previous sub rsp, 48 caused [rsp+32]=[rbp-16] to overlap
; val at [rbp-12], writing garbage (stack address low bits) to registry.
; ---------------------------------------------------------
DoShutdownAction proc
    push rbp
    mov rbp, rsp
    ; 32 bytes shadow space + 16 bytes for two extra arg slots (args 5-6)
    ; + 12 bytes for locals (hKey=8, val=4) + 4 bytes pad = 64 bytes.
    ; N must be a multiple of 16 (after push rbp RSP is already 16-aligned).
    ; 64 % 16 == 0. Correct.
    sub rsp, 64

    ; --- Open registry key ---
    ; RegOpenKeyExA(HKEY_LOCAL_MACHINE, regKey, 0, KEY_SET_VALUE, &hKey)
    mov rcx, 0FFFFFFFF80000002h     ; HKEY_LOCAL_MACHINE
    lea rdx, regKey                 ; subkey path
    xor r8, r8                      ; ulOptions = 0
    mov r9, 2                       ; samDesired = KEY_SET_VALUE (0x0002)
    lea rax, [rbp-8]                ; address of local hKey
    mov [rsp+32], rax               ; 5th arg on stack (= [rbp-24], safe)
    call qword ptr [pRegOpenKeyExA]
    test eax, eax
    jnz _done                       ; non-zero means failure; bail out

    ; --- Write value ---
    ; RegSetValueExA(hKey, "Enabled", 0, REG_DWORD, &val, sizeof(val))
    mov dword ptr [rbp-12], 0       ; val = 0  (disable HVCI)

    mov rcx, [rbp-8]                ; hKey
    lea rdx, valName                ; "Enabled"
    xor r8, r8                      ; Reserved = 0
    mov r9, 4                       ; dwType = REG_DWORD
    lea rax, [rbp-12]               ; &val  (now safe: [rbp-12] is above [rbp-24])
    mov [rsp+32], rax               ; 5th arg (= [rbp-24])
    mov qword ptr [rsp+40], 4       ; 6th arg = cbData = sizeof(DWORD) (= [rbp-16], safe)
    call qword ptr [pRegSetValueExA]
    ; Point 3: stash result before RegCloseKey clobbers eax
    mov dword ptr [rbp-16], eax     ; save return code in pad slot

    ; --- Close the key regardless of write outcome ---
    mov rcx, [rbp-8]                ; hKey
    call qword ptr [pRegCloseKey]

    ; Check whether RegSetValueExA returned ERROR_SUCCESS (0)
    cmp dword ptr [rbp-16], 0
    ; ZF=1 on success; no action needed here — key is already closed

_done:
    add rsp, 64
    pop rbp
    ret
DoShutdownAction endp

; ---------------------------------------------------------
; static void DoStartupAction(void)
;
; Called when the service starts (SERVICE_RUNNING).
; Uses NtQuerySystemInformation(SystemTimeOfDayInformation)
; to obtain the precise kernel boot time (same source as the
; _lux PowerShell script), then:
;   Enabled            = 1  (REG_DWORD)  — always written
;   WasEnabledBy       = 2  (REG_DWORD)  — always written
;   ChangedInBootCycle        (REG_QWORD) — written ONLY when
;       the current registry value differs from BootTime
;
; Stack layout (sub rsp, 128):
;
;   [rbp -  8]         -- hKey  (HKEY, 8 bytes)
;   [rbp - 12]         -- val   (DWORD, 4 bytes)   ← Enabled / WasEnabledBy
;   [rbp - 16]         -- retLen (int, 4 bytes)     ← NtQuery out-param
;   [rbp - 64]         -- timeInfo (48 bytes)       ← SYSTEM_TIMEOFDAY_INFORMATION
;                          .BootTime    at [rbp-64] (LARGE_INTEGER, 8 bytes)
;                          .CurrentTime at [rbp-56]
;                          ... (remaining 32 bytes)
;   [rbp - 72]         -- existingBootTime (8 bytes) ← RegQueryValueExA output
;   [rbp - 76]         -- cbData (DWORD, 4 bytes)    ← RegQueryValueExA size param
;
;   [rsp +  0..31]     -- shadow space (args 1-4)
;   [rsp + 32]         -- 5th argument slot  (= [rbp-96])
;   [rsp + 40]         -- 6th argument slot  (= [rbp-88])
;   rsp = rbp - 128
;
; 128 % 16 == 0.  Correct.
; ---------------------------------------------------------
DoStartupAction proc
    push rbp
    mov rbp, rsp
    sub rsp, 128

    ; --- Query kernel boot time via NtQuerySystemInformation ---
    ; NtQuerySystemInformation(
    ;     SystemTimeOfDayInformation = 3,
    ;     &timeInfo,
    ;     sizeof(SYSTEM_TIMEOFDAY_INFORMATION) = 48,
    ;     &retLen)
    mov ecx, 3                          ; SystemTimeOfDayInformation
    lea rdx, [rbp-64]                   ; &timeInfo
    mov r8d, 48                         ; buffer size
    lea r9,  [rbp-16]                   ; &retLen
    call qword ptr [pNtQuerySystemInformation]
    test eax, eax
    jnz _startup_done                   ; NTSTATUS != STATUS_SUCCESS → bail

    ; timeInfo.BootTime is now valid at [rbp-64] (first LARGE_INTEGER field).

    ; --- Open registry key ---
    ; RegOpenKeyExA(HKEY_LOCAL_MACHINE, regKey, 0,
    ;               KEY_QUERY_VALUE|KEY_SET_VALUE (0x0003), &hKey)
    mov rcx, 0FFFFFFFF80000002h         ; HKEY_LOCAL_MACHINE
    lea rdx, regKey
    xor r8, r8                          ; ulOptions = 0
    mov r9, 3                           ; KEY_QUERY_VALUE | KEY_SET_VALUE
    lea rax, [rbp-8]                    ; &hKey
    mov [rsp+32], rax
    call qword ptr [pRegOpenKeyExA]
    test eax, eax
    jnz _startup_done                   ; open failed → bail

    ; --- Write Enabled = 1  (always) ---
    mov dword ptr [rbp-12], 1
    mov rcx, [rbp-8]                    ; hKey
    lea rdx, valName                    ; "Enabled"
    xor r8, r8                          ; Reserved
    mov r9, 4                           ; REG_DWORD
    lea rax, [rbp-12]                   ; &val
    mov [rsp+32], rax
    mov qword ptr [rsp+40], 4           ; cbData = 4
    call qword ptr [pRegSetValueExA]

    ; --- Write WasEnabledBy = 2  (always) ---
    mov dword ptr [rbp-12], 2
    mov rcx, [rbp-8]                    ; hKey
    lea rdx, valNameWasEnabledBy        ; "WasEnabledBy"
    xor r8, r8
    mov r9, 4                           ; REG_DWORD
    lea rax, [rbp-12]                   ; &val
    mov [rsp+32], rax
    mov qword ptr [rsp+40], 4
    call qword ptr [pRegSetValueExA]

    ; --- Conditionally write ChangedInBootCycle ---
    ; Read current registry value; write only when it differs from BootTime.
    mov dword ptr [rbp-76], 8           ; cbData = sizeof(QWORD)
    mov qword ptr [rbp-72], 0           ; existingBootTime = 0 (safe init)
    mov rcx, [rbp-8]                    ; hKey
    lea rdx, valNameChangedInBootCycle  ; "ChangedInBootCycle"
    xor r8, r8                          ; lpReserved = NULL
    xor r9, r9                          ; lpType     = NULL (don't need it)
    lea rax, [rbp-72]                   ; &existingBootTime
    mov [rsp+32], rax
    lea rax, [rbp-76]                   ; &cbData
    mov [rsp+40], rax
    call qword ptr [pRegQueryValueExA]
    ; If query failed (value missing) → write unconditionally
    test eax, eax
    jnz _write_boot_cycle
    ; Query succeeded → compare existing QWORD with our BootTime
    mov rax, [rbp-72]                   ; existing value from registry
    cmp rax, [rbp-64]                   ; compare with timeInfo.BootTime
    je  _skip_boot_cycle                ; identical → skip write

_write_boot_cycle:
    mov rcx, [rbp-8]                    ; hKey
    lea rdx, valNameChangedInBootCycle  ; "ChangedInBootCycle"
    xor r8, r8
    mov r9, 0Bh                         ; REG_QWORD = 11 = 0x0B
    lea rax, [rbp-64]                   ; &timeInfo.BootTime (still on stack)
    mov [rsp+32], rax
    mov qword ptr [rsp+40], 8           ; cbData = 8
    call qword ptr [pRegSetValueExA]

_skip_boot_cycle:
    ; --- Close the key ---
    mov rcx, [rbp-8]
    call qword ptr [pRegCloseKey]

_startup_done:
    add rsp, 128
    pop rbp
    ret
DoStartupAction endp

; ---------------------------------------------------------
; static DWORD WINAPI ShutdownThread(void* param)
;
; Worker thread: performs the shutdown action, then
; reports SERVICE_STOPPED and signals the stop event.
; ---------------------------------------------------------
ShutdownThread proc
    push rbp
    mov rbp, rsp
    sub rsp, 32                     ; shadow space only; no extra args or locals needed

    call DoShutdownAction

    ; Report SERVICE_STOPPED (1)
    mov dword ptr [gSvcStatus + 4],  1      ; dwCurrentState  = SERVICE_STOPPED
    mov dword ptr [gSvcStatus + 20], 0     ; dwCheckPoint    = 0
    mov dword ptr [gSvcStatus + 24], 0     ; dwWaitHint      = 0

    mov rcx, [gSvcStatusHandle]
    lea rdx, gSvcStatus
    call qword ptr [pSetServiceStatus]

    ; Signal the stop event if it was created
    mov rcx, [ghSvcStopEvent]
    test rcx, rcx
    jz _skip_event
    call SetEvent

_skip_event:
    xor eax, eax                    ; return 0
    add rsp, 32
    pop rbp
    ret
ShutdownThread endp

; ---------------------------------------------------------
; static DWORD WINAPI SvcCtrlHandler(
;     DWORD dwCtrl, DWORD dwEventType,
;     void* lpEventData, void* lpContext)
;
; Handles SERVICE_CONTROL_STOP / SHUTDOWN / PRESHUTDOWN:
; transitions to STOP_PENDING and spins up ShutdownThread.
; ---------------------------------------------------------
SvcCtrlHandler proc
    push rbp
    mov rbp, rsp
    sub rsp, 64                     ; 32 shadow + 16 for CreateThread args 5-6 + 16 pad

    cmp ecx, 0Fh                    ; SERVICE_CONTROL_PRESHUTDOWN
    je  _shutdown
    cmp ecx, 5                      ; SERVICE_CONTROL_SHUTDOWN
    je  _shutdown
    cmp ecx, 1                      ; SERVICE_CONTROL_STOP
    je  _shutdown
    jmp _default

_shutdown:
    ; Transition to SERVICE_STOP_PENDING (3)
    mov dword ptr [gSvcStatus + 4],  3      ; dwCurrentState = STOP_PENDING
    mov dword ptr [gSvcStatus + 20], 1     ; dwCheckPoint   = 1
    mov dword ptr [gSvcStatus + 24], 3000  ; dwWaitHint     = 3000 ms

    mov rcx, [gSvcStatusHandle]
    lea rdx, gSvcStatus
    call qword ptr [pSetServiceStatus]

    ; Spawn worker thread to do the actual work without blocking SCM
    ; CreateThread(NULL, 0, ShutdownThread, NULL, 0, NULL)
    xor rcx, rcx                    ; lpThreadAttributes = NULL
    xor rdx, rdx                    ; dwStackSize        = 0 (default)
    lea r8,  ShutdownThread         ; lpStartAddress
    xor r9,  r9                     ; lpParameter        = NULL
    mov qword ptr [rsp+32], 0       ; dwCreationFlags    = 0
    mov qword ptr [rsp+40], 0       ; lpThreadId         = NULL
    call CreateThread
    ; Point 4: close the thread handle — kernel keeps the thread alive,
    ; but leaving the handle open leaks a kernel object in this process.
    test rax, rax
    jz _thread_done
    mov rcx, rax
    call CloseHandle
_thread_done:

    xor eax, eax
    jmp _end

_default:
    ; For any unhandled control code just refresh the status
    mov rcx, [gSvcStatusHandle]
    lea rdx, gSvcStatus
    call qword ptr [pSetServiceStatus]
    xor eax, eax

_end:
    add rsp, 64
    pop rbp
    ret
SvcCtrlHandler endp

; ---------------------------------------------------------
; static void WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv)
;
; Entry point called by the SCM. Creates the stop event,
; registers the control handler, reports RUNNING, then
; re-enables HVCI (DoStartupAction), and finally waits
; until the stop event is signalled.
; ---------------------------------------------------------
SvcMain proc
    push rbp
    mov rbp, rsp
    sub rsp, 64                     ; 32 shadow + 16 alignment pad

    ; Create the manual-reset event that ShutdownThread will signal
    ; CreateEventA(NULL, TRUE /*manual reset*/, FALSE /*not signalled*/, NULL)
    xor rcx, rcx
    mov rdx, 1
    xor r8,  r8
    xor r9,  r9
    call CreateEventA
    mov [ghSvcStopEvent], rax

    ; Register our control handler with the SCM
    ; RegisterServiceCtrlHandlerExA("HvciShutdownSvc", SvcCtrlHandler, NULL)
    lea rcx, svcName
    lea rdx, SvcCtrlHandler
    xor r8, r8
    xor r9, r9
    call qword ptr [pRegisterServiceCtrlHandlerEx]
    mov [gSvcStatusHandle], rax

    ; Fill in the SERVICE_STATUS structure
    mov dword ptr [gSvcStatus +  0], 10h    ; dwServiceType      = SERVICE_WIN32_OWN_PROCESS
    mov dword ptr [gSvcStatus +  4], 4      ; dwCurrentState     = SERVICE_RUNNING
    mov dword ptr [gSvcStatus +  8], 105h   ; dwControlsAccepted = STOP|SHUTDOWN|PRESHUTDOWN
    mov dword ptr [gSvcStatus + 12], 0      ; dwWin32ExitCode    = 0
    mov dword ptr [gSvcStatus + 16], 0      ; dwServiceSpecificExitCode = 0
    mov dword ptr [gSvcStatus + 20], 0      ; dwCheckPoint       = 0
    mov dword ptr [gSvcStatus + 24], 0      ; dwWaitHint         = 0

    mov rcx, [gSvcStatusHandle]
    lea rdx, gSvcStatus
    call qword ptr [pSetServiceStatus]

    ; Re-enable HVCI immediately after reporting SERVICE_RUNNING.
    ; Uses NtQuerySystemInformation(SystemTimeOfDayInformation) for the
    ; precise kernel BootTime — identical approach to hvci_pseudo_wlaczanie_lux.ps1.
    ; Writes: Enabled=1, WasEnabledBy=2, ChangedInBootCycle=BootTime.
    call DoStartupAction

    ; Block until ShutdownThread signals the stop event
    mov rcx, [ghSvcStopEvent]
    mov rdx, 0FFFFFFFFh             ; INFINITE
    call WaitForSingleObject

    ; Clean up and return to the dispatcher
    mov rcx, [ghSvcStopEvent]
    call CloseHandle

    add rsp, 64
    pop rbp
    ret
SvcMain endp

; ---------------------------------------------------------
; int main(void)
;
; Loads advapi32.dll and ntdll.dll, resolves all needed
; function pointers, builds the service table, and hands
; control to the SCM.
; ---------------------------------------------------------
main proc
    push rbp
    mov rbp, rsp
    ; 32 shadow + 8 for hAdv local + 8 for hNtdll local
    ; + 32 for SERVICE_TABLE_ENTRY[2] + 8 pad = 88
    ; 88 % 16 == 8 — not aligned!  Use 96 instead. 96 % 16 == 0. OK.
    sub rsp, 96

    ; --- Load advapi32.dll and resolve its six functions ---
    lea rcx, advapi32_name
    call LoadLibraryA
    mov [rbp-8], rax                ; hAdv = module handle

    mov rcx, [rbp-8]
    lea rdx, fn_Register
    call GetProcAddress
    mov [pRegisterServiceCtrlHandlerEx], rax

    mov rcx, [rbp-8]
    lea rdx, fn_SetStatus
    call GetProcAddress
    mov [pSetServiceStatus], rax

    mov rcx, [rbp-8]
    lea rdx, fn_StartDisp
    call GetProcAddress
    mov [pStartServiceCtrlDispatcher], rax

    mov rcx, [rbp-8]
    lea rdx, fn_RegOpen
    call GetProcAddress
    mov [pRegOpenKeyExA], rax

    mov rcx, [rbp-8]
    lea rdx, fn_RegQuery
    call GetProcAddress
    mov [pRegQueryValueExA], rax

    mov rcx, [rbp-8]
    lea rdx, fn_RegSet
    call GetProcAddress
    mov [pRegSetValueExA], rax

    mov rcx, [rbp-8]
    lea rdx, fn_RegClose
    call GetProcAddress
    mov [pRegCloseKey], rax

    ; --- Load ntdll.dll and resolve NtQuerySystemInformation ---
    ; ntdll.dll is already mapped into every process, so LoadLibraryA
    ; just increments its reference count and returns the cached handle.
    lea rcx, ntdll_name
    call LoadLibraryA
    mov [rbp-16], rax               ; hNtdll = module handle

    mov rcx, [rbp-16]
    lea rdx, fn_NtQuery
    call GetProcAddress
    mov [pNtQuerySystemInformation], rax

    ; --- Build SERVICE_TABLE_ENTRY table[2] on the stack ---
    ; table[0] = { "HvciShutdownSvc", SvcMain }
    lea rax, svcName
    mov qword ptr [rbp-56], rax
    lea rax, SvcMain
    mov qword ptr [rbp-48], rax
    ; table[1] = { NULL, NULL }  (terminator required by the SCM)
    mov qword ptr [rbp-40], 0
    mov qword ptr [rbp-32], 0

    ; Hand off to the SCM; this call blocks until the service exits
    lea rcx, [rbp-56]
    call qword ptr [pStartServiceCtrlDispatcher]

    xor ecx, ecx
    call ExitProcess
main endp

end
