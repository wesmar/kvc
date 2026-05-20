; ==============================================================================
; ExplorerFrame DLL - Constants and PE Structure Field Offsets
; Windows x64 watermark suppression
; ==============================================================================

; DLL notification codes
DLL_PROCESS_DETACH              equ 0
DLL_PROCESS_ATTACH              equ 1

; VirtualProtect page protection flags
PAGE_READWRITE                  equ 004h
PAGE_EXECUTE_READWRITE          equ 040h

; HeapAlloc flags
HEAP_ZERO_MEMORY                equ 008h

; Branding pattern configuration
BRANDING_PATTERN_COUNT          equ 14      ; 1 winbrand slot + 13 shell32 slots
SHELL32_PATTERN_COUNT           equ 13      ; BRANDING_PATTERN_COUNT - 1
WILDCARD_MARKER                 equ 025h    ; L'%'

; LoadStringW resource IDs to block (shell32 activation watermarks, Windows 7/8/early 10)
; These IDs no longer exist in shell32.dll on Windows 10 build 28000+.
; Kept for compatibility with older Windows versions.
BLOCKED_RESOURCE_ID_1           equ 62000
BLOCKED_RESOURCE_ID_2           equ 62001

; ==============================================================================
; Shell32.dll watermark resource IDs (loaded into patterns[1..13])
; Verified present on Windows 10 Pro Build 28000.2113
; ==============================================================================

SHELL32_ID_0                    equ 33088   ; "Test Mode"
SHELL32_ID_1                    equ 33089   ; "Safe Mode"
SHELL32_ID_2                    equ 33108   ; "%ws Build %ws"
SHELL32_ID_3                    equ 33109   ; "Evaluation copy."
SHELL32_ID_4                    equ 33111   ; "This copy of Windows is licensed for "
SHELL32_ID_5                    equ 33117   ; "SecureBoot isn't configured correctly"
SHELL32_ID_6                    equ 33094   ; "Device Under Test"
SHELL32_ID_7                    equ 33110   ; "For testing purposes only."
SHELL32_ID_8                    equ 33112   ; "Windows License is expired"
SHELL32_ID_9                    equ 33118   ; "This PC isn't set up securely—data may be at risk."
SHELL32_ID_10                   equ 33120   ; "This PC isn't secure"
SHELL32_ID_11                   equ 33121   ; "Secure boot is disabled. This PC isn't set up for retail use..."
SHELL32_ID_12                   equ 33123   ; "System requirements not met. Go to Settings to learn more"

; Pattern buffer sizes in WCHARs (one entry per pattern slot)
PBUFSZ_0                        equ 128     ; patterns[0]:  winbrand  "Windows 11 Pro"
PBUFSZ_1                        equ 32      ; patterns[1]:  33088     "Test Mode"
PBUFSZ_2                        equ 32      ; patterns[2]:  33089     "Safe Mode"
PBUFSZ_3                        equ 128     ; patterns[3]:  33108     "%ws Build %ws"
PBUFSZ_4                        equ 32      ; patterns[4]:  33109     "Evaluation copy."
PBUFSZ_5                        equ 64      ; patterns[5]:  33111     "This copy of Windows is licensed for "
PBUFSZ_6                        equ 64      ; patterns[6]:  33117     "SecureBoot isn't configured correctly"
PBUFSZ_7                        equ 32      ; patterns[7]:  33094     "Device Under Test"
PBUFSZ_8                        equ 32      ; patterns[8]:  33110     "For testing purposes only."
PBUFSZ_9                        equ 32      ; patterns[9]:  33112     "Windows License is expired"
PBUFSZ_10                       equ 64      ; patterns[10]: 33118     "This PC isn't set up securely—data may be at risk."
PBUFSZ_11                       equ 32      ; patterns[11]: 33120     "This PC isn't secure"
PBUFSZ_12                       equ 160     ; patterns[12]: 33121     long SecureBoot disabled text (~144 chars)
PBUFSZ_13                       equ 64      ; patterns[13]: 33123     "System requirements not met. Go to Settings to learn more"

; BrandingLoadString component ID  (winbrand.dll "Basebrd", id=12 → "Windows 11 Pro")
BRANDING_COMPONENT_ID           equ 12

; PE header field offsets used during IAT patching
; IMAGE_DOS_HEADER
IMDOS_e_lfanew                  equ 60

; Within IMAGE_NT_HEADERS64:
;   Signature       at offset 0   (4 bytes)
;   FileHeader      at offset 4   (20 bytes)
;   OptionalHeader  at offset 24
;     DataDirectory[0] at OptionalHeader+112
;     DataDirectory[1] (Import) at OptionalHeader+120
;     DataDirectory[13] (Delay Import) at OptionalHeader+216
; So DataDirectory[1].VirtualAddress  = 24+120 = 144
;    DataDirectory[13].VirtualAddress = 24+216 = 240
IMNT_ImportDirectory_VA         equ 144
IMNT_DelayImportDirectory_VA    equ 240

; IMAGE_IMPORT_DESCRIPTOR field offsets (20 bytes total per entry)
IMID_OriginalFirstThunk         equ 0
IMID_Name                       equ 12
IMID_FirstThunk                 equ 16
IMID_SIZE                       equ 20

; IMAGE_DELAYLOAD_DESCRIPTOR (ImgDelayDescr) field offsets (32 bytes per entry)
; grAttrs  = 1 means all RVA fields are RVAs (modern, non-legacy)
IMDD_Name                       equ 4   ; rvaDLLName  (DWORD RVA)
IMDD_IAT                        equ 12  ; rvaIAT      (DWORD RVA of delay IAT array)
IMDD_INT                        equ 16  ; rvaINT      (DWORD RVA of delay INT / import name table)
IMDD_SIZE                       equ 32
