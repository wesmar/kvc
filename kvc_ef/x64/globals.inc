; ==============================================================================
; ExplorerFrame DLL - External Global Declarations
; Include in every module that references shared state.
; ==============================================================================

; Array of BRANDING_PATTERN_COUNT QWORD pointers to heap-allocated WCHAR buffers.
;   [0] = BrandingLoadString result (winbrand.dll)  - size 128 WCHARs
;   [1] = LoadStringW #33088 (shell32.dll)          - size  64 WCHARs
;   [2] = LoadStringW #33089 (shell32.dll)          - size  64 WCHARs
;   [3] = LoadStringW #33108 (shell32.dll)          - size 128 WCHARs
;   [4] = LoadStringW #33109 (shell32.dll)          - size 128 WCHARs
;   [5] = LoadStringW #33111 (shell32.dll)          - size 167 WCHARs
;   [6] = LoadStringW #33117 (shell32.dll)          - size 128 WCHARs
EXTRN g_brandingPatterns        :QWORD
