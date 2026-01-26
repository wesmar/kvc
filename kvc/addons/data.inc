; 2D coordinate for block positions within a piece
POINT_STRUCT STRUCT
    x DWORD ?
    y DWORD ?
POINT_STRUCT ENDS

; Tetromino piece structure (48 bytes total)
; Contains shape type, position, and 4 block offsets relative to piece origin
PIECE STRUCT
    shapeType BYTE ?                 ; 0=I, 1=O, 2=Z, 3=S, 4=T, 5=L, 6=J
    color BYTE ?                     ; Color index (1-7, matches shapeType+1)
    padding WORD ?                   ; Alignment padding
    x DWORD ?                        ; Board X position (column)
    y DWORD ?                        ; Board Y position (row)
    yFloat DWORD ?                   ; Fractional Y for smooth gravity
    blocks POINT_STRUCT 4 DUP(<>)    ; 4 block offsets relative to (x,y)
PIECE ENDS

; Main game state structure - holds all gameplay data
; Board stored as 1D array, accessed as board[y * width + x]
GAME_STATE STRUCT
    boardWidth DWORD ?               ; Board width in cells (typically 10)
    boardHeight DWORD ?              ; Board height in cells (typically 20)
    board BYTE 400 DUP(?)            ; Cell array: 0=empty, 1-7=piece color
    currentPiece PIECE <>            ; Active falling piece
    nextPiece PIECE <>               ; Preview piece shown in info panel
    score DWORD ?                    ; Current game score
    lines DWORD ?                    ; Total lines cleared
    level DWORD ?                    ; Current level (affects speed)
    gameOver BYTE ?                  ; 1 if game ended
    paused BYTE ?                    ; 1 if game paused
    showGhost BYTE ?                 ; 1 to show ghost piece preview
    padding BYTE ?                   ; Alignment padding
    rngSeed DWORD ?                  ; Random seed for piece generation
    playerName WORD 128 DUP(?)       ; Unicode player name (max 127 chars)
    highScore DWORD ?                ; Persisted high score
    highScoreName WORD 128 DUP(?)    ; Unicode name of high score holder
    yFloat DWORD ?                   ; Gravity accumulator (fractional movement)
    ; Line clear animation state
    clearActive BYTE ?               ; 1 if animation in progress
    clearCount  BYTE ?               ; Number of lines being cleared (1..4)
    clearPad    WORD ?               ; Alignment padding
    clearMask   DWORD ?              ; Bitmask of rows to animate (bit y = row y)
    clearTimer  DWORD ?              ; Animation elapsed time in ms
GAME_STATE ENDS

; Renderer state - GDI handles for double-buffered drawing
RENDERER_STATE STRUCT
    hwnd QWORD ?                     ; Window handle
    hdcMem QWORD ?                   ; Memory DC for backbuffer
    hbmMem QWORD ?                   ; Backbuffer bitmap
    hbmOld QWORD ?                   ; Original bitmap (for cleanup)
    wWidth DWORD ?                   ; Window client width
    wHeight DWORD ?                  ; Window client height
    hFontNormal QWORD ?              ; 20pt bold font for stats
    hFontSmall QWORD ?               ; 14pt font for controls/author
    hFontPause QWORD ?               ; 26pt bold font for PAUSED text
    hFontGameOver QWORD ?            ; 30pt bold font for GAME OVER
    colorBrushes QWORD 8 DUP(?)      ; Solid brushes for 8 piece colors
    pausePulse DWORD ?               ; Animation counter for pulsing PAUSED text
RENDERER_STATE ENDS