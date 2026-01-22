POINT_STRUCT STRUCT
    x DWORD ?
    y DWORD ?
POINT_STRUCT ENDS

PIECE STRUCT
    shapeType BYTE ?
    color BYTE ?
    padding WORD ?
    x DWORD ?
    y DWORD ?
    yFloat DWORD ?
    blocks POINT_STRUCT 4 DUP(<>)
PIECE ENDS

GAME_STATE STRUCT
    boardWidth DWORD ?
    boardHeight DWORD ?
    board BYTE 400 DUP(?)
    currentPiece PIECE <>
    nextPiece PIECE <>
    score DWORD ?
    lines DWORD ?
    level DWORD ?
    gameOver BYTE ?
    paused BYTE ?
    showGhost BYTE ?
    padding BYTE ?
    rngSeed DWORD ?
    playerName WORD 128 DUP(?)
    highScore DWORD ?
    highScoreName WORD 128 DUP(?)
    yFloat DWORD ?
GAME_STATE ENDS

RENDERER_STATE STRUCT
    hwnd QWORD ?
    hdcMem QWORD ?
    hbmMem QWORD ?
    hbmOld QWORD ?
    wWidth DWORD ?
    wHeight DWORD ?
    hFontNormal QWORD ?
    hFontSmall QWORD ?
    hFontPause QWORD ?
    hFontGameOver QWORD ?
    colorBrushes QWORD 8 DUP(?)
    pausePulse DWORD ?
RENDERER_STATE ENDS