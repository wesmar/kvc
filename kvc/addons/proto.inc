EXTERN GetModuleHandleA:PROC
EXTERN GetTickCount:PROC
EXTERN ExitProcess:PROC
EXTERN RegisterClassExA:PROC
EXTERN CreateWindowExA:PROC
EXTERN ShowWindow:PROC
EXTERN UpdateWindow:PROC
EXTERN GetMessageA:PROC
EXTERN TranslateMessage:PROC
EXTERN DispatchMessageA:PROC
EXTERN DefWindowProcA:PROC
EXTERN PostQuitMessage:PROC
EXTERN LoadCursorA:PROC
EXTERN LoadLibraryA:PROC
EXTERN ExtractIconA:PROC
EXTERN FreeLibrary:PROC
EXTERN BeginPaint:PROC
EXTERN EndPaint:PROC
EXTERN GetClientRect:PROC
EXTERN AdjustWindowRect:PROC
EXTERN InvalidateRect:PROC
EXTERN SetWindowTextA:PROC
EXTERN CreateFontA:PROC
EXTERN DeleteObject:PROC
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN CreateCompatibleDC:PROC
EXTERN CreateCompatibleBitmap:PROC
EXTERN SelectObject:PROC
EXTERN DeleteDC:PROC
EXTERN BitBlt:PROC
EXTERN CreateSolidBrush:PROC
EXTERN FillRect:PROC
EXTERN SetBkMode:PROC
EXTERN SetTextColor:PROC
EXTERN SetBkColor:PROC
EXTERN TextOutA:PROC
EXTERN CreatePen:PROC
EXTERN MoveToEx:PROC
EXTERN LineTo:PROC
EXTERN CreateHatchBrush:PROC
EXTERN lstrlenA:PROC
EXTERN wsprintfA:PROC
EXTERN WideCharToMultiByte:PROC
EXTERN GetWindowTextW:PROC
EXTERN SetWindowTextW:PROC
EXTERN RegCreateKeyExW:PROC
EXTERN RegOpenKeyExW:PROC
EXTERN RegQueryValueExW:PROC
EXTERN RegSetValueExW:PROC
EXTERN RegCloseKey:PROC
EXTERN RegDeleteKeyW:PROC
EXTERN SetTimer:PROC
EXTERN KillTimer:PROC
EXTERN SetFocus:PROC

InitGame PROTO pGame:QWORD, boardWidth:DWORD, boardHeight:DWORD
StartGame PROTO pGame:QWORD
GenerateRandomPiece PROTO pGame:QWORD, pPiece:QWORD
SpawnNewPiece PROTO pGame:QWORD
CheckCollision PROTO pGame:QWORD, pPiece:QWORD
LockPiece PROTO pGame:QWORD
ClearFullLines PROTO pGame:QWORD
UpdateGame PROTO pGame:QWORD, deltaTimeMs:DWORD
MoveLeft PROTO pGame:QWORD
MoveRight PROTO pGame:QWORD
MoveDown PROTO pGame:QWORD, dy:DWORD
RotatePiece PROTO pGame:QWORD
DropPiece PROTO pGame:QWORD
PauseGame PROTO pGame:QWORD
ResumeGame PROTO pGame:QWORD
TogglePause PROTO pGame:QWORD
SetPlayerName PROTO pGame:QWORD, pName:QWORD

InitRenderer PROTO pRenderer:QWORD, hwnd:QWORD
CleanupRenderer PROTO pRenderer:QWORD
CreateBackBuffer PROTO pRenderer:QWORD
ResizeRenderer PROTO pRenderer:QWORD, wWidth:DWORD, wHeight:DWORD
RenderGame PROTO pRenderer:QWORD, pGame:QWORD, hdc:QWORD
DrawBoard PROTO pRenderer:QWORD, pGame:QWORD
DrawGhostPiece PROTO pRenderer:QWORD, pGame:QWORD
DrawPiece PROTO pRenderer:QWORD, pPiece:QWORD
DrawNextPiece PROTO pRenderer:QWORD, pPiece:QWORD
DrawInfo PROTO pRenderer:QWORD, pGame:QWORD

SavePlayerName PROTO pName:QWORD
LoadPlayerName PROTO pGame:QWORD
SaveHighScore PROTO pGame:QWORD
LoadHighScore PROTO pGame:QWORD
ClearRegistry PROTO
