// ProcessListGUI.cpp - Implementation of GUI process explorer window
// Provides interactive process management with sorting, filtering, and operations

#include "ProcessListGUI.h"
#include "Utils.h"
#include <windowsx.h>
#include <sstream>
#include <algorithm>

// Global instance pointer for WindowProc callback
static ProcessListWindow* g_pWindow = nullptr;

// Protection dialog parameter structure
struct ProtectionParams {
    DWORD TargetPid;
    std::wstring SelectedLevel;
    std::wstring SelectedSigner;
	bool Force;
    bool Confirmed;
};

// Dialog procedure for protection configuration
INT_PTR CALLBACK ProtectDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static ProtectionParams* pParams = nullptr;

    switch (message) {
    case WM_INITDIALOG: {
        pParams = (ProtectionParams*)lParam;
        
        // Set target PID label
        std::wstring pidStr = L"Target PID: " + std::to_wstring(pParams->TargetPid);
        SetDlgItemText(hDlg, IDC_LABEL_PID, pidStr.c_str());

        // Populate Protection Level combo
        HWND hLevel = GetDlgItem(hDlg, IDC_COMBO_LEVEL);
        SendMessage(hLevel, CB_ADDSTRING, 0, (LPARAM)L"PPL");
        SendMessage(hLevel, CB_ADDSTRING, 0, (LPARAM)L"PP");
        SendMessage(hLevel, CB_SETCURSEL, 0, 0);

        // Populate Signer Type combo
        HWND hSigner = GetDlgItem(hDlg, IDC_COMBO_SIGNER);
        const wchar_t* signers[] = { 
            L"WinTcb", L"Windows", L"Antimalware", L"Lsa", 
            L"WinSystem", L"Authenticode", L"App", L"CodeGen" 
        };
        
        for (const auto& s : signers) {
            SendMessage(hSigner, CB_ADDSTRING, 0, (LPARAM)s);
        }
        SendMessage(hSigner, CB_SETCURSEL, 0, 0);

        return (INT_PTR)TRUE;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_BTN_OK) {
            // Get selected level
			int levelIdx = (int)SendMessage(GetDlgItem(hDlg, IDC_COMBO_LEVEL), CB_GETCURSEL, 0, 0);
			int signerIdx = (int)SendMessage(GetDlgItem(hDlg, IDC_COMBO_SIGNER), CB_GETCURSEL, 0, 0);
            
            if (levelIdx == CB_ERR || signerIdx == CB_ERR) {
                MessageBoxW(hDlg, L"Invalid selection", L"Error", MB_OK | MB_ICONERROR);
                return (INT_PTR)TRUE;
            }
            
            wchar_t buf[64];
            GetDlgItemText(hDlg, IDC_COMBO_LEVEL, buf, 64);
            pParams->SelectedLevel = buf;

            GetDlgItemText(hDlg, IDC_COMBO_SIGNER, buf, 64);
            pParams->SelectedSigner = buf;
			pParams->Force = (IsDlgButtonChecked(hDlg, IDC_CHECK_FORCE) == BST_CHECKED);
            pParams->Confirmed = true;
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        else if (LOWORD(wParam) == IDC_BTN_CANCEL) {
            pParams->Confirmed = false;
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

ProcessListWindow::ProcessListWindow(Controller* controller)
    : m_controller(controller)
    , m_hWnd(nullptr)
    , m_hListView(nullptr)
    , m_hFilterCheck(nullptr)
    , m_hSearchEdit(nullptr)
    , m_hRefreshButton(nullptr)
    , m_hStatusText(nullptr)
    , m_filterProtected(false)
    , m_sortColumn(-1)
    , m_sortAscending(true)
{
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);
}

ProcessListWindow::~ProcessListWindow()
{
    if (m_hWnd) {
        DestroyWindow(m_hWnd);
    }
}

// Creates and displays the main window
void ProcessListWindow::Show()
{
    if (!CreateMainWindow()) {
        ERROR(L"Failed to create main window");
        return;
    }
    
    RefreshProcessList();
    ShowWindow(m_hWnd, SW_SHOW);
    UpdateWindow(m_hWnd);
    
    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

// Creates the main window frame
bool ProcessListWindow::CreateMainWindow()
{
    const wchar_t* className = L"KVCProcessListWindow";
    
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = className;
    
    if (!RegisterClassExW(&wc)) {
        DWORD lastError = GetLastError();
        if (lastError != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }
    
    m_hWnd = CreateWindowExW(
        0,
        className,
        L"KVC Process List - All Processes",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1400, 800,
        nullptr,
        nullptr,
        GetModuleHandle(nullptr),
        this
    );
    
    return m_hWnd != nullptr;
}

// Creates the ListView control
bool ProcessListWindow::CreateListView()
{
    m_hListView = CreateWindowExW(
        0,
        WC_LISTVIEW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        0, 40,
        1380, 680,
        m_hWnd,
        (HMENU)IDC_PROCESS_LISTVIEW,
        GetModuleHandle(nullptr),
        nullptr
    );
    
    if (!m_hListView) {
        return false;
    }
    
    // Enable full row select and grid lines
    ListView_SetExtendedListViewStyle(m_hListView, 
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    
    // Install subclass for typeahead search
    SetWindowSubclass(m_hListView, ListViewSubclassProc, 0, (DWORD_PTR)this);
    
    SetupListViewColumns();
    return true;
}

// Creates filter checkbox, search box, and refresh button
bool ProcessListWindow::CreateControls()
{
    HINSTANCE hInst = GetModuleHandle(nullptr);
    
    // Filter checkbox
    m_hFilterCheck = CreateWindowExW(
        0, L"BUTTON", L"Show only protected",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 10, 150, 25,
        m_hWnd, (HMENU)IDC_FILTER_PROTECTED, hInst, nullptr
    );
    
    // Search label
    CreateWindowExW(
        0, L"STATIC", L"Search:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        170, 13, 50, 20,
        m_hWnd, nullptr, hInst, nullptr
    );
    
    // Search edit box
    m_hSearchEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL,
        225, 10, 200, 25,
        m_hWnd, (HMENU)IDC_SEARCH_EDIT, hInst, nullptr
    );
    
    // Refresh button
    m_hRefreshButton = CreateWindowExW(
        0, L"BUTTON", L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        435, 10, 80, 25,
        m_hWnd, (HMENU)IDC_REFRESH_BUTTON, hInst, nullptr
    );
    
    // Status text
    m_hStatusText = CreateWindowExW(
        0, L"STATIC", L"Loading...",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 730, 1360, 20,
        m_hWnd, (HMENU)IDC_STATUS_TEXT, hInst, nullptr
    );
    
    return true;
}

// Sets up ListView columns with appropriate widths
void ProcessListWindow::SetupListViewColumns()
{
    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    col.fmt = LVCFMT_LEFT;
    
    // PID
    col.pszText = (LPWSTR)L"PID";
    col.cx = 60;
    ListView_InsertColumn(m_hListView, COL_PID, &col);
    
    // Process Name
    col.pszText = (LPWSTR)L"Process Name";
    col.cx = 180;
    ListView_InsertColumn(m_hListView, COL_NAME, &col);
    
    // User
    col.pszText = (LPWSTR)L"User";
    col.cx = 200;
    ListView_InsertColumn(m_hListView, COL_USER, &col);
    
    // Integrity Level
    col.pszText = (LPWSTR)L"Integrity";
    col.cx = 80;
    ListView_InsertColumn(m_hListView, COL_INTEGRITY, &col);
    
    // Protection Level
    col.pszText = (LPWSTR)L"Protection";
    col.cx = 90;
    ListView_InsertColumn(m_hListView, COL_PROTECTION, &col);
    
    // Signer
    col.pszText = (LPWSTR)L"Signer";
    col.cx = 120;
    ListView_InsertColumn(m_hListView, COL_SIGNER, &col);
    
    // EXE Signature
    col.pszText = (LPWSTR)L"EXE Signature";
    col.cx = 120;
    ListView_InsertColumn(m_hListView, COL_EXE_SIG, &col);
    
    // DLL Signature
    col.pszText = (LPWSTR)L"DLL Signature";
    col.cx = 120;
    ListView_InsertColumn(m_hListView, COL_DLL_SIG, &col);
    
    // Kernel Address
    col.pszText = (LPWSTR)L"Kernel Address";
    col.cx = 140;
    ListView_InsertColumn(m_hListView, COL_KERNEL_ADDR, &col);
}

// Refreshes process list from kernel via driver
void ProcessListWindow::RefreshProcessList()
{
    if (!m_controller->BeginDriverSession()) {
        ERROR(L"Failed to start driver session for GUI");
        return;
    }
    
    m_processes = m_controller->GetAllProcessList();
    m_controller->EndDriverSession(true);
    
    PopulateListView();
    UpdateStatusBar();
}

// Populates ListView with filtered process data
void ProcessListWindow::PopulateListView()
{
    DWORD selectedPid = GetSelectedPID();
    
    ListView_DeleteAllItems(m_hListView);
    
    int itemIndex = 0;
    int indexToSelect = -1;
    
    for (const auto& proc : m_processes) {
        // Apply filters
        if (m_filterProtected && proc.ProtectionLevel == 0) {
            continue;
        }
        
        if (!m_searchText.empty()) {
            std::wstring nameLower = proc.ProcessName;
            std::wstring searchLower = m_searchText;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
            std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::tolower);
            
            if (nameLower.find(searchLower) == std::wstring::npos) {
                continue;
            }
        }
        
        // Insert item
        LVITEMW item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = itemIndex;
        item.lParam = proc.Pid;
        
        // PID
        wchar_t pidStr[32];
        swprintf_s(pidStr, L"%d", proc.Pid);
        item.pszText = pidStr;
        int actualIndex = ListView_InsertItem(m_hListView, &item);
        
        if (actualIndex >= 0) {
            // Check if this is the previously selected process
            if (proc.Pid == selectedPid) {
                indexToSelect = actualIndex;
            }
            
            // Process Name
            ListView_SetItemText(m_hListView, actualIndex, COL_NAME, (LPWSTR)proc.ProcessName.c_str());
            
            // User
            ListView_SetItemText(m_hListView, actualIndex, COL_USER, (LPWSTR)proc.UserName.c_str());
            
            // Integrity Level
            ListView_SetItemText(m_hListView, actualIndex, COL_INTEGRITY, (LPWSTR)proc.IntegrityLevel.c_str());
            
            // Protection Level
            ListView_SetItemText(m_hListView, actualIndex, COL_PROTECTION, 
                (LPWSTR)Utils::GetProtectionLevelAsString(proc.ProtectionLevel));
            
            // Signer
            ListView_SetItemText(m_hListView, actualIndex, COL_SIGNER, 
                (LPWSTR)Utils::GetSignerTypeAsString(proc.SignerType));
            
            // EXE Signature
            ListView_SetItemText(m_hListView, actualIndex, COL_EXE_SIG, 
                (LPWSTR)Utils::GetSignatureLevelAsString(proc.SignatureLevel));
            
            // DLL Signature
            ListView_SetItemText(m_hListView, actualIndex, COL_DLL_SIG, 
                (LPWSTR)Utils::GetSignatureLevelAsString(proc.SectionSignatureLevel));
            
            // Kernel Address
            wchar_t addrStr[32];
            swprintf_s(addrStr, L"0x%016llX", proc.KernelAddress);
            ListView_SetItemText(m_hListView, actualIndex, COL_KERNEL_ADDR, addrStr);
            
            itemIndex++;
        }
    }
    
    // Restore selection
    if (indexToSelect != -1) {
        ListView_SetItemState(m_hListView, indexToSelect, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(m_hListView, indexToSelect, FALSE);
    }
}

// Updates status bar with process count
void ProcessListWindow::UpdateStatusBar()
{
    int totalCount = (int)m_processes.size();
    int displayedCount = ListView_GetItemCount(m_hListView);
    
    wchar_t statusText[256];
    swprintf_s(statusText, L"Total: %d processes | Displayed: %d", totalCount, displayedCount);
    SetWindowTextW(m_hStatusText, statusText);
}

// Gets PID of currently selected item
DWORD ProcessListWindow::GetSelectedPID()
{
    int selectedIndex = ListView_GetNextItem(m_hListView, -1, LVNI_SELECTED);
    if (selectedIndex < 0) {
        return 0;
    }
    
    LVITEMW item = {};
    item.mask = LVIF_PARAM;
    item.iItem = selectedIndex;
    
    if (ListView_GetItem(m_hListView, &item)) {
        return static_cast<DWORD>(item.lParam);
    }
    
    return 0;
}

// Determines text color for process based on protection characteristics
COLORREF ProcessListWindow::GetProcessColor(const ProcessEntry& entry)
{
    // Only color protected processes (ProtectionLevel > 0)
    if (entry.ProtectionLevel == 0) {
        return RGB(0, 0, 0); // Black for unprotected processes
    }

    // Kernel/Critical processes (highest protection signature levels)
    if (entry.SignatureLevel == 0x1e && entry.SectionSignatureLevel == 0x1c) {
        return RGB(128, 0, 128); // Purple
    }

    // Color by signer type for protected processes
    UCHAR signerType = entry.SignerType;
    
    if (signerType == 4) { // Lsa
        return RGB(200, 0, 0); // Red
    }
    if (signerType == 6) { // WinTcb
        return RGB(0, 160, 0); // Green
    }
    if (signerType == 7) { // WinSystem
        return RGB(0, 0, 200); // Blue
    }
    if (signerType == 5) { // Windows
        return RGB(0, 150, 150); // Teal/Cyan
    }
    if (signerType == 3) { // Antimalware
        return RGB(200, 150, 0); // Dark Yellow/Orange
    }

	// Default for other protected signers
	return RGB(200, 150, 0); // Dark Yellow
}

// Updates header sort direction indicators
void ProcessListWindow::UpdateHeaderSortIcon()
{
    HWND hHeader = ListView_GetHeader(m_hListView);
    int columnCount = Header_GetItemCount(hHeader);

    for (int i = 0; i < columnCount; i++) {
        HDITEM item = {};
        item.mask = HDI_FORMAT;
        Header_GetItem(hHeader, i, &item);

        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);

        if (i == m_sortColumn) {
            item.fmt |= (m_sortAscending ? HDF_SORTUP : HDF_SORTDOWN);
        }

        Header_SetItem(hHeader, i, &item);
    }
}

// Sorts ListView by column and refreshes display
void ProcessListWindow::SortListView(int column)
{
    // Toggle sort direction if same column, otherwise reset to ascending
    if (column == m_sortColumn) {
        m_sortAscending = !m_sortAscending;
    } else {
        m_sortColumn = column;
        m_sortAscending = true;
    }

    // Sort the process vector
    std::sort(m_processes.begin(), m_processes.end(), 
        [this](const ProcessEntry& a, const ProcessEntry& b) -> bool {
            bool result = false;

            switch (m_sortColumn) {
                case COL_PID: 
                    result = (a.Pid < b.Pid); 
                    break;
                
                case COL_NAME: 
                    result = (_wcsicmp(a.ProcessName.c_str(), b.ProcessName.c_str()) < 0); 
                    break;
                
                case COL_USER: 
                    result = (_wcsicmp(a.UserName.c_str(), b.UserName.c_str()) < 0); 
                    break;
                
                case COL_INTEGRITY: 
                    result = (_wcsicmp(a.IntegrityLevel.c_str(), b.IntegrityLevel.c_str()) < 0); 
                    break;
                
                case COL_PROTECTION:
                    if (a.ProtectionLevel != b.ProtectionLevel)
                        result = (a.ProtectionLevel < b.ProtectionLevel);
                    else
                        result = (a.SignerType < b.SignerType);
                    break;

                case COL_SIGNER:
                    result = (a.SignerType < b.SignerType);
                    break;

                case COL_EXE_SIG:
                    result = (a.SignatureLevel < b.SignatureLevel);
                    break;

                case COL_DLL_SIG:
                    result = (a.SectionSignatureLevel < b.SectionSignatureLevel);
                    break;

                case COL_KERNEL_ADDR:
                    result = (a.KernelAddress < b.KernelAddress);
                    break;

                default:
                    result = (a.Pid < b.Pid);
                    break;
            }

            return m_sortAscending ? result : !result;
        }
    );

    // Update header sort indicator
    UpdateHeaderSortIcon();
    
    // Refresh view with reduced flicker
    SendMessage(m_hListView, WM_SETREDRAW, FALSE, 0);
    PopulateListView();
    SendMessage(m_hListView, WM_SETREDRAW, TRUE, 0);
}

// Shows context menu for process operations
void ProcessListWindow::ShowContextMenu(int x, int y)
{
    if (GetSelectedPID() == 0) {
        return;
    }
    
    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, IDM_PROTECT, L"Protect Process");
    AppendMenuW(hMenu, MF_STRING, IDM_UNPROTECT, L"Unprotect Process");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, IDM_KILL, L"Terminate Process");
    AppendMenuW(hMenu, MF_STRING, IDM_DUMP, L"Dump Process");
    AppendMenuW(hMenu, MF_STRING, IDM_MODULES, L"Show Modules");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, IDM_COPY_PID, L"Copy PID");
    AppendMenuW(hMenu, MF_STRING, IDM_COPY_NAME, L"Copy Name");
    
    TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN, x, y, 0, m_hWnd, nullptr);
    DestroyMenu(hMenu);
}

// Handles context menu command selection
void ProcessListWindow::HandleContextMenuCommand(UINT commandId)
{
    DWORD pid = GetSelectedPID();
    if (pid == 0) {
        return;
    }
    
    switch (commandId) {
        case IDM_PROTECT:
            ProtectSelected();
            break;
            
        case IDM_UNPROTECT:
            UnprotectSelected();
            break;
            
        case IDM_KILL:
            KillSelected();
            break;
            
        case IDM_DUMP:
            DumpSelected();
            break;
            
        case IDM_MODULES:
            ShowModulesSelected();
            break;
            
        case IDM_COPY_PID:
            CopySelectedToClipboard(COL_PID);
            break;
            
        case IDM_COPY_NAME:
            CopySelectedToClipboard(COL_NAME);
            break;
    }
}

// Protect selected process with configuration dialog
void ProcessListWindow::ProtectSelected()
{
    DWORD pid = GetSelectedPID();
    if (pid == 0) return;

    ProtectionParams params;
    params.TargetPid = pid;
    params.Confirmed = false;

    INT_PTR result = DialogBoxParam(
        GetModuleHandle(nullptr), 
        MAKEINTRESOURCE(IDD_PROTECT_DIALOG), 
        m_hWnd, 
        ProtectDialogProc, 
        (LPARAM)&params
    );

	if (params.Confirmed) {
		// Check if process is already protected (only if not forcing)
		if (!params.Force) {
			bool isProtected = false;
			for (const auto& proc : m_processes) {
				if (proc.Pid == pid) {
					isProtected = (proc.ProtectionLevel != 0);
					break;
				}
			}
			
			if (isProtected) {
				MessageBoxW(m_hWnd, L"Process is already protected. Use Force checkbox to override.", L"Information", MB_OK | MB_ICONINFORMATION);
				return;
			}
		}
		
		bool result = params.Force 
			? m_controller->SetProcessProtection(pid, params.SelectedLevel, params.SelectedSigner)
			: m_controller->ProtectProcess(pid, params.SelectedLevel, params.SelectedSigner);

		if (result) {
			RefreshProcessList();
			
			wchar_t msg[256];
			swprintf_s(msg, L"Process %d protected successfully with %s-%s", 
				pid, params.SelectedLevel.c_str(), params.SelectedSigner.c_str());
			MessageBoxW(m_hWnd, msg, L"Success", MB_OK | MB_ICONINFORMATION);
		} else {
			MessageBoxW(m_hWnd, L"Failed to protect process. Verify permissions or DSE status.", L"Error", MB_OK | MB_ICONERROR);
		}
	}
}

// Unprotect selected process
void ProcessListWindow::UnprotectSelected()
{
    DWORD pid = GetSelectedPID();
    if (pid == 0) return;
    
    // Check if process is already unprotected
    bool isProtected = false;
    for (const auto& proc : m_processes) {
        if (proc.Pid == pid) {
            isProtected = (proc.ProtectionLevel != 0);
            break;
        }
    }
    
    if (!isProtected) {
        MessageBoxW(m_hWnd, L"Process is already unprotected", L"Information", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    if (m_controller->UnprotectProcess(pid)) {
        RefreshProcessList();
        MessageBoxW(m_hWnd, L"Process unprotected successfully", L"Success", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxW(m_hWnd, L"Failed to unprotect process", L"Error", MB_OK | MB_ICONERROR);
    }
}

// Kill selected process
void ProcessListWindow::KillSelected()
{
    DWORD pid = GetSelectedPID();
    if (pid == 0) return;
    
    wchar_t msg[256];
    swprintf_s(msg, L"Are you sure you want to terminate process %d?", pid);
    
    if (MessageBoxW(m_hWnd, msg, L"Confirm Termination", MB_YESNO | MB_ICONWARNING) == IDYES) {
        if (m_controller->KillProcess(pid)) {
            RefreshProcessList();
            MessageBoxW(m_hWnd, L"Process terminated successfully", L"Success", MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBoxW(m_hWnd, L"Failed to terminate process", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

// Dump selected process
void ProcessListWindow::DumpSelected()
{
    DWORD pid = GetSelectedPID();
    if (pid == 0) return;
    
    // Get Downloads folder path (same as CLI)
    std::wstring outPath;
    wchar_t* dl;
    if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &dl) == S_OK) {
        outPath = dl;
        outPath += L"\\";
        CoTaskMemFree(dl);
    } else {
        outPath = L".\\";
    }
    
    if (m_controller->DumpProcess(pid, outPath)) {
        wchar_t msg[512];
        swprintf_s(msg, L"Process dumped successfully to:\n%s", outPath.c_str());
        MessageBoxW(m_hWnd, msg, L"Success", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxW(m_hWnd, L"Failed to dump process", L"Error", MB_OK | MB_ICONERROR);
    }
}

// Show modules for selected process
void ProcessListWindow::ShowModulesSelected()
{
    DWORD pid = GetSelectedPID();
    if (pid == 0) return;
    
    m_controller->EnumerateProcessModules(pid);
    MessageBoxW(m_hWnd, L"Module list displayed in console", L"Info", MB_OK | MB_ICONINFORMATION);
}

// Copy selected item column to clipboard
void ProcessListWindow::CopySelectedToClipboard(ProcessColumn column)
{
    int selectedIndex = ListView_GetNextItem(m_hListView, -1, LVNI_SELECTED);
    if (selectedIndex < 0) return;
    
    wchar_t text[512] = {};
    ListView_GetItemText(m_hListView, selectedIndex, column, text, 512);
    
    if (OpenClipboard(m_hWnd)) {
        EmptyClipboard();
        
        int len = (int)wcslen(text);
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(wchar_t));
        
        if (hMem) {
            wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
            wcscpy_s(pMem, len + 1, text);
            GlobalUnlock(hMem);
            
            SetClipboardData(CF_UNICODETEXT, hMem);
        }
        
        CloseClipboard();
    }
}

// Static window procedure that forwards to instance method
LRESULT CALLBACK ProcessListWindow::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    ProcessListWindow* pWindow = nullptr;
    
    if (msg == WM_CREATE) {
        CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
        pWindow = reinterpret_cast<ProcessListWindow*>(pCreate->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pWindow));
        pWindow->m_hWnd = hwnd;
        
        // Create child controls
        pWindow->CreateListView();
        pWindow->CreateControls();
        
    } else {
        pWindow = reinterpret_cast<ProcessListWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (pWindow) {
        return pWindow->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// Instance message handler
LRESULT ProcessListWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
        case WM_SIZE:
            OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
            
		case WM_NOTIFY:
			return OnNotify(reinterpret_cast<LPNMHDR>(lParam));
            
        case WM_COMMAND:
            OnCommand(wParam);
            return 0;
            
        case WM_CONTEXTMENU: {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            ShowContextMenu(pt.x, pt.y);
            return 0;
        }
            
        case WM_DESTROY:
            OnDestroy();
            return 0;
    }
    
    return DefWindowProc(m_hWnd, msg, wParam, lParam);
}

// Handle window resize
void ProcessListWindow::OnSize(int width, int height)
{
    if (m_hListView) {
        SetWindowPos(m_hListView, nullptr, 0, 40, width - 20, height - 90, SWP_NOZORDER);
    }
    
    if (m_hStatusText) {
        SetWindowPos(m_hStatusText, nullptr, 10, height - 40, width - 20, 20, SWP_NOZORDER);
    }
}

// Handle notification messages
LRESULT ProcessListWindow::OnNotify(LPNMHDR pnmh)
{
    if (pnmh->idFrom == IDC_PROCESS_LISTVIEW) {
        
        // Handle column header click for sorting
        if (pnmh->code == LVN_COLUMNCLICK) {
            LPNMLISTVIEW pnmlv = reinterpret_cast<LPNMLISTVIEW>(pnmh);
            SortListView(pnmlv->iSubItem);
            return 0;
        }
        // Handle custom draw for row coloring
        else if (pnmh->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW lplvcd = reinterpret_cast<LPNMLVCUSTOMDRAW>(pnmh);
            
            switch (lplvcd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
                
            case CDDS_ITEMPREPAINT: {
                // Get PID from lParam instead of using dwItemSpec as index
                LVITEMW item = {};
                item.mask = LVIF_PARAM;
                item.iItem = static_cast<int>(lplvcd->nmcd.dwItemSpec);
                
                if (ListView_GetItem(m_hListView, &item)) {
                    DWORD pid = static_cast<DWORD>(item.lParam);
                    
                    // Find process in vector by PID
                    for (const auto& proc : m_processes) {
                        if (proc.Pid == pid) {
                            lplvcd->clrText = GetProcessColor(proc);
                            break;
                        }
                    }
                }
                return CDRF_NEWFONT;
            }
            }
        }
    }
    return 0;
}

// Handle command messages
void ProcessListWindow::OnCommand(WPARAM wParam)
{
    WORD commandId = LOWORD(wParam);
    
    switch (commandId) {
        case IDC_FILTER_PROTECTED:
            m_filterProtected = (Button_GetCheck(m_hFilterCheck) == BST_CHECKED);
            PopulateListView();
            UpdateStatusBar();
            break;
            
        case IDC_REFRESH_BUTTON:
            RefreshProcessList();
            break;
            
        case IDC_SEARCH_EDIT:
            if (HIWORD(wParam) == EN_CHANGE) {
                wchar_t searchText[256] = {};
                GetWindowTextW(m_hSearchEdit, searchText, 256);
                m_searchText = searchText;
                PopulateListView();
                UpdateStatusBar();
            }
            break;
            
        default:
            HandleContextMenuCommand(commandId);
            break;
    }
}

// Handle window destruction
void ProcessListWindow::OnDestroy()
{
    PostQuitMessage(0);
}

// ListView subclass procedure for typeahead search
LRESULT CALLBACK ProcessListWindow::ListViewSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    ProcessListWindow* pThis = reinterpret_cast<ProcessListWindow*>(dwRefData);
    
    if (msg == WM_CHAR) {
        wchar_t ch = (wchar_t)wParam;
        
        // Handle alphanumeric characters
        if (iswalnum(ch)) {
            pThis->JumpToLetter(towlower(ch));
            return 0;
        }
    }
    
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

// Jump to first process name starting with given letter
void ProcessListWindow::JumpToLetter(wchar_t letter)
{
    int itemCount = ListView_GetItemCount(m_hListView);
    if (itemCount == 0) return;
    
    // Get currently selected item to start search from next item
    int currentSel = ListView_GetNextItem(m_hListView, -1, LVNI_SELECTED);
    int startFrom = (currentSel >= 0) ? currentSel + 1 : 0;
    
    // Search from current position to end
    for (int i = startFrom; i < itemCount; i++) {
        wchar_t text[256] = {};
        ListView_GetItemText(m_hListView, i, COL_NAME, text, 256);
        
        if (text[0] && towlower(text[0]) == letter) {
            // Found matching item - select and ensure visible
            ListView_SetItemState(m_hListView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(m_hListView, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(m_hListView, i, FALSE);
            return;
        }
    }
    
    // If not found from current position, search from beginning
    for (int i = 0; i < startFrom; i++) {
        wchar_t text[256] = {};
        ListView_GetItemText(m_hListView, i, COL_NAME, text, 256);
        
        if (text[0] && towlower(text[0]) == letter) {
            ListView_SetItemState(m_hListView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(m_hListView, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(m_hListView, i, FALSE);
            return;
        }
    }
}

// Entry point function for GUI mode
void ShowProcessListGUI(Controller* controller)
{
    INFO(L"[GUI] Initializing High-Security Environment...");
    if (controller->BeginDriverSession()) 
    {
        if (controller->SelfProtect(L"PPL", L"WinTcb")) {
            SUCCESS(L"[GUI] Self-Protection Active: PPL-WinTcb applied.");
            SUCCESS(L"[GUI] Process is now immune to external termination.");
        } else {
            ERROR(L"[GUI] Failed to apply Self-Protection. Running in standard mode.");
        }
        controller->EndDriverSession(false);
    }
    else
    {
        ERROR(L"[GUI] Failed to initialize driver session. Self-Protection unavailable.");
    }
    ProcessListWindow window(controller);
    window.Show();
}