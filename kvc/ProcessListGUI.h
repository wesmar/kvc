// ProcessListGUI.h - GUI window for displaying all system processes with detailed information
// Implements ListView-based process explorer with sorting, filtering, and context menu operations

#pragma once

#include "common.h"
#include "Controller.h"
#include <vector>
#include <string>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")

// Backward compatibility safeguard for Windows API programming.
#ifndef IDC_STATIC
#define IDC_STATIC -1
#endif

// Resource IDs for dialog and controls
#define IDD_PROCESS_LIST        1001
#define IDC_PROCESS_LISTVIEW    1002
#define IDC_FILTER_PROTECTED    1003
#define IDC_SEARCH_EDIT         1004
#define IDC_REFRESH_BUTTON      1005
#define IDC_STATUS_TEXT         1006

#define IDD_PROTECT_DIALOG      1100
#define IDC_COMBO_LEVEL         1101
#define IDC_COMBO_SIGNER        1102
#define IDC_BTN_OK              1103
#define IDC_BTN_CANCEL          1104
#define IDC_LABEL_PID           1105
#define IDC_CHECK_FORCE         1106

// Context menu IDs
#define IDM_PROTECT             2001
#define IDM_UNPROTECT           2002
#define IDM_KILL                2003
#define IDM_DUMP                2004
#define IDM_MODULES             2005
#define IDM_COPY_PID            2006
#define IDM_COPY_NAME           2007
#define IDM_COPY_PATH           2008

// ListView column indices
enum ProcessColumn {
    COL_PID = 0,
    COL_NAME,
    COL_USER,
    COL_INTEGRITY,
    COL_PROTECTION,
    COL_SIGNER,
    COL_EXE_SIG,
    COL_DLL_SIG,
    COL_KERNEL_ADDR
};

// Main window class for process list GUI
class ProcessListWindow
{
public:
    ProcessListWindow(Controller* controller);
    ~ProcessListWindow();

    // Show the window and enter message loop
    void Show();

private:
    Controller* m_controller;
    HWND m_hWnd;
    HWND m_hListView;
    HWND m_hFilterCheck;
    HWND m_hSearchEdit;
    HWND m_hRefreshButton;
    HWND m_hStatusText;
    
    std::vector<ProcessEntry> m_processes;
    bool m_filterProtected;
    std::wstring m_searchText;
    int m_sortColumn;
    bool m_sortAscending;

    // Window creation and initialization
    bool CreateMainWindow();
    bool CreateListView();
    bool CreateControls();
    void SetupListViewColumns();
    
    // Data management
    void RefreshProcessList();
    void PopulateListView();
    void ApplyFilters();
    void UpdateStatusBar();
    
    // ListView operations
    void SortListView(int column);
    void UpdateHeaderSortIcon();
    COLORREF GetProcessColor(const ProcessEntry& entry);
    DWORD GetSelectedPID();
    std::wstring GetSelectedProcessName();
    void CopySelectedToClipboard(ProcessColumn column);
    
    // Context menu
    void ShowContextMenu(int x, int y);
    void HandleContextMenuCommand(UINT commandId);
    
    // Process operations
    void ProtectSelected();
    void UnprotectSelected();
    void KillSelected();
    void DumpSelected();
    void ShowModulesSelected();
    
    // Message handlers
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    void OnSize(int width, int height);
    LRESULT OnNotify(LPNMHDR pnmh);
    void OnCommand(WPARAM wParam);
    void OnDestroy();
    
    // ListView typeahead search
    static LRESULT CALLBACK ListViewSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
    void JumpToLetter(wchar_t letter);
};

// Entry point function called from kvc.cpp when --gui flag is used
void ShowProcessListGUI(Controller* controller);
