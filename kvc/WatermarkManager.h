// WatermarkManager.h
// Windows Desktop Watermark Removal via ExplorerFrame.dll Hijacking

#pragma once

#include "common.h"
#include "TrustedInstallerIntegrator.h"
#include <windows.h>
#include <vector>
#include <string>

class WatermarkManager
{
public:
    explicit WatermarkManager(TrustedInstallerIntegrator& trustedInstaller);
    
    // Main operations
    bool RemoveWatermark() noexcept;
    bool RestoreWatermark() noexcept;
    std::wstring GetWatermarkStatus() noexcept;
    bool IsWatermarkRemoved() noexcept;

private:
    // Extraction pipeline: Resource → Skip icon → XOR → CAB → Split PE
    bool ExtractWatermarkDLL(std::vector<BYTE>& outDllData) noexcept;
    
    // System operations
    bool RestartExplorer() noexcept;
    std::wstring GetSystem32Path() noexcept;
    std::wstring ReadRegistryValue(HKEY hKey, const std::wstring& subKey, 
                                   const std::wstring& valueName) noexcept;
    
    TrustedInstallerIntegrator& m_trustedInstaller;
    
    // Registry paths
    static constexpr const wchar_t* CLSID_KEY = 
        L"CLSID\\{ab0b37ec-56f6-4a0e-a8fd-7a8bf7c2da96}\\InProcServer32";
    static constexpr const wchar_t* HIJACKED_DLL = 
        L"%SystemRoot%\\system32\\ExpIorerFrame.dll";
    static constexpr const wchar_t* ORIGINAL_DLL = 
        L"%SystemRoot%\\system32\\ExplorerFrame.dll";
    
    // Resource constants
    static constexpr size_t ICON_SKIP_SIZE = 3774;  // Skip icon data in resource
    static constexpr int RESOURCE_ID = 102;          // New resource for watermark
};