// ControllerBinaryManager.cpp - Binary component extraction and deployment with privilege escalation

#include "Controller.h"
#include "common.h"
#include "Utils.h"
#include "HelpSystem.h"
#include "TrustedInstallerIntegrator.h"
#include <filesystem>
#include <array>
#include <winioctl.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

namespace fs = std::filesystem;

// ── EFI helpers (local to this translation unit) ─────────────────────────────

// Finds the EFI System Partition volume GUID path using Windows API
static std::wstring FindESPVolumeGuid() noexcept
{
    wchar_t volumeName[MAX_PATH];
    HANDLE hFind = FindFirstVolumeW(volumeName, ARRAYSIZE(volumeName));
    if (hFind == INVALID_HANDLE_VALUE) return {};

    do {
        // volumeName is in format \\?\Volume{GUID}\ (trailing backslash)
        std::wstring volumePath = volumeName;
        if (volumePath.back() == L'\\') volumePath.pop_back();

        // Open volume handle to query partition information
        HANDLE hVolume = CreateFileW(volumePath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING, 0, nullptr);
        if (hVolume != INVALID_HANDLE_VALUE) {
            PARTITION_INFORMATION_EX partInfo{};
            DWORD bytesReturned = 0;
            if (DeviceIoControl(hVolume, IOCTL_DISK_GET_PARTITION_INFO_EX, nullptr, 0,
                                &partInfo, sizeof(partInfo), &bytesReturned, nullptr)) {
                if (partInfo.PartitionStyle == PARTITION_STYLE_GPT) {
                    // EFI System Partition GUID: {C12A7328-F81F-11D2-BA4B-00A0C93EC93B}
                    static constexpr GUID ESP_GUID = { 0xC12A7328, 0xF81F, 0x11D2, { 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
                    if (IsEqualGUID(partInfo.Gpt.PartitionType, ESP_GUID)) {
                        CloseHandle(hVolume);
                        FindVolumeClose(hFind);
                        return volumeName; // Returns with trailing backslash (e.g. \\?\Volume{...}\)
                    }
                }
            }
            CloseHandle(hVolume);
        }
    } while (FindNextVolumeW(hFind, volumeName, ARRAYSIZE(volumeName)));

    FindVolumeClose(hFind);
    return {};
}

// Create directory tree (ignore if already exists)
static void EnsureDir(const fs::path& p) noexcept
{
    try { fs::create_directories(p); } catch (...) {}
}

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
        
        // Add Windows Defender exclusions for deployed components using batch operation
        INFO(L"Adding Windows Defender exclusions for deployed components");

        // Use batch operation instead of individual calls for better performance
        std::vector<std::wstring> paths = {
            kvcPassPath.wstring(),
            kvcCryptPath.wstring(), 
            kvcMainPath.wstring()
        };

        std::vector<std::wstring> processes = {
            L"kvc_pass.exe",
            L"kvc.exe"
        };

        // Single batch call replaces 5 individual operations - much faster!
        m_trustedInstaller.AddMultipleDefenderExclusions(paths, processes, {});

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

// Ensure kvc_pass.exe is available: check System32/CWD, then try kvc.dat in CWD,
// then offer to download kvc.dat from GitHub. Called before browser password commands.
bool Controller::EnsureBinaryComponents() noexcept {
    auto probe = [](const std::wstring& path) noexcept {
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    };

    // Already deployed?
    wchar_t sys32[MAX_PATH];
    if (GetSystemDirectoryW(sys32, MAX_PATH) > 0) {
        if (probe(std::wstring(sys32) + L"\\kvc_pass.exe")) return true;
    }
    if (probe(L"kvc_pass.exe")) return true;

    // kvc.dat already in CWD?
    if (probe(KVC_DATA_FILE)) {
        INFO(L"Found kvc.dat, running setup...");
        return LoadAndSplitCombinedBinaries();
    }

    // Prompt download
    printf("[*] kvc.dat not found. Download from github? [Y/n]: ");
    fflush(stdout);
    wchar_t ch = static_cast<wchar_t>(_getwch());
    wprintf(L"%lc\n", ch);
    if (ch == L'n' || ch == L'N') {
        ERROR(L"kvc.dat required. Place it in the current directory or run 'kvc setup'.");
        return false;
    }

    INFO(L"Downloading kvc.dat...");
    HRESULT hr = URLDownloadToFileW(nullptr,
        L"https://github.com/wesmar/kvc/releases/download/latest/kvc.dat",
        KVC_DATA_FILE, 0, nullptr);
    if (FAILED(hr)) {
        ERROR(L"Download failed (0x%08X). Check internet connection.", static_cast<unsigned>(hr));
        return false;
    }
    SUCCESS(L"kvc.dat downloaded.");
    return LoadAndSplitCombinedBinaries();
}

// ── UnderVolter EFI module deployment ────────────────────────────────────────

bool Controller::DeployUnderVolter() noexcept
{
    try {
        // 1. Locate UnderVolter.dat (current dir or System32)
        fs::path datPath = fs::current_path() / KVC_UNDERVOLTER_FILE;
        if (!fs::exists(datPath)) {
            wchar_t sys32[MAX_PATH];
            GetSystemDirectoryW(sys32, MAX_PATH);
            datPath = fs::path(sys32) / KVC_UNDERVOLTER_FILE;
        }
        if (!fs::exists(datPath)) {
            printf("[*] UnderVolter.dat not found. Download from github? [Y/n]: ");
            fflush(stdout);
            wchar_t ch = static_cast<wchar_t>(_getwch());
            wprintf(L"%lc\n", ch);
            if (ch == L'n' || ch == L'N') {
                ERROR(L"UnderVolter.dat required. Place it in the current directory or run 'kvc setup'.");
                return false;
            }
            INFO(L"Downloading UnderVolter.dat...");
            const std::wstring cwdDat = (fs::current_path() / KVC_UNDERVOLTER_FILE).wstring();
            HRESULT hr = URLDownloadToFileW(nullptr,
                L"https://github.com/wesmar/kvc/releases/download/latest/UnderVolter.dat",
                cwdDat.c_str(), 0, nullptr);
            if (FAILED(hr)) {
                ERROR(L"Download failed (0x%08X). Check internet connection.", static_cast<unsigned>(hr));
                return false;
            }
            SUCCESS(L"UnderVolter.dat downloaded.");
            datPath = cwdDat;
        }

        INFO(L"Loading %s (%zu bytes)", datPath.c_str(),
             static_cast<size_t>(fs::file_size(datPath)));

        // 2. Read + XOR-decrypt
        auto enc = Utils::ReadFile(datPath.wstring());
        if (enc.empty()) { ERROR(L"Failed to read UnderVolter.dat"); return false; }

        auto dec = Utils::DecryptXOR(enc, KVC_XOR_KEY);
        if (dec.empty()) { ERROR(L"XOR decryption failed"); return false; }

        // 3. Split: dec = Loader.efi | UnderVolter.efi | UnderVolter.ini
        //    SplitCombinedPE only extracts exact PE sizes and discards trailing data,
        //    so UnderVolter.ini (plain text, no MZ) would be lost. Use GetPEFileLength
        //    twice directly on dec to find both PE boundaries; INI is the remainder.
        std::vector<BYTE> loaderData, uvEfiData, uvIniData;
        {
            auto loaderLen = Utils::GetPEFileLength(dec, 0);
            if (!loaderLen || *loaderLen == 0 || *loaderLen >= dec.size()) {
                ERROR(L"Failed to extract Loader.efi from UnderVolter.dat");
                return false;
            }
            auto efiLen = Utils::GetPEFileLength(dec, *loaderLen);
            if (!efiLen || *efiLen == 0 || *loaderLen + *efiLen >= dec.size()) {
                ERROR(L"Failed to extract UnderVolter.efi from UnderVolter.dat");
                return false;
            }
            loaderData.assign(dec.begin(), dec.begin() + *loaderLen);
            uvEfiData.assign(dec.begin() + *loaderLen, dec.begin() + *loaderLen + *efiLen);
            uvIniData.assign(dec.begin() + *loaderLen + *efiLen, dec.end());
        }
        if (loaderData.empty() || uvEfiData.empty() || uvIniData.empty()) {
            ERROR(L"Failed to extract UnderVolter.efi / UnderVolter.ini from UnderVolter.dat");
            return false;
        }

        INFO(L"Loader.efi: %zu bytes | UnderVolter.efi: %zu bytes | UnderVolter.ini: %zu bytes",
             loaderData.size(), uvEfiData.size(), uvIniData.size());

        // 4. Warning + confirmation
        printf("\n");
        printf("  %s\n",  HelpLayout::MakeBorderA('=', 64).c_str());
        printf("  |        UnderVolter EFI Deployment - WARNING                  |\n");
        printf("  |%s|\n", HelpLayout::MakeBorderA('-', 62).c_str());
        printf("  |  This will write files to the EFI System Partition.          |\n");
        printf("  |  Incorrect deployment may prevent Windows from booting.      |\n");
        printf("  |  KVC backs up BOOTX64.EFI before replacement.                |\n");
        printf("  |  Use 'kvc undervolter remove' to revert at any time.         |\n");
        printf("  %s\n",  HelpLayout::MakeBorderA('=', 64).c_str());
        printf("\n");
        printf("  Deployment mode:\n");
        printf("\n");
        printf("    [A]  Replace \\EFI\\BOOT\\BOOTX64.EFI with Loader.efi\n");
        printf("         Runs transparently on every boot automatically.\n");
        printf("\n");
        printf("    [B]  Copy files to \\EFI\\UnderVolter\\ only\n");
        printf("         Requires adding a UEFI boot entry manually.\n");
        printf("\n");
        printf("    [N]  Cancel\n");
        printf("\n");
        printf("  Choice [A/B/N]: ");

        wchar_t ch = static_cast<wchar_t>(_getwch());
        wprintf(L"%lc\n\n", ch);
        if (ch == L'N' || ch == L'n') {
            INFO(L"Deployment cancelled by user.");
            return false;
        }
        const bool replaceBootx64 = (ch == L'A' || ch == L'a');

        // 5. Find ESP
        const std::wstring espPath = FindESPVolumeGuid();
        if (espPath.empty()) { ERROR(L"Failed to locate EFI System Partition (ESP)"); return false; }

        INFO(L"Located EFI System Partition: %s", espPath.c_str());

        const fs::path esp = espPath;
        const fs::path uvDir = esp / L"EFI" / L"UnderVolter";

        EnsureDir(uvDir);

        bool ok = true;

        // 6. Always write UnderVolter.efi + UnderVolter.ini to EFI\UnderVolter
        ok &= Utils::WriteFile((uvDir / UNDERVOLTER_EFI_FILE).wstring(), uvEfiData);
        ok &= Utils::WriteFile((uvDir / UNDERVOLTER_INI_FILE).wstring(), uvIniData);

        if (replaceBootx64) {
            const fs::path bootDir    = esp / L"EFI" / L"BOOT";
            const fs::path bootx64    = bootDir / L"BOOTX64.EFI";
            const fs::path bootx64bak = bootDir / L"BOOTX64.efi.bak";

            EnsureDir(bootDir);

            // Backup original BOOTX64.EFI if not already backed up
            if (fs::exists(bootx64) && !fs::exists(bootx64bak)) {
                try {
                    fs::copy_file(bootx64, bootx64bak);
                    INFO(L"Backed up BOOTX64.EFI -> BOOTX64.efi.bak");
                } catch (...) {
                    ERROR(L"Failed to backup BOOTX64.EFI - aborting replacement");
                    return false;
                }
            }

            // Write Loader.efi as BOOTX64.EFI
            ok &= Utils::WriteFile(bootx64.wstring(), loaderData);
            if (ok) {
                INFO(L"Loader.efi written as \\EFI\\BOOT\\BOOTX64.EFI");
            }
        } else {
            // Standalone: write Loader.efi to \EFI\UnderVolter\ for manual boot entry
            ok &= Utils::WriteFile((uvDir / UNDERVOLTER_LOADER_FILE).wstring(), loaderData);
            INFO(L"Files written to \\EFI\\UnderVolter\\ - add UEFI boot entry manually.");
        }

        if (ok) {
            SUCCESS(L"UnderVolter deployed successfully.");
            SUCCESS(L"UnderVolter.efi + UnderVolter.ini -> \\EFI\\UnderVolter\\");
            if (replaceBootx64)
                SUCCESS(L"Loader.efi -> \\EFI\\BOOT\\BOOTX64.EFI (original backed up)");
            INFO(L"CPU voltage/power settings will apply on next boot.");
        } else {
            ERROR(L"Some files failed to write - deployment may be incomplete.");
        }
        return ok;

    } catch (const std::exception& e) {
        ERROR(L"Exception in DeployUnderVolter: %S", e.what());
        return false;
    } catch (...) {
        ERROR(L"Unknown exception in DeployUnderVolter");
        return false;
    }
}

bool Controller::RemoveUnderVolter() noexcept
{
    try {
        const std::wstring espPath = FindESPVolumeGuid();
        if (espPath.empty()) { ERROR(L"Failed to locate EFI System Partition (ESP)"); return false; }

        INFO(L"Located EFI System Partition: %s", espPath.c_str());

        const fs::path esp        = espPath;
        const fs::path uvDir      = esp / L"EFI" / L"UnderVolter";
        const fs::path bootDir    = esp / L"EFI" / L"BOOT";
        const fs::path bootx64    = bootDir / L"BOOTX64.EFI";
        const fs::path bootx64bak = bootDir / L"BOOTX64.efi.bak";

        bool ok = true;

        // Restore original BOOTX64.EFI from backup
        if (fs::exists(bootx64bak)) {
            try {
                fs::copy_file(bootx64bak, bootx64, fs::copy_options::overwrite_existing);
                fs::remove(bootx64bak);
                INFO(L"BOOTX64.efi.bak restored as BOOTX64.EFI");
            } catch (...) {
                ERROR(L"Failed to restore BOOTX64.efi.bak");
                ok = false;
            }
        } else {
            INFO(L"No backup found - BOOTX64.EFI was not replaced by KVC");
        }

        // Remove \EFI\UnderVolter\ directory
        if (fs::exists(uvDir)) {
            std::error_code ec;
            fs::remove_all(uvDir, ec);
            if (ec) {
                ERROR(L"Failed to remove \\EFI\\UnderVolter\\: %S", ec.message().c_str());
                ok = false;
            } else {
                INFO(L"\\EFI\\UnderVolter\\ removed");
            }
        } else {
            INFO(L"\\EFI\\UnderVolter\\ not found - nothing to remove");
        }

        if (ok) SUCCESS(L"UnderVolter removed from EFI partition.");
        return ok;

    } catch (const std::exception& e) {
        ERROR(L"Exception in RemoveUnderVolter: %S", e.what());
        return false;
    } catch (...) {
        ERROR(L"Unknown exception in RemoveUnderVolter");
        return false;
    }
}

std::wstring Controller::GetUnderVolterStatus() noexcept
{
    try {
        const std::wstring espPath = FindESPVolumeGuid();
        if (espPath.empty()) return L"ERROR: could not locate ESP";

        const fs::path esp        = espPath;
        const fs::path uvEfi      = esp / L"EFI" / L"UnderVolter" / UNDERVOLTER_EFI_FILE;
        const fs::path uvIni      = esp / L"EFI" / L"UnderVolter" / UNDERVOLTER_INI_FILE;
        const fs::path bootx64bak = esp / L"EFI" / L"BOOT" / L"BOOTX64.efi.bak";

        const bool efiPresent = fs::exists(uvEfi);
        const bool iniPresent = fs::exists(uvIni);
        const bool loaderActive = fs::exists(bootx64bak);

        if (!efiPresent && !iniPresent)
            return L"NOT DEPLOYED";

        std::wstring status = L"DEPLOYED";
        if (efiPresent)  status += L" | UnderVolter.efi: OK";
        if (iniPresent)  status += L" | UnderVolter.ini: OK";
        if (loaderActive) status += L" | Loader: ACTIVE (BOOTX64.EFI replaced)";
        else              status += L" | Loader: standalone (manual boot entry)";
        return status;

    } catch (...) {
        return L"ERROR: exception during status check";
    }
}
