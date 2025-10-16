// ReportExporter.h - Export DPAPI extraction results in HTML, TXT, and console formats

#pragma once

#include "common.h"
#include <vector>
#include <string>

struct PasswordResult;
struct RegistryMasterKey;

/**
 * @struct ReportData
 * Aggregates extraction results and calculates statistics
 */
struct ReportData
{
    std::vector<PasswordResult> passwordResults; ///< Extracted passwords
    std::vector<RegistryMasterKey> masterKeys;   ///< Extracted registry keys
    std::wstring outputPath;                     ///< Output directory
    std::string timestamp;                       ///< Generation timestamp

    struct Stats {
        int totalPasswords = 0;
        int chromePasswords = 0;
        int edgePasswords = 0;
        int wifiPasswords = 0;
        int masterKeyCount = 0;
    } stats;

    ReportData() = default;
    ReportData(const std::vector<PasswordResult>& results,
               const std::vector<RegistryMasterKey>& keys,
               const std::wstring& path);

private:
    void CalculateStatistics(); ///< Populate stats from results
};

/**
 * ReportExporter
 * Generates professional reports in multiple formats
 */
class ReportExporter
{
public:
    ReportExporter() = default;
    ~ReportExporter() = default;

    ReportExporter(const ReportExporter&) = delete;
    ReportExporter& operator=(const ReportExporter&) = delete;
    ReportExporter(ReportExporter&&) noexcept = default;
    ReportExporter& operator=(ReportExporter&&) noexcept = default;

    bool ExportAllFormats(const ReportData& data) noexcept; ///< HTML + TXT + console summary
    bool ExportHTML(const ReportData& data) noexcept;       ///< Generate HTML report
    bool ExportTXT(const ReportData& data) noexcept;        ///< Generate TXT report
    void DisplaySummary(const ReportData& data) noexcept;   ///< Print console summary

private:
    // HTML generation
    std::string GenerateHTMLContent(const ReportData& data) noexcept;
    std::string BuildHTMLHeader(const ReportData& data) noexcept;
    std::string BuildSummarySection(const ReportData& data) noexcept;
    std::string BuildMasterKeysTable(const ReportData& data) noexcept;
    std::string BuildPasswordsTable(const ReportData& data) noexcept;
    std::string BuildWiFiTable(const ReportData& data) noexcept;

    // TXT generation
    std::wstring GenerateTXTContent(const ReportData& data) noexcept;
    std::wstring BuildTXTHeader(const ReportData& data) noexcept;
    std::wstring BuildTXTMasterKeys(const ReportData& data) noexcept;
    std::wstring BuildTXTPasswords(const ReportData& data) noexcept;
    std::wstring BuildTXTWiFi(const ReportData& data) noexcept;

    // Utilities
    std::wstring GetHTMLPath(const std::wstring& outputPath) noexcept;
    std::wstring GetTXTPath(const std::wstring& outputPath) noexcept;
    bool EnsureOutputDirectory(const std::wstring& path) noexcept;
};
