#pragma once

#include "common.h"
#include <vector>
#include <string>

struct PasswordResult;
struct RegistryMasterKey;

// Report data aggregation with automatic statistics
struct ReportData
{
    std::vector<PasswordResult> passwordResults;
    std::vector<RegistryMasterKey> masterKeys;
    std::wstring outputPath;
    std::string timestamp;
    
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
    void CalculateStatistics();
};

// Professional report export in multiple formats
class ReportExporter
{
public:
    ReportExporter() = default;
    ~ReportExporter() = default;
    
    ReportExporter(const ReportExporter&) = delete;
    ReportExporter& operator=(const ReportExporter&) = delete;
    ReportExporter(ReportExporter&&) noexcept = default;
    ReportExporter& operator=(ReportExporter&&) noexcept = default;

    // Main export interface
    bool ExportAllFormats(const ReportData& data) noexcept;
    bool ExportHTML(const ReportData& data) noexcept;
    bool ExportTXT(const ReportData& data) noexcept;
    
    void DisplaySummary(const ReportData& data) noexcept;

private:
    // HTML generation with obfuscated markup
    std::string GenerateHTMLContent(const ReportData& data) noexcept;
    std::string BuildHTMLHeader(const ReportData& data) noexcept;
    std::string BuildSummarySection(const ReportData& data) noexcept;
    std::string BuildMasterKeysTable(const ReportData& data) noexcept;
    std::string BuildPasswordsTable(const ReportData& data) noexcept;
    std::string BuildWiFiTable(const ReportData& data) noexcept;
    
    // TXT generation for lightweight output
    std::wstring GenerateTXTContent(const ReportData& data) noexcept;
    std::wstring BuildTXTHeader(const ReportData& data) noexcept;
    std::wstring BuildTXTMasterKeys(const ReportData& data) noexcept;
    std::wstring BuildTXTPasswords(const ReportData& data) noexcept;
    std::wstring BuildTXTWiFi(const ReportData& data) noexcept;
    
    // Utility functions for encoding and paths
    std::wstring GetHTMLPath(const std::wstring& outputPath) noexcept;
    std::wstring GetTXTPath(const std::wstring& outputPath) noexcept;
    bool EnsureOutputDirectory(const std::wstring& path) noexcept;
};
