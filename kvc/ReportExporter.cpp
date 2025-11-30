#include "ReportExporter.h"
#include "Controller.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <array>
#include <string_view>

namespace fs = std::filesystem;

// CSS styling definitions as structured data for maintainability and reduced binary footprint
namespace HTMLStyles {
    struct StyleRule {
        std::string_view selector;
        std::string_view properties;
    };
    
    // Core layout and typography styles
    static constexpr std::array BASE_STYLES = {
        StyleRule{ "*", "box-sizing:border-box" },
        StyleRule{ "body", "font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;margin:0;padding:20px;background:#f0f2f5;color:#333" },
        StyleRule{ ".container", "max-width:100%;margin:0 auto;background:white;padding:25px;border-radius:10px;box-shadow:0 4px 12px rgba(0,0,0,0.1)" },
        StyleRule{ "h1", "color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:15px;margin-top:0;font-size:28px" },
    };
    
    // Summary and info box styles
    static constexpr std::array SUMMARY_STYLES = {
        StyleRule{ ".summary", "background:#e8f4fd;padding:20px;border-radius:8px;margin:25px 0;border-left:5px solid #3498db" },
        StyleRule{ ".summary strong", "color:#2980b9" },
    };
    
    // Table layout and formatting styles
    static constexpr std::array TABLE_STYLES = {
        StyleRule{ "table", "width:100%;border-collapse:collapse;margin:25px 0;table-layout:fixed" },
        StyleRule{ "th,td", "padding:14px;text-align:left;border:1px solid #ddd;word-wrap:break-word" },
        StyleRule{ "th", "background:#f8f9fa;font-weight:bold;color:#2c3e50;position:sticky;top:0" },
        StyleRule{ "tr:nth-child(even)", "background:#f9f9f9" },
        StyleRule{ "tr:hover", "background:#f0f8ff" },
    };
    
    // Data presentation styles
    static constexpr std::array DATA_STYLES = {
        StyleRule{ ".password", "background:#ffe6e6;font-family:'Consolas',monospace;font-size:14px" },
        StyleRule{ ".status-decrypted", "color:#27ae60;font-weight:bold" },
        StyleRule{ ".status-extracted", "color:#ffc107;font-weight:bold" },
        StyleRule{ ".hex-data", "font-family:'Consolas','Monaco',monospace;font-size:11px;word-break:break-all;background:#f8f9fa;padding:4px 8px;border-radius:4px" },
    };
    
    // Color-coded category indicators
    static constexpr std::array CATEGORY_STYLES = {
        StyleRule{ ".chrome", "border-left:5px solid #4285f4" },
        StyleRule{ ".edge", "border-left:5px solid #0078d4" },
        StyleRule{ ".wifi", "border-left:5px solid #ff6b35" },
        StyleRule{ ".masterkey", "border-left:5px solid #9b59b6" },
        StyleRule{ ".section-title", "font-size:20px;color:#2c3e50;margin:30px 0 15px 0;padding-bottom:10px;border-bottom:2px solid #3498db" },
    };
    
    // Build minified CSS from all style arrays
    inline std::string BuildCSS() {
        std::ostringstream css;
        
        auto appendStyles = [&css](const auto& styles) {
            for (const auto& rule : styles) {
                css << rule.selector << "{" << rule.properties << "}";
            }
        };
        
        appendStyles(BASE_STYLES);
        appendStyles(SUMMARY_STYLES);
        appendStyles(TABLE_STYLES);
        appendStyles(DATA_STYLES);
        appendStyles(CATEGORY_STYLES);
        
        return css.str();
    }
}

// Table column width definitions for HTML generation
namespace TableWidths {
    // Master keys table
    static constexpr std::array MASTER_KEYS = { "15%", "40%", "40%", "5%" };
    static constexpr std::array<std::string_view, 4> MASTER_KEYS_HEADERS = { 
        "Key Type", "Raw Data (Hex)", "Processed Data (Hex)", "Status" 
    };
    
    // Browser passwords table
    static constexpr std::array PASSWORDS = { "15%", "15%", "25%", "15%", "20%", "10%" };
    static constexpr std::array<std::string_view, 6> PASSWORDS_HEADERS = {
        "Browser", "Profile", "URL", "Username", "Password", "Status"
    };
    
    // WiFi credentials table
    static constexpr std::array WIFI = { "30%", "40%", "15%", "15%" };
    static constexpr std::array<std::string_view, 4> WIFI_HEADERS = {
        "Network Name", "Password", "Type", "Status"
    };
}

// ReportData implementation with automatic statistics calculation
ReportData::ReportData(const std::vector<PasswordResult>& results, 
                       const std::vector<RegistryMasterKey>& keys,
                       const std::wstring& path)
    : passwordResults(results), masterKeys(keys), outputPath(path)
{
    std::wstring wts = TimeUtils::GetFormattedTimestamp("datetime_display");
    timestamp = StringUtils::WideToUTF8(wts);
    
    CalculateStatistics();
}

void ReportData::CalculateStatistics()
{
    stats = Stats{};
    stats.masterKeyCount = static_cast<int>(masterKeys.size());
    
    for (const auto& result : passwordResults) {
        if (!result.password.empty()) {
            stats.totalPasswords++;
            
            if (result.type.find(L"Chrome") != std::wstring::npos) 
                stats.chromePasswords++;
            else if (result.type.find(L"Edge") != std::wstring::npos) 
                stats.edgePasswords++;
            else if (result.type.find(L"WiFi") != std::wstring::npos) 
                stats.wifiPasswords++;
        }
    }
}

bool ReportExporter::ExportAllFormats(const ReportData& data) noexcept
{
    INFO(L"Generating comprehensive password reports...");
    
    if (!EnsureOutputDirectory(data.outputPath)) {
        ERROR(L"Failed to create output directory: %s", data.outputPath.c_str());
        return false;
    }
    
    bool htmlSuccess = ExportHTML(data);
    bool txtSuccess = ExportTXT(data);
    
    return htmlSuccess && txtSuccess;
}

bool ReportExporter::ExportHTML(const ReportData& data) noexcept
{
    auto htmlPath = GetHTMLPath(data.outputPath);
    std::ofstream htmlFile(htmlPath, std::ios::binary);
    
    if (!htmlFile.is_open()) {
        ERROR(L"Failed to create HTML report: %s", htmlPath.c_str());
        return false;
    }
    
    std::string htmlContent = GenerateHTMLContent(data);
    htmlFile << htmlContent;
    htmlFile.close();
    
    return true;
}

bool ReportExporter::ExportTXT(const ReportData& data) noexcept
{
    auto txtPath = GetTXTPath(data.outputPath);
    std::wofstream txtFile(txtPath);
    
    if (!txtFile.is_open()) {
        ERROR(L"Failed to create TXT report: %s", txtPath.c_str());
        return false;
    }
    
    std::wstring txtContent = GenerateTXTContent(data);
    txtFile << txtContent;
    txtFile.close();
    
    return true;
}

void ReportExporter::DisplaySummary(const ReportData& data) noexcept
{
    std::wcout << L"\n";
    SUCCESS(L"=== DPAPI PASSWORD EXTRACTION SUMMARY ===");
    SUCCESS(L"Registry Master Keys: %d", data.stats.masterKeyCount);
    SUCCESS(L"Total Passwords: %d", data.stats.totalPasswords);
    SUCCESS(L"Chrome Passwords: %d", data.stats.chromePasswords);
    SUCCESS(L"Edge Passwords: %d", data.stats.edgePasswords);
    SUCCESS(L"WiFi Passwords: %d", data.stats.wifiPasswords);
    SUCCESS(L"Reports Generated:");
    SUCCESS(L"  - HTML: %s\\dpapi_results.html", data.outputPath.c_str());
    SUCCESS(L"  - TXT:  %s\\dpapi_results.txt", data.outputPath.c_str());
    std::wcout << L"\n";
}

std::string ReportExporter::GenerateHTMLContent(const ReportData& data) noexcept
{
    std::ostringstream html;
    
    html << BuildHTMLHeader(data);
    html << BuildSummarySection(data);
    html << BuildMasterKeysTable(data);
    html << BuildPasswordsTable(data);
    html << BuildWiFiTable(data);
    html << "</div>\n</body>\n</html>";
    
    return html.str();
}

std::string ReportExporter::BuildHTMLHeader(const ReportData& data) noexcept
{
    std::ostringstream header;
    
    header << "<!DOCTYPE html>\n<html>\n<head>\n";
    header << "    <meta charset=\"utf-8\">\n";
    header << "    <title>kvc DPAPI Extraction Results - Kernel Vulnerability Capabilities Framework by WESMAR</title>\n";
    header << "    <style>" << HTMLStyles::BuildCSS() << "</style>\n";
    header << "</head>\n<body>\n";
    header << "    <div class=\"container\">\n";
    header << "        <h1>&#128274; kvc DPAPI Extraction Results - Kernel Vulnerability Capabilities Framework by WESMAR</h1>\n";
    
    return header.str();
}

std::string ReportExporter::BuildSummarySection(const ReportData& data) noexcept
{
    std::ostringstream summary;
    
    summary << "        <div class=\"summary\">\n";
    summary << "            <strong>Generated:</strong> " << data.timestamp << "<br>\n";
    summary << "            <strong>Registry Master Keys:</strong> " << data.stats.masterKeyCount << "<br>\n";
    summary << "            <strong>Total Passwords:</strong> " << data.stats.totalPasswords << "<br>\n";
    summary << "            <strong>Chrome Passwords:</strong> " << data.stats.chromePasswords << "<br>\n";
    summary << "            <strong>Edge Passwords:</strong> " << data.stats.edgePasswords << "<br>\n";
    summary << "            <strong>WiFi Passwords:</strong> " << data.stats.wifiPasswords << "<br>\n";
    summary << "            <strong>Extraction Method:</strong> Registry DPAPI + TrustedInstaller<br>\n";
    summary << "            <strong>Tool:</strong> kvc v1.0.1 - marek@wesolowski.eu.org\n";
    summary << "        </div>\n";
    
    return summary.str();
}

std::string ReportExporter::BuildMasterKeysTable(const ReportData& data) noexcept
{
    std::ostringstream table;
    
    table << "\n        <div class=\"section-title\">DPAPI Master Keys</div>\n";
    table << "        <table>\n";
    table << "            <thead>\n";
    table << "                <tr>\n";
    
    for (size_t i = 0; i < TableWidths::MASTER_KEYS.size(); ++i) {
        table << "                    <th style=\"width: " << TableWidths::MASTER_KEYS[i] << ";\">" 
              << TableWidths::MASTER_KEYS_HEADERS[i] << "</th>\n";
    }
    
    table << "                </tr>\n";
    table << "            </thead>\n";
    table << "            <tbody>";
    
    for (const auto& masterKey : data.masterKeys) {
        std::string keyType = "Unknown";
        if (masterKey.keyName.find(L"DPAPI_SYSTEM") != std::wstring::npos) {
            keyType = "DPAPI_SYSTEM";
        } else if (masterKey.keyName.find(L"NL$KM") != std::wstring::npos) {
            keyType = "NL$KM";  
        } else if (masterKey.keyName.find(L"DefaultPassword") != std::wstring::npos) {
            keyType = "DefaultPassword";
        }
        
        std::string rawHex = CryptoUtils::BytesToHex(masterKey.encryptedData, 32);
        std::string processedHex = CryptoUtils::BytesToHex(masterKey.decryptedData, 32);
        
        if (rawHex.length() > 64) {
            rawHex = rawHex.substr(0, 64) + "...";
        }
        if (processedHex.length() > 64) {
            processedHex = processedHex.substr(0, 64) + "...";
        }
        
        std::string statusClass = masterKey.isDecrypted ? "status-decrypted" : "status-extracted";
        std::string statusText = masterKey.isDecrypted ? "&#10004;" : "&#9889;";
        
        table << "                <tr class=\"masterkey\">\n";
        table << "                    <td><strong>" << keyType << "</strong></td>\n";
        table << "                    <td class=\"hex-data\">" << rawHex << "</td>\n";
        table << "                    <td class=\"hex-data\">" << processedHex << "</td>\n";
        table << "                    <td class=\"" << statusClass << "\">" << statusText << "</td>\n";
        table << "                </tr>\n\n";
    }
    
    table << "            </tbody>\n        </table>\n";
    return table.str();
}

std::string ReportExporter::BuildPasswordsTable(const ReportData& data) noexcept
{
    std::ostringstream table;
    
    table << "\n        <div class=\"section-title\">Browser Passwords</div>\n";
    table << "        <table>\n";
    table << "            <thead>\n";
    table << "                <tr>\n";
    
    for (size_t i = 0; i < TableWidths::PASSWORDS.size(); ++i) {
        table << "                    <th style=\"width: " << TableWidths::PASSWORDS[i] << ";\">" 
              << TableWidths::PASSWORDS_HEADERS[i] << "</th>\n";
    }
    
    table << "                </tr>\n";
    table << "            </thead>\n";
    table << "            <tbody>";
    
    for (const auto& result : data.passwordResults) {
        if (result.type.find(L"Chrome") != std::wstring::npos || 
            result.type.find(L"Edge") != std::wstring::npos) {
            
            std::string cssClass = result.type.find(L"Chrome") != std::wstring::npos ? "chrome" : "edge";
            
            table << "                <tr class=\"" << cssClass << "\">\n";
            table << "                    <td>" << StringUtils::WideToUTF8(result.type) << "</td>\n";
            table << "                    <td>" << StringUtils::WideToUTF8(result.profile) << "</td>\n";
            table << "                    <td>" << StringUtils::WideToUTF8(result.url) << "</td>\n";
            table << "                    <td>" << StringUtils::WideToUTF8(result.username) << "</td>\n";
            table << "                    <td class=\"password\">" << StringUtils::WideToUTF8(result.password) << "</td>\n";
            table << "                    <td class=\"status-decrypted\">" << StringUtils::WideToUTF8(result.status) << "</td>\n";
            table << "                </tr>\n";
        }
    }
    
    table << "            </tbody>\n        </table>\n";
    return table.str();
}

std::string ReportExporter::BuildWiFiTable(const ReportData& data) noexcept
{
    std::ostringstream table;
    
    table << "\n        <div class=\"section-title\">WiFi Credentials</div>\n";
    table << "        <table>\n";
    table << "            <thead>\n";
    table << "                <tr>\n";
    
    for (size_t i = 0; i < TableWidths::WIFI.size(); ++i) {
        table << "                    <th style=\"width: " << TableWidths::WIFI[i] << ";\">" 
              << TableWidths::WIFI_HEADERS[i] << "</th>\n";
    }
    
    table << "                </tr>\n";
    table << "            </thead>\n";
    table << "            <tbody>";
    
    for (const auto& result : data.passwordResults) {
        if (result.type.find(L"WiFi") != std::wstring::npos) {
            table << "                <tr class=\"wifi\">\n";
            table << "                    <td>" << StringUtils::WideToUTF8(result.profile) << "</td>\n";
            table << "                    <td class=\"password\">" << StringUtils::WideToUTF8(result.password) << "</td>\n";
            table << "                    <td>" << StringUtils::WideToUTF8(result.type) << "</td>\n";
            table << "                    <td class=\"status-decrypted\">" << StringUtils::WideToUTF8(result.status) << "</td>\n";
            table << "                </tr>\n";
        }
    }
    
    table << "            </tbody>\n        </table>\n";
    return table.str();
}

std::wstring ReportExporter::GenerateTXTContent(const ReportData& data) noexcept
{
    std::wostringstream txt;
    
    txt << BuildTXTHeader(data);
    txt << BuildTXTMasterKeys(data);
    txt << BuildTXTPasswords(data);
    txt << BuildTXTWiFi(data);
    
    return txt.str();
}

std::wstring ReportExporter::BuildTXTHeader(const ReportData& data) noexcept
{
    std::wostringstream header;
    
    header << L"=== kvc DPAPI EXTRACTION RESULTS ===\n";
    header << L"Generated: " << std::wstring(data.timestamp.begin(), data.timestamp.end()) << L"\n";
    header << L"Registry Master Keys: " << data.stats.masterKeyCount << L"\n";
    header << L"Total Passwords: " << data.stats.totalPasswords << L"\n";
    header << L"Tool: kvc v1.0.1 - Kernel Vulnerability Capabilities Framework by WESMAR\n";
    header << L"=================================\n\n";
    
    return header.str();
}

std::wstring ReportExporter::BuildTXTMasterKeys(const ReportData& data) noexcept
{
    std::wostringstream section;
    
    section << L"=== REGISTRY MASTER KEYS ===\n";
    for (const auto& masterKey : data.masterKeys) {
        section << L"Key: " << masterKey.keyName << L"\n";
        section << L"Size: " << masterKey.encryptedData.size() << L" bytes\n";
        section << L"Status: " << (masterKey.isDecrypted ? L"DECRYPTED" : L"EXTRACTED") << L"\n";
        section << L"---------------------------------\n";
    }
    section << L"\n";
    
    return section.str();
}

std::wstring ReportExporter::BuildTXTPasswords(const ReportData& data) noexcept
{
    std::wostringstream section;
    
    section << L"=== BROWSER PASSWORDS ===\n";
    for (const auto& result : data.passwordResults) {
        if (result.type.find(L"Chrome") != std::wstring::npos || 
            result.type.find(L"Edge") != std::wstring::npos) {
            section << L"Browser: " << result.type << L"\n";
            section << L"Profile: " << result.profile << L"\n";
            section << L"URL: " << result.url << L"\n";
            section << L"Username: " << result.username << L"\n";
            section << L"Password: " << result.password << L"\n";
            section << L"Status: " << result.status << L"\n";
            section << L"---------------------------------\n";
        }
    }
    section << L"\n";
    
    return section.str();
}

std::wstring ReportExporter::BuildTXTWiFi(const ReportData& data) noexcept
{
    std::wostringstream section;
    
    section << L"=== WIFI CREDENTIALS ===\n";
    for (const auto& result : data.passwordResults) {
        if (result.type.find(L"WiFi") != std::wstring::npos) {
            section << L"Network: " << result.profile << L"\n";
            section << L"Password: " << result.password << L"\n";
            section << L"Status: " << result.status << L"\n";
            section << L"---------------------------------\n";
        }
    }
    section << L"\n";
    
    return section.str();
}

std::wstring ReportExporter::GetHTMLPath(const std::wstring& outputPath) noexcept
{
    return outputPath + L"\\dpapi_results.html";
}

std::wstring ReportExporter::GetTXTPath(const std::wstring& outputPath) noexcept
{
    return outputPath + L"\\dpapi_results.txt";
}

bool ReportExporter::EnsureOutputDirectory(const std::wstring& path) noexcept
{
    if (!fs::exists(path)) {
        try {
            fs::create_directories(path);
            return true;
        } catch (...) {
            return false;
        }
    }
    return true;
}
