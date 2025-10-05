/**
 * @file ReportExporter.h
 * @brief Professional report generation for DPAPI password extraction results
 * @author Marek Wesolowski
 * @date 2025
 * @copyright KVC Framework
 * 
 * Exports extraction results in multiple formats (HTML, TXT) with automatic
 * statistics calculation and modern styling.
 * Provides comprehensive reporting for credential extraction operations.
 */

#pragma once

#include "common.h"
#include <vector>
#include <string>

// Forward declarations
struct PasswordResult;
struct RegistryMasterKey;

/**
 * @struct ReportData
 * @brief Report data aggregation with automatic statistics
 * 
 * Aggregates all extraction results and calculates statistics automatically
 * upon construction. Provides convenient access to categorized data.
 * Used as input for report generation in multiple formats.
 */
struct ReportData
{
    std::vector<PasswordResult> passwordResults;    ///< All password extraction results
    std::vector<RegistryMasterKey> masterKeys;      ///< Registry master keys extracted
    std::wstring outputPath;                        ///< Output directory path for reports
    std::string timestamp;                          ///< Generation timestamp
    
    /**
     * @struct Stats
     * @brief Automatically calculated extraction statistics
     * 
     * Contains counts and metrics for different credential types
     * extracted during DPAPI operations.
     */
    struct Stats {
        int totalPasswords = 0;     ///< Total passwords extracted
        int chromePasswords = 0;    ///< Chrome browser passwords
        int edgePasswords = 0;      ///< Edge browser passwords
        int wifiPasswords = 0;      ///< WiFi credentials
        int masterKeyCount = 0;     ///< Master keys extracted
    } stats;
    
    /**
     * @brief Default constructor
     * 
     * Creates empty report data structure. Statistics will be
     * zero-initialized.
     */
    ReportData() = default;
    
    /**
     * @brief Construct report data with automatic statistics calculation
     * @param results Password extraction results
     * @param keys Registry master keys
     * @param path Output directory path
     * 
     * Initializes report data with extraction results and automatically
     * calculates statistics by calling CalculateStatistics().
     */
    ReportData(const std::vector<PasswordResult>& results, 
               const std::vector<RegistryMasterKey>& keys,
               const std::wstring& path);
    
private:
    /**
     * @brief Calculate statistics from results
     * 
     * Analyzes password results and master keys to populate
     * statistics structure. Called automatically by constructor.
     * 
     * @note Private method called automatically on construction
     */
    void CalculateStatistics();
};

/**
 * @class ReportExporter
 * @brief Professional report export in multiple formats
 * 
 * Features:
 * - HTML export with modern CSS styling and responsive design
 * - TXT export for lightweight text-based reports
 * - Automatic statistics calculation and display
 * - Color-coded categorization (Chrome, Edge, WiFi)
 * - UTF-8 encoding support
 * - Professional formatting and layout
 * 
 * Report Types:
 * - HTML: Interactive web-based report with styling
 * - TXT: Plain text report for quick viewing
 * - Console: Summary display with color coding
 * 
 * @note Creates timestamped reports in specified output directory
 */
class ReportExporter
{
public:
    ReportExporter() = default;         ///< Default constructor
    ~ReportExporter() = default;        ///< Default destructor
    
    // Disable copy semantics
    ReportExporter(const ReportExporter&) = delete;                    ///< Copy constructor deleted
    ReportExporter& operator=(const ReportExporter&) = delete;        ///< Copy assignment deleted
    
    // Enable move semantics
    ReportExporter(ReportExporter&&) noexcept = default;              ///< Move constructor
    ReportExporter& operator=(ReportExporter&&) noexcept = default;   ///< Move assignment

    /**
     * @brief Export reports in all supported formats
     * @param data Report data with extraction results
     * @return true if all formats exported successfully
     * 
     * Creates both HTML and TXT reports in the output directory.
     * Also displays summary statistics to console.
     * 
     * Files created:
     * - dpapi_results.html: HTML report with full styling
     * - dpapi_results.txt: Plain text report
     * 
     * @note Comprehensive reporting across all formats
     */
    bool ExportAllFormats(const ReportData& data) noexcept;
    
    /**
     * @brief Export HTML report with modern styling
     * @param data Report data with extraction results
     * @return true if HTML export successful
     * 
     * Generates professional HTML report with:
     * - Responsive CSS styling
     * - Color-coded sections
     * - Interactive elements
     * - Statistics dashboard
     * - Master keys table
     * - Passwords table (collapsible)
     * - WiFi credentials section
     * 
     * @note Creates dpapi_results.html in output directory
     */
    bool ExportHTML(const ReportData& data) noexcept;
    
    /**
     * @brief Export plain text report
     * @param data Report data with extraction results
     * @return true if TXT export successful
     * 
     * Generates lightweight text report with:
     * - Simple column-based formatting
     * - Basic statistics
     * - Master keys listing
     * - Passwords in readable format
     * - WiFi credentials section
     * 
     * @note Creates dpapi_results.txt in output directory
     */
    bool ExportTXT(const ReportData& data) noexcept;
    
    /**
     * @brief Display summary statistics to console
     * @param data Report data with extraction results
     * 
     * Prints color-coded summary to console with:
     * - Total extraction statistics
     * - File paths for generated reports
     * - Success/failure indicators
     * - Quick overview of results
     * 
     * @note Useful for immediate feedback after extraction
     */
    void DisplaySummary(const ReportData& data) noexcept;

private:
    // === HTML Generation Methods ===
    
    /**
     * @brief Generate complete HTML content
     * @param data Report data for generation
     * @return std::string HTML content as string
     * 
     * Builds complete HTML document by combining:
     * - HTML header with CSS styling
     * - Summary section with statistics
     * - Master keys table
     * - Passwords table
     * - WiFi credentials table
     * 
     * @note Internal HTML generation implementation
     */
    std::string GenerateHTMLContent(const ReportData& data) noexcept;
    
    /**
     * @brief Build HTML header section
     * @param data Report data for header
     * @return std::string HTML header content
     * 
     * Creates HTML head section with:
     * - Page title and metadata
     * - CSS styles for responsive design
     * - JavaScript for interactivity
     * - Character encoding
     * 
     * @note Includes modern CSS framework for styling
     */
    std::string BuildHTMLHeader(const ReportData& data) noexcept;
    
    /**
     * @brief Build summary section with statistics
     * @param data Report data for statistics
     * @return std::string HTML summary section
     * 
     * Creates statistics dashboard with:
     * - Total passwords count
     * - Browser-specific counts
     * - WiFi credentials count
     * - Master keys count
     * - Visual progress bars
     * 
     * @note Color-coded statistics display
     */
    std::string BuildSummarySection(const ReportData& data) noexcept;
    
    /**
     * @brief Build master keys table
     * @param data Report data with master keys
     * @return std::string HTML table content
     * 
     * Creates table displaying:
     * - Registry key names
     * - Key data (hex encoded)
     * - Decryption status
     * - Data sizes
     * 
     * @note Technical details for master keys
     */
    std::string BuildMasterKeysTable(const ReportData& data) noexcept;
    
    /**
     * @brief Build passwords table
     * @param data Report data with passwords
     * @return std::string HTML table content
     * 
     * Creates interactive table displaying:
     * - Browser type and profile
     * - URLs and usernames
     * - Decrypted passwords
     * - Extraction status
     * - Source files
     * 
     * @note Collapsible sections for large datasets
     */
    std::string BuildPasswordsTable(const ReportData& data) noexcept;
    
    /**
     * @brief Build WiFi credentials table
     * @param data Report data with WiFi credentials
     * @return std::string HTML table content
     * 
     * Creates table displaying:
     * - WiFi profile names
     * - Network SSIDs
     * - Security keys
     * - Connection status
     * 
     * @note Separate section for wireless credentials
     */
    std::string BuildWiFiTable(const ReportData& data) noexcept;
    
    // === TXT Generation Methods ===
    
    /**
     * @brief Generate complete TXT content
     * @param data Report data for generation
     * @return std::wstring TXT content as wide string
     * 
     * Builds plain text report with:
     * - Header with timestamp
     * - Statistics summary
     * - Master keys listing
     * - Passwords in columns
     * - WiFi credentials
     * 
     * @note Internal TXT generation implementation
     */
    std::wstring GenerateTXTContent(const ReportData& data) noexcept;
    
    /**
     * @brief Build TXT header section
     * @param data Report data for header
     * @return std::wstring TXT header content
     * 
     * Creates text header with:
     * - Report title
     * - Generation timestamp
     * - Separation lines
     * - Basic information
     * 
     * @note Simple formatting for text output
     */
    std::wstring BuildTXTHeader(const ReportData& data) noexcept;
    
    /**
     * @brief Build TXT master keys section
     * @param data Report data with master keys
     * @return std::wstring TXT master keys content
     * 
     * Lists master keys in text format:
     * - Key names and paths
     * - Hex-encoded data (truncated)
     * - Decryption status
     * - Size information
     * 
     * @note Technical details in readable format
     */
    std::wstring BuildTXTMasterKeys(const ReportData& data) noexcept;
    
    /**
     * @brief Build TXT passwords section
     * @param data Report data with passwords
     * @return std::wstring TXT passwords content
     * 
     * Displays passwords in column format:
     * - Browser and profile
     * - URL and username
     * - Password (plaintext)
     * - Status indicator
     * 
     * @note Aligned columns for readability
     */
    std::wstring BuildTXTPasswords(const ReportData& data) noexcept;
    
    /**
     * @brief Build TXT WiFi credentials section
     * @param data Report data with WiFi credentials
     * @return std::wstring TXT WiFi content
     * 
     * Lists WiFi credentials:
     * - Profile names
     * - Network information
     * - Security keys
     * - Connection details
     * 
     * @note Separate section for wireless networks
     */
    std::wstring BuildTXTWiFi(const ReportData& data) noexcept;
    
    // === Utility Functions ===
    
    /**
     * @brief Get HTML report file path
     * @param outputPath Base output directory
     * @return std::wstring Full HTML file path
     * 
     * Constructs complete path for HTML report file.
     * Format: {outputPath}\dpapi_results.html
     */
    std::wstring GetHTMLPath(const std::wstring& outputPath) noexcept;
    
    /**
     * @brief Get TXT report file path
     * @param outputPath Base output directory
     * @return std::wstring Full TXT file path
     * 
     * Constructs complete path for TXT report file.
     * Format: {outputPath}\dpapi_results.txt
     */
    std::wstring GetTXTPath(const std::wstring& outputPath) noexcept;
    
    /**
     * @brief Ensure output directory exists
     * @param path Directory path to validate
     * @return bool true if directory exists or was created
     * 
     * Validates that output directory exists and is writable.
     * Creates directory structure if missing.
     * 
     * @note Essential for successful report generation
     */
    bool EnsureOutputDirectory(const std::wstring& path) noexcept;
};