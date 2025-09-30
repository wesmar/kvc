// OrchestratorCore.h - Main orchestration logic and configuration management
#ifndef ORCHESTRATOR_CORE_H
#define ORCHESTRATOR_CORE_H

#include <Windows.h>
#include <filesystem>
#include <optional>
#include <string>
#include "CommunicationLayer.h"
#include "EdgeDPAPI.h"

namespace fs = std::filesystem;

// Application configuration parsed from command-line arguments
struct Configuration
{
    bool verbose = false;
    fs::path outputPath;
    std::wstring browserType;
    std::wstring browserProcessName;
    std::wstring browserDefaultExePath;
    std::string browserDisplayName;

    // Parses command line arguments and builds configuration
    static std::optional<Configuration> CreateFromArgs(int argc, wchar_t* argv[], const Console& console);
};

// Executes the complete browser analysis workflow
PipeCommunicator::ExtractionStats RunInjectionWorkflow(const Configuration& config, const Console& console);

// Processes all installed browsers in batch mode
void ProcessAllBrowsers(const Console& console, bool verbose, const fs::path& outputPath);

// Displays final extraction summary for a single browser
void DisplayExtractionSummary(const std::string& browserName, const PipeCommunicator::ExtractionStats& stats,
                              const Console& console, bool singleBrowser, const fs::path& outputPath);

// Builds a human-readable summary string from extraction statistics
std::string BuildExtractionSummary(const PipeCommunicator::ExtractionStats& stats);

#endif // ORCHESTRATOR_CORE_H