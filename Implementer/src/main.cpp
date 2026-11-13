#include <windows.h>

#include "core.h"
#include "config.h"

namespace {

using impl::U32;

constexpr wchar_t kAppName[] = L"implementer";
constexpr wchar_t kVersion[] = L"0.1.0";

class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept
        : m_handle(handle) {}

    ~UniqueHandle() noexcept {
        Reset();
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept
        : m_handle(other.Release()) {}

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }

    HANDLE Get() const noexcept { return m_handle; }
    explicit operator bool() const noexcept {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }

    void Reset(HANDLE handle = INVALID_HANDLE_VALUE) noexcept {
        if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
        m_handle = handle;
    }

    HANDLE Release() noexcept {
        HANDLE handle = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return handle;
    }

private:
    HANDLE m_handle;
};

class HeapBlock {
public:
    explicit HeapBlock(SIZE_T size) noexcept
        : m_memory(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)) {}

    ~HeapBlock() noexcept {
        if (m_memory) HeapFree(GetProcessHeap(), 0, m_memory);
    }

    HeapBlock(const HeapBlock&) = delete;
    HeapBlock& operator=(const HeapBlock&) = delete;

    void* Get() const noexcept { return m_memory; }
    explicit operator bool() const noexcept { return m_memory != nullptr; }

private:
    void* m_memory;
};

struct TextBuffer {
    static constexpr size_t Capacity = 384;
    wchar_t data[Capacity]{};
    size_t length = 0;

    void Append(const wchar_t* text) noexcept {
        if (!text) return;
        while (*text && length + 1 < Capacity) {
            data[length++] = *text++;
        }
        data[length] = L'\0';
    }

    void AppendUnsigned(unsigned long long value) noexcept {
        wchar_t digits[32]{};
        size_t count = 0;
        do {
            digits[count++] = static_cast<wchar_t>(L'0' + (value % 10));
            value /= 10;
        } while (value != 0 && count < static_cast<size_t>(32));

        while (count > 0 && length + 1 < Capacity) {
            data[length++] = digits[--count];
        }
        data[length] = L'\0';
    }
};

bool EqualsIgnoreCase(const wchar_t* left, const wchar_t* right) noexcept {
    if (!left || !right) return left == right;
    return CompareStringOrdinal(left, -1, right, -1, TRUE) == CSTR_EQUAL;
}

bool IsSeparator(wchar_t value) noexcept {
    return value == L'\\' || value == L'/';
}

void AppendPath(TextBuffer& buffer, const wchar_t* directory, const wchar_t* leaf) noexcept {
    buffer.Append(directory);
    if (buffer.length > 0 && !IsSeparator(buffer.data[buffer.length - 1])) {
        buffer.Append(L"\\");
    }
    buffer.Append(leaf);
}

bool WriteConsoleText(const wchar_t* text) noexcept {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output == nullptr || output == INVALID_HANDLE_VALUE) return false;

    if (GetFileType(output) == FILE_TYPE_CHAR) {
        const size_t length = lstrlenW(text);
        DWORD written = 0;
        return WriteConsoleW(
            output,
            text,
            static_cast<DWORD>(length),
            &written,
            nullptr
        ) != FALSE;
    }

    const int bytes = WideCharToMultiByte(
        CP_UTF8,
        0,
        text,
        -1,
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (bytes <= 1) return false;

    char* utf8 = static_cast<char*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<SIZE_T>(bytes))
    );
    if (!utf8) return false;

    const bool converted = WideCharToMultiByte(
        CP_UTF8,
        0,
        text,
        -1,
        utf8,
        bytes,
        nullptr,
        nullptr
    ) > 0;
    DWORD written = 0;
    const bool ok = converted && WriteFile(
        output,
        utf8,
        static_cast<DWORD>(bytes - 1),
        &written,
        nullptr
    ) != FALSE;

    HeapFree(GetProcessHeap(), 0, utf8);
    return ok;
}

void PrintLine(const wchar_t* text) noexcept {
    TextBuffer line;
    line.Append(text);
    line.Append(L"\r\n");
    (void)WriteConsoleText(line.data);
}

int PrintUsage() noexcept {
    TextBuffer heading;
    heading.Append(kAppName);
    heading.Append(L" ");
    heading.Append(kVersion);
    PrintLine(heading.data);
    PrintLine(L"");
    PrintLine(L"Usage:");
    PrintLine(L"  implementer.exe pack <input-dir> <output.bmp> <entry-name> [options]");
    PrintLine(L"  implementer.exe pack --config <file.ini>");
    PrintLine(L"  implementer.exe inspect <input.bmp> [--config <file.ini>]");
    PrintLine(L"  implementer.exe extract <input.bmp> <output-dir> [--config <file.ini>]");
    PrintLine(L"  implementer.exe --self-test");
    PrintLine(L"");
    PrintLine(L"Pack options:");
    PrintLine(L"  --strip-pe             Strip 0x80-byte DOS headers from PE files (default)");
    PrintLine(L"  --no-strip             Store every input file byte-for-byte");
    PrintLine(L"  --template <path>      DOS-header template (default: System32\\drivers\\ks.sys)");
    PrintLine(L"  --keep-temp            Keep temporary payload and CAB files");
    PrintLine(L"  --config <file.ini>    Use ordered [Files], XOR mode, and XOR key from INI");
    PrintLine(L"");
    PrintLine(L"Extract options:");
    PrintLine(L"  --config <file.ini>    Required for full-cab XOR; also supplies template");
    PrintLine(L"  --template <path>      DOS-header template used for PE reconstruction");
    PrintLine(L"");
    PrintLine(L"Input files are sorted case-insensitively and concatenated in that order.");
    PrintLine(L"Every PE stores its original e_lfanew; non-PE files are stored intact.");
    PrintLine(L"");
    PrintLine(L"Build modes:");
    PrintLine(L"  Static   /MT, no Visual C++ redistributable");
    PrintLine(L"  Dynamic  /MD, uses the Visual C++ runtime");
    PrintLine(L"  None     no CRT, custom entry point, no STL");
    return 0;
}

int PrintVersion() noexcept {
    TextBuffer text;
    text.Append(kAppName);
    text.Append(L" ");
    text.Append(kVersion);
    text.Append(L" (C++23)");
    PrintLine(text.data);
    return 0;
}

int PrintError(const wchar_t* operation, DWORD error) noexcept {
    TextBuffer message;
    message.Append(L"FAIL: ");
    message.Append(operation);
    if (error != ERROR_SUCCESS) {
        message.Append(L" (Win32 ");
        message.AppendUnsigned(error);
        message.Append(L")");
    }
    PrintLine(message.data);
    return 1;
}

void AppendSha256(TextBuffer& text, const BYTE digest[32]) noexcept {
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    for (SIZE_T index = 0; index < 32; ++index) {
        wchar_t pair[3]{
            digits[digest[index] >> 4],
            digits[digest[index] & 0x0F],
            L'\0'
        };
        text.Append(pair);
    }
}

void AppendFixed2(TextBuffer& text, double value) noexcept {
    if (value < 0.0) {
        text.Append(L"-");
        value = -value;
    }
    const unsigned whole = static_cast<unsigned>(value);
    const unsigned fraction = static_cast<unsigned>((value - whole) * 100.0 + 0.5);
    text.AppendUnsigned(whole);
    text.Append(L".");
    if (fraction < 10) text.Append(L"0");
    text.AppendUnsigned(fraction);
}

bool WideToAnsi(const wchar_t* input, char* output, SIZE_T capacity) noexcept {
    if (!input || !output || capacity == 0) return false;
    const int result = WideCharToMultiByte(
        CP_ACP,
        WC_NO_BEST_FIT_CHARS,
        input,
        -1,
        output,
        static_cast<int>(capacity),
        nullptr,
        nullptr
    );
    return result > 0;
}

int ExecutePack(
    const impl::PackOptions& options,
    const wchar_t* inputDirectory,
    const wchar_t* outputPath,
    const wchar_t* entryNameWide,
    bool keepTemp
) noexcept {
    struct PackState {
        wchar_t payloadPath[MAX_PATH];
        wchar_t cabPath[MAX_PATH];
        wchar_t tempDirectory[MAX_PATH];
        char entryName[MAX_PATH];
    };
    HeapBlock stateMemory(sizeof(PackState));
    if (!stateMemory) return PrintError(L"cannot allocate pack state", ERROR_NOT_ENOUGH_MEMORY);
    auto* state = static_cast<PackState*>(stateMemory.Get());

    if (!impl::EndsWithNoCase(outputPath, L".bmp")) {
        return PrintError(L"output name must end with .bmp", 0);
    }

    if (!WideToAnsi(entryNameWide, state->entryName, MAX_PATH)) {
        return PrintError(L"entry name is not representable in ANSI", GetLastError());
    }

    impl::Buffer payload;
    U32 fileCount = 0;
    const bool built = options.files
        ? impl::BuildContainerFromFiles(options, payload, fileCount)
        : impl::BuildContainer(inputDirectory, options, payload, fileCount);
    if (!built) {
        return PrintError(L"cannot build payload container", GetLastError());
    }

    const DWORD tempLength = GetTempPathW(
        static_cast<DWORD>(
            sizeof(state->tempDirectory) / sizeof(state->tempDirectory[0])
        ),
        state->tempDirectory
    );
    if (tempLength == 0
        || tempLength >= sizeof(state->tempDirectory) / sizeof(state->tempDirectory[0])) {
        return PrintError(L"GetTempPathW", GetLastError());
    }

    if (!impl::WriteTemporaryFile(
            state->tempDirectory,
            L"imp",
            payload,
            state->payloadPath,
            static_cast<SIZE_T>(
                sizeof(state->payloadPath) / sizeof(state->payloadPath[0])
            )
        )) {
        return PrintError(L"cannot write temporary payload", GetLastError());
    }

    if (GetTempFileNameW(
            state->tempDirectory,
            L"imp",
            0,
            state->cabPath
        ) == 0) {
        DeleteFileW(state->payloadPath);
        return PrintError(L"GetTempFileNameW", GetLastError());
    }

    impl::Buffer cab;
    impl::Buffer bitmap;
    const bool cabCreated = impl::CreateCab(
        state->cabPath,
        state->payloadPath,
        state->entryName,
        cab
    );

    if (!cabCreated) {
        const DWORD error = GetLastError();
        if (!keepTemp) {
            DeleteFileW(state->payloadPath);
            DeleteFileW(state->cabPath);
        }
        return PrintError(L"CAB creation failed", error);
    }

    if (!impl::ApplyCabXor(
            cab,
            options.xorMode,
            options.xorKey,
            options.xorKeyLength
        )) {
        if (!keepTemp) {
            DeleteFileW(state->payloadPath);
            DeleteFileW(state->cabPath);
        }
        return PrintError(L"CAB XOR failed", GetLastError());
    }

    if (cab.size < 4) {
        TextBuffer diagnostic;
        diagnostic.Append(L"CAB output is empty: ");
        diagnostic.Append(state->cabPath);
        PrintLine(diagnostic.data);
        if (!keepTemp) {
            DeleteFileW(state->payloadPath);
            DeleteFileW(state->cabPath);
        }
        return 1;
    }

    if (!impl::WrapCabInBitmap(cab.data, cab.size, bitmap)) {
        if (!keepTemp) {
            DeleteFileW(state->payloadPath);
            DeleteFileW(state->cabPath);
        }
        return PrintError(L"BMP wrapping failed", GetLastError());
    }

    if (!impl::WriteFileFromBuffer(outputPath, bitmap.data, bitmap.size)) {
        const DWORD error = GetLastError();
        if (!keepTemp) {
            DeleteFileW(state->payloadPath);
            DeleteFileW(state->cabPath);
        }
        return PrintError(L"output write failed", error);
    }

    if (!keepTemp) {
        DeleteFileW(state->payloadPath);
        DeleteFileW(state->cabPath);
    }

    const BYTE* pixels = bitmap.data + 54;
    const SIZE_T pixelBytes = bitmap.size - 54;

    TextBuffer summary;
    summary.Append(L"Packed files: ");
    summary.AppendUnsigned(fileCount);
    summary.Append(L", payload: ");
    summary.AppendUnsigned(payload.size);
    summary.Append(L" bytes, CAB: ");
    summary.AppendUnsigned(cab.size);
    summary.Append(L" bytes, BMP: ");
    summary.AppendUnsigned(bitmap.size);
    summary.Append(L" bytes, entropy: ");
    AppendFixed2(summary, impl::CalculateEntropy(pixels, pixelBytes));
    summary.Append(L"/8, entry: ");
    summary.Append(entryNameWide);
    summary.Append(options.stripPe ? L", PE headers stripped" : L", raw storage");
    if (options.xorMode == impl::XorMode::FullCab) {
        summary.Append(L", XOR full-cab");
    } else if (options.xorMode == impl::XorMode::MaskMagic) {
        summary.Append(L", XOR mask-magic");
    } else {
        summary.Append(L", XOR none");
    }
    PrintLine(summary.data);
    if (keepTemp) {
        summary = TextBuffer{};
        summary.Append(L"Temporary payload: ");
        summary.Append(state->payloadPath);
        PrintLine(summary.data);
        summary = TextBuffer{};
        summary.Append(L"Temporary CAB: ");
        summary.Append(state->cabPath);
        PrintLine(summary.data);
    }
    return 0;
}

int PackCommand(int argc, wchar_t** argv) noexcept {
    if (argc < 3) {
        return PrintError(L"pack expects <input-dir> <output.bmp> <entry-name> or --config <file.ini>", 0);
    }

    if (EqualsIgnoreCase(argv[2], L"--config") || argc == 3) {
        const wchar_t* configPath = EqualsIgnoreCase(argv[2], L"--config")
            ? (argc >= 4 ? argv[3] : nullptr)
            : argv[2];
        if (!configPath) return PrintError(L"--config requires a path", 0);

        HeapBlock configMemory(sizeof(impl::PackConfig));
        if (!configMemory) {
            return PrintError(L"cannot allocate pack config", ERROR_NOT_ENOUGH_MEMORY);
        }
        auto* config = static_cast<impl::PackConfig*>(configMemory.Get());
        if (!impl::LoadPackConfig(configPath, *config)) {
            TextBuffer error;
            error.Append(L"cannot load config");
            if (config->errorLine != 0) {
                error.Append(L" at line ");
                error.AppendUnsigned(config->errorLine);
            }
            if (config->error[0]) {
                error.Append(L": ");
                error.Append(config->error);
            }
            PrintLine(error.data);
            return 1;
        }

        const impl::PackOptions options{
            config->templatePath,
            config->stripPe,
            false,
            config->files,
            config->fileCount,
            config->xorMode,
            config->xorKey,
            config->xorKeyLength
        };
        return ExecutePack(
            options,
            nullptr,
            config->outputPath,
            config->entryName,
            false
        );
    }

    if (argc < 5) {
        return PrintError(L"pack expects <input-dir> <output.bmp> <entry-name>", 0);
    }

    const wchar_t* inputDirectory = argv[2];
    const wchar_t* outputPath = argv[3];
    const wchar_t* entryNameWide = argv[4];
    bool stripPe = true;
    bool keepTemp = false;
    wchar_t templatePath[MAX_PATH]{};
    wchar_t systemDirectory[MAX_PATH]{};
    const UINT systemLength = GetSystemDirectoryW(
        systemDirectory,
        static_cast<UINT>(sizeof(systemDirectory) / sizeof(systemDirectory[0]))
    );
    if (systemLength == 0
        || systemLength >= sizeof(systemDirectory) / sizeof(systemDirectory[0])
        || !impl::JoinPath(
            templatePath,
            sizeof(templatePath) / sizeof(templatePath[0]),
            systemDirectory,
            L"drivers\\ks.sys"
        )) {
        return PrintError(L"cannot resolve the default ks.sys path", GetLastError());
    }

    for (int index = 5; index < argc; ++index) {
        if (EqualsIgnoreCase(argv[index], L"--strip-pe")) {
            stripPe = true;
        } else if (EqualsIgnoreCase(argv[index], L"--no-strip")) {
            stripPe = false;
        } else if (EqualsIgnoreCase(argv[index], L"--keep-temp")) {
            keepTemp = true;
        } else if (EqualsIgnoreCase(argv[index], L"--template")) {
            if (index + 1 >= argc) {
                return PrintError(L"--template requires a path", 0);
            }
            impl::CopyString(
                templatePath,
                sizeof(templatePath) / sizeof(templatePath[0]),
                argv[++index]
            );
        } else {
            return PrintError(L"unknown pack option", 0);
        }
    }

    const impl::PackOptions options{
        templatePath,
        stripPe,
        true,
        nullptr,
        0,
        impl::XorMode::MaskMagic,
        nullptr,
        0
    };
    return ExecutePack(options, inputDirectory, outputPath, entryNameWide, keepTemp);
}

int InspectCommand(int argc, wchar_t** argv) noexcept {
    if (argc < 3) return PrintError(L"inspect expects <input.bmp> [--config <file.ini>]", 0);

    impl::XorMode xorMode = impl::XorMode::MaskMagic;
    const BYTE* xorKey = nullptr;
    U32 xorKeyLength = 0;
    HeapBlock configMemory(sizeof(impl::PackConfig));
    if (!configMemory) {
        return PrintError(L"cannot allocate inspect config", ERROR_NOT_ENOUGH_MEMORY);
    }
    auto* config = static_cast<impl::PackConfig*>(configMemory.Get());

    for (int index = 3; index < argc; ++index) {
        if (EqualsIgnoreCase(argv[index], L"--config") && index + 1 < argc) {
            if (!impl::LoadPackConfig(argv[++index], *config)) {
                return PrintError(L"cannot load inspect config", GetLastError());
            }
            xorMode = config->xorMode;
            xorKey = config->xorKey;
            xorKeyLength = config->xorKeyLength;
        } else {
            return PrintError(L"unknown inspect option", 0);
        }
    }

    impl::Buffer bitmap;
    impl::Buffer cab;
    impl::Buffer payload;
    if (!impl::ReadFileToBuffer(argv[2], bitmap)
        || !impl::UnwrapBitmap(bitmap.data, bitmap.size, cab)
        || !impl::UndoCabXor(cab, xorMode, xorKey, xorKeyLength)
        || !impl::ExtractCab(cab.data, cab.size, payload)) {
        return PrintError(L"cannot inspect bitmap", GetLastError());
    }

    impl::ContainerView container{};
    if (!impl::OpenContainer(payload.data, payload.size, container)) {
        return PrintError(L"invalid container manifest", 0);
    }
    if (container.header->xorMode != static_cast<U32>(xorMode)) {
        return PrintError(L"XOR mode does not match the container manifest", 0);
    }
    if (xorMode == impl::XorMode::FullCab) {
        BYTE keyHash[32]{};
        if (!xorKey
            || !impl::ComputeSha256(xorKey, xorKeyLength, keyHash)
            || !impl::Sha256Equals(keyHash, container.header->xorKeySha256)) {
            return PrintError(L"XOR key does not match the container manifest", 0);
        }
    }

    TextBuffer header;
    header.Append(L"Files: ");
    header.AppendUnsigned(container.header->count);
    header.Append(L", payload: ");
    header.AppendUnsigned(payload.size);
    header.Append(L" bytes, CAB entropy: ");
    AppendFixed2(header, impl::CalculateEntropy(cab.data, cab.size));
    header.Append(L"/8");
    PrintLine(header.data);

    for (U32 index = 0; index < container.header->count; ++index) {
        const impl::FileRecord& record = container.records[index];
        TextBuffer line;
        line.Append(L"  ");
        line.Append(record.name);
        line.Append(L"  ");
        line.AppendUnsigned(record.originalSize);
        line.Append(L" bytes");
        if ((record.flags & impl::kFileFlagDosHeaderStripped) != 0) {
            line.Append(L", stored ");
            line.AppendUnsigned(record.storedSize);
            line.Append(L", e_lfanew 0x");
            constexpr wchar_t digits[] = L"0123456789ABCDEF";
            bool started = false;
            for (int shift = 28; shift >= 0; shift -= 4) {
                const unsigned value = (record.eLfanew >> shift) & 0xFu;
                if (value != 0 || started || shift == 0) {
                    started = true;
                    wchar_t pair[2]{digits[value], L'\0'};
                    line.Append(pair);
                }
            }
            line.Append(L", DOS stripped");
        } else {
            line.Append(L", raw");
        }
        line.Append(L"  SHA-256 ");
        AppendSha256(line, record.originalSha256);
        PrintLine(line.data);
    }
    return 0;
}

int ExtractCommand(int argc, wchar_t** argv) noexcept {
    if (argc < 4) return PrintError(L"extract expects <input.bmp> <output-dir> [--config <file.ini>]", 0);

    wchar_t templatePath[MAX_PATH]{};
    impl::XorMode xorMode = impl::XorMode::MaskMagic;
    const BYTE* xorKey = nullptr;
    U32 xorKeyLength = 0;
    HeapBlock configMemory(sizeof(impl::PackConfig));
    if (!configMemory) {
        return PrintError(L"cannot allocate extract config", ERROR_NOT_ENOUGH_MEMORY);
    }
    auto* config = static_cast<impl::PackConfig*>(configMemory.Get());
    wchar_t systemDirectory[MAX_PATH]{};
    const UINT systemLength = GetSystemDirectoryW(
        systemDirectory,
        static_cast<UINT>(sizeof(systemDirectory) / sizeof(systemDirectory[0]))
    );
    if (systemLength == 0
        || systemLength >= sizeof(systemDirectory) / sizeof(systemDirectory[0])
        || !impl::JoinPath(
            templatePath,
            sizeof(templatePath) / sizeof(templatePath[0]),
            systemDirectory,
            L"drivers\\ks.sys"
        )) {
        return PrintError(L"cannot resolve the default ks.sys path", GetLastError());
    }

    for (int index = 4; index < argc; ++index) {
        if (EqualsIgnoreCase(argv[index], L"--config") && index + 1 < argc) {
            if (!impl::LoadPackConfig(argv[++index], *config)) {
                return PrintError(L"cannot load extract config", GetLastError());
            }
            xorMode = config->xorMode;
            xorKey = config->xorKey;
            xorKeyLength = config->xorKeyLength;
            if (config->templatePath[0]) {
                impl::CopyString(
                    templatePath,
                    sizeof(templatePath) / sizeof(templatePath[0]),
                    config->templatePath
                );
            }
        } else if (EqualsIgnoreCase(argv[index], L"--template")) {
            if (index + 1 >= argc) {
                return PrintError(L"--template requires a path", 0);
            }
            impl::CopyString(
                templatePath,
                sizeof(templatePath) / sizeof(templatePath[0]),
                argv[++index]
            );
        } else {
            return PrintError(L"unknown extract option", 0);
        }
    }

    impl::Buffer bitmap;
    impl::Buffer cab;
    impl::Buffer payload;
    if (!impl::ReadFileToBuffer(argv[2], bitmap)
        || !impl::UnwrapBitmap(bitmap.data, bitmap.size, cab)
        || !impl::UndoCabXor(cab, xorMode, xorKey, xorKeyLength)
        || !impl::ExtractCab(cab.data, cab.size, payload)) {
        return PrintError(L"cannot extract bitmap payload", GetLastError());
    }

    impl::ContainerView container{};
    if (!impl::OpenContainer(payload.data, payload.size, container)) {
        return PrintError(L"invalid container manifest", 0);
    }
    if (container.header->xorMode != static_cast<U32>(xorMode)) {
        return PrintError(L"XOR mode does not match the container manifest", 0);
    }
    if (xorMode == impl::XorMode::FullCab) {
        BYTE keyHash[32]{};
        if (!xorKey
            || !impl::ComputeSha256(xorKey, xorKeyLength, keyHash)
            || !impl::Sha256Equals(keyHash, container.header->xorKeySha256)) {
            return PrintError(L"XOR key does not match the container manifest", 0);
        }
    }
    if (!impl::ExtractContainer(container, argv[3], templatePath)) {
        return PrintError(L"container extraction or hash verification failed", GetLastError());
    }

    TextBuffer message;
    message.Append(L"Extracted ");
    message.AppendUnsigned(container.header->count);
    message.Append(L" files to ");
    message.Append(argv[3]);
    PrintLine(message.data);
    return 0;
}

int SelfTest() noexcept {
    wchar_t systemDirectory[MAX_PATH]{};
    const UINT length = GetSystemDirectoryW(
        systemDirectory,
        static_cast<UINT>(sizeof(systemDirectory) / sizeof(systemDirectory[0]))
    );
    if (length == 0 || length >= sizeof(systemDirectory) / sizeof(systemDirectory[0])) {
        PrintLine(L"FAIL: GetSystemDirectoryW");
        return 1;
    }

    TextBuffer path;
    AppendPath(path, systemDirectory, L"drivers\\ks.sys");

    UniqueHandle file(CreateFileW(
        path.data,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));
    if (!file) {
        TextBuffer message;
        message.Append(L"FAIL: cannot open ");
        message.Append(path.data);
        message.Append(L" (Win32 ");
        message.AppendUnsigned(GetLastError());
        message.Append(L")");
        PrintLine(message.data);
        return 1;
    }

    BYTE header[128]{};
    DWORD read = 0;
    if (!ReadFile(file.Get(), header, sizeof(header), &read, nullptr)
        || read != sizeof(header)) {
        PrintLine(L"FAIL: cannot read the 128-byte DOS header template");
        return 1;
    }
    if (header[0] != 'M' || header[1] != 'Z') {
        PrintLine(L"FAIL: ks.sys does not begin with MZ");
        return 1;
    }

    const DWORD peOffset =
        static_cast<DWORD>(header[0x3C])
        | (static_cast<DWORD>(header[0x3D]) << 8)
        | (static_cast<DWORD>(header[0x3E]) << 16)
        | (static_cast<DWORD>(header[0x3F]) << 24);

    TextBuffer message;
    message.Append(L"PASS: ");
    message.Append(path.data);
    message.Append(L", e_lfanew=0x");
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    bool started = false;
    for (int shift = 28; shift >= 0; shift -= 4) {
        const unsigned value = (peOffset >> shift) & 0xFu;
        if (value != 0 || started || shift == 0) {
            started = true;
            wchar_t pair[2]{digits[value], L'\0'};
            message.Append(pair);
        }
    }
    PrintLine(message.data);
    return 0;
}

int Run(int argc, wchar_t** argv) noexcept {
    if (argc <= 1) {
        return PrintUsage();
    }

    if (EqualsIgnoreCase(argv[1], L"--help")
        || EqualsIgnoreCase(argv[1], L"-h")
        || EqualsIgnoreCase(argv[1], L"help")
        || EqualsIgnoreCase(argv[1], L"/?")) {
        return PrintUsage();
    }
    if (argc > 2 && EqualsIgnoreCase(argv[2], L"--help")) {
        return PrintUsage();
    }
    if (EqualsIgnoreCase(argv[1], L"--version") || EqualsIgnoreCase(argv[1], L"-v")) {
        return PrintVersion();
    }
    if (EqualsIgnoreCase(argv[1], L"--self-test")) {
        return SelfTest();
    }
    if (EqualsIgnoreCase(argv[1], L"pack")) {
        return PackCommand(argc, argv);
    }
    if (EqualsIgnoreCase(argv[1], L"inspect")) {
        return InspectCommand(argc, argv);
    }
    if (EqualsIgnoreCase(argv[1], L"extract")) {
        return ExtractCommand(argc, argv);
    }

    PrintLine(L"Unknown argument.");
    return 2;
}

} // namespace

#ifdef IMPLEMENTER_NO_CRT

namespace {

bool IsCommandLineSpace(wchar_t value) noexcept {
    return value == L' ' || value == L'\t';
}

struct ParsedCommandLine {
    void* memory = nullptr;
    int argc = 0;
    wchar_t** argv = nullptr;
};

bool ParseCommandLine(ParsedCommandLine& parsed) noexcept {
    const wchar_t* source = GetCommandLineW();
    if (!source) return false;

    SIZE_T length = 0;
    while (source[length]) ++length;
    const SIZE_T maxArguments = length / 2 + 2;
    const SIZE_T pointerBytes = maxArguments * sizeof(wchar_t*);
    const SIZE_T characterBytes = (length + 1) * sizeof(wchar_t);
    if (pointerBytes > ~static_cast<SIZE_T>(0) - characterBytes) return false;

    parsed.memory = HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        pointerBytes + characterBytes
    );
    if (!parsed.memory) return false;

    parsed.argv = static_cast<wchar_t**>(parsed.memory);
    auto* destination = reinterpret_cast<wchar_t*>(
        static_cast<BYTE*>(parsed.memory) + pointerBytes
    );
    const wchar_t* cursor = source;

    while (*cursor) {
        while (IsCommandLineSpace(*cursor)) ++cursor;
        if (!*cursor) break;

        parsed.argv[parsed.argc++] = destination;
        bool quoted = false;
        while (*cursor) {
            if (!quoted && IsCommandLineSpace(*cursor)) break;

            if (*cursor == L'\\') {
                SIZE_T slashes = 0;
                while (cursor[slashes] == L'\\') ++slashes;
                if (cursor[slashes] == L'"') {
                    for (SIZE_T index = 0; index < slashes / 2; ++index) {
                        *destination++ = L'\\';
                    }
                    if ((slashes & 1u) != 0) {
                        *destination++ = L'\\';
                        cursor += slashes + 1;
                    } else {
                        cursor += slashes;
                    }
                } else {
                    for (SIZE_T index = 0; index < slashes; ++index) {
                        *destination++ = L'\\';
                    }
                    cursor += slashes;
                }
            } else if (*cursor == L'"') {
                if (quoted && cursor[1] == L'"') {
                    *destination++ = L'"';
                    cursor += 2;
                } else {
                    quoted = !quoted;
                    ++cursor;
                }
            } else {
                *destination++ = *cursor++;
            }
        }
        *destination++ = L'\0';
    }

    parsed.argv[parsed.argc] = nullptr;
    return parsed.argc > 0;
}

} // namespace

extern "C" __declspec(noreturn) void mainCRTStartup() noexcept {
    ParsedCommandLine parsed;
    const bool parsedOk = ParseCommandLine(parsed);
    const int result = parsedOk ? Run(parsed.argc, parsed.argv) : 2;
    if (parsed.memory) HeapFree(GetProcessHeap(), 0, parsed.memory);
    ExitProcess(static_cast<UINT>(result));
}

#else

int wmain(int argc, wchar_t** argv) {
    return Run(argc, argv);
}

#endif
