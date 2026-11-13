#include "config.h"

namespace impl {

namespace {

struct WideLease {
    wchar_t* data = nullptr;
    ~WideLease() {
        if (data) HeapFree(GetProcessHeap(), 0, data);
    }
};

struct LineBuffer {
    wchar_t data[1024]{};
    SIZE_T length = 0;
};

bool IsSpace(wchar_t value) noexcept {
    return value == L' ' || value == L'\t' || value == L'\r' || value == L'\n';
}

void Trim(wchar_t* text) noexcept {
    SIZE_T length = 0;
    while (text[length]) ++length;
    SIZE_T start = 0;
    while (start < length && IsSpace(text[start])) ++start;
    while (length > start && IsSpace(text[length - 1])) --length;
    if (start > 0) {
        memmove(text, text + start, (length - start) * sizeof(wchar_t));
    }
    text[length - start] = L'\0';
}

__declspec(noinline)
bool CopyTrimmedValue(const wchar_t* value, wchar_t* output, SIZE_T capacity) noexcept {
    if (!value || !output || capacity == 0) return false;
    LineBuffer buffer{};
    CopyString(buffer.data, 1024, value);
    Trim(buffer.data);

    SIZE_T start = 0;
    SIZE_T length = 0;
    while (buffer.data[length]) ++length;
    if (length >= 2
        && buffer.data[0] == L'"'
        && buffer.data[length - 1] == L'"') {
        start = 1;
        length -= 2;
    }
    if (length + 1 > capacity) return false;
    memcpy(output, buffer.data + start, length * sizeof(wchar_t));
    output[length] = L'\0';
    return true;
}

bool ParseBoolean(const wchar_t* value, bool& output) noexcept {
    if (EqualsNoCase(value, L"1")
        || EqualsNoCase(value, L"true")
        || EqualsNoCase(value, L"yes")) {
        output = true;
        return true;
    }
    if (EqualsNoCase(value, L"0")
        || EqualsNoCase(value, L"false")
        || EqualsNoCase(value, L"no")) {
        output = false;
        return true;
    }
    return false;
}

bool ParseXorMode(const wchar_t* value, XorMode& output) noexcept {
    if (EqualsNoCase(value, L"none")) {
        output = XorMode::None;
        return true;
    }
    if (EqualsNoCase(value, L"mask-magic")) {
        output = XorMode::MaskMagic;
        return true;
    }
    if (EqualsNoCase(value, L"full-cab")) {
        output = XorMode::FullCab;
        return true;
    }
    return false;
}

int HexDigit(wchar_t value) noexcept {
    if (value >= L'0' && value <= L'9') return value - L'0';
    if (value >= L'a' && value <= L'f') return value - L'a' + 10;
    if (value >= L'A' && value <= L'F') return value - L'A' + 10;
    return -1;
}

bool ParseHexKey(const wchar_t* value, U8* output, U32& length) noexcept {
    SIZE_T textLength = 0;
    while (value[textLength]) ++textLength;
    if (textLength == 0 || textLength > 512 || (textLength & 1u) != 0) {
        return false;
    }

    const U32 bytes = static_cast<U32>(textLength / 2);
    for (U32 index = 0; index < bytes; ++index) {
        const int high = HexDigit(value[index * 2]);
        const int low = HexDigit(value[index * 2 + 1]);
        if (high < 0 || low < 0) return false;
        output[index] = static_cast<U8>((high << 4) | low);
    }
    length = bytes;
    return true;
}

bool IsAbsolutePath(const wchar_t* path) noexcept {
    if (!path) return false;
    if ((path[0] && path[1] == L':') || (path[0] == L'\\' && path[1] == L'\\')) {
        return true;
    }
    return path[0] == L'\\';
}

bool ExpandPath(wchar_t* path, SIZE_T capacity) noexcept {
    if (!path || !path[0]) return true;
    WideLease expanded;
    expanded.data = static_cast<wchar_t*>(HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        capacity * sizeof(wchar_t)
    ));
    if (!expanded.data) return false;
    const DWORD length = ExpandEnvironmentStringsW(
        path,
        expanded.data,
        static_cast<DWORD>(capacity)
    );
    if (length == 0 || length > capacity) return false;
    CopyString(path, capacity, expanded.data);
    return true;
}

__declspec(noinline)
bool ResolveRelativePath(
    const PackConfig& config,
    wchar_t* path,
    SIZE_T capacity
) noexcept {
    if (!path || !path[0] || IsAbsolutePath(path)) return true;
    wchar_t absolute[1024]{};
    if (!JoinPath(absolute, 1024, config.baseDirectory, path)) return false;
    if (capacity < 1024) {
        SIZE_T length = 0;
        while (absolute[length]) ++length;
        if (length + 1 > capacity) return false;
    }
    CopyString(path, capacity, absolute);
    return true;
}

bool SetError(PackConfig& config, U32 line, const wchar_t* message) noexcept {
    config.errorLine = line;
    CopyString(config.error, 256, message);
    SetLastError(ERROR_INVALID_DATA);
    return false;
}

__declspec(noinline)
bool SetDefaultTemplate(PackConfig& config) noexcept {
    wchar_t systemDirectory[MAX_PATH]{};
    const UINT length = GetSystemDirectoryW(
        systemDirectory,
        static_cast<UINT>(sizeof(systemDirectory) / sizeof(systemDirectory[0]))
    );
    return length > 0
        && length < sizeof(systemDirectory) / sizeof(systemDirectory[0])
        && JoinPath(
            config.templatePath,
            sizeof(config.templatePath) / sizeof(config.templatePath[0]),
            systemDirectory,
            L"drivers\\ks.sys"
        );
}

__declspec(noinline)
bool ValidateAndFinalize(PackConfig& config) {
    if (!ExpandPath(
            config.outputPath,
            sizeof(config.outputPath) / sizeof(config.outputPath[0])
        )
        || !ExpandPath(
            config.templatePath,
            sizeof(config.templatePath) / sizeof(config.templatePath[0])
        )) {
        return SetError(config, 0, L"cannot expand config path");
    }
    if (!ResolveRelativePath(
            config,
            config.outputPath,
            sizeof(config.outputPath) / sizeof(config.outputPath[0])
        )) {
        return SetError(config, 0, L"Pack.Output path too long");
    }
    if (config.templatePath[0]
        && !ResolveRelativePath(
            config,
            config.templatePath,
            sizeof(config.templatePath) / sizeof(config.templatePath[0])
        )) {
        return SetError(config, 0, L"Pack.Template path too long");
    }
    if (!config.outputPath[0]) {
        return SetError(config, 0, L"missing Pack.Output");
    }
    if (!config.entryName[0]) {
        CopyString(
            config.entryName,
            sizeof(config.entryName) / sizeof(config.entryName[0]),
            BaseName(config.outputPath)
        );
    }
    if (!config.templatePath[0] && !SetDefaultTemplate(config)) {
        return SetError(config, 0, L"cannot resolve ks.sys template");
    }
    if (config.fileCount == 0) {
        return SetError(config, 0, L"missing [Files] entries");
    }
    if (config.xorMode == XorMode::FullCab && config.xorKeyLength == 0) {
        return SetError(config, 0, L"full-cab requires a non-empty XOR key");
    }
    return true;
}

} // namespace

bool LoadPackConfig(const wchar_t* iniPath, PackConfig& config) {
    memset(&config, 0, sizeof(config));
    config.stripPe = true;
    config.xorMode = XorMode::FullCab;
    if (!iniPath) return false;
    memcpy(config.xorKey, kDefaultXorKey, sizeof(kDefaultXorKey));
    config.xorKeyLength = sizeof(kDefaultXorKey);
    CopyString(
        config.iniPath,
        sizeof(config.iniPath) / sizeof(config.iniPath[0]),
        iniPath
    );

    Buffer fileData;
    if (!ReadFileToBuffer(iniPath, fileData) || fileData.size == 0) {
        SetLastError(ERROR_FILE_INVALID);
        return false;
    }

    WideLease wide;
    SIZE_T characterCount = 0;
    const U8* bytes = fileData.data;
    SIZE_T byteCount = fileData.size;

    if (byteCount >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) {
        bytes += 2;
        byteCount -= 2;
        if ((byteCount & 1u) != 0) {
            return SetError(config, 0, L"invalid UTF-16 config length");
        }
        characterCount = byteCount / 2;
        wide.data = static_cast<wchar_t*>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (characterCount + 1) * sizeof(wchar_t))
        );
        if (!wide.data) return false;
        memcpy(wide.data, bytes, byteCount);
    } else {
        if (byteCount >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) {
            bytes += 3;
            byteCount -= 3;
        }
        const int required = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(bytes),
            static_cast<int>(byteCount),
            nullptr,
            0
        );
        if (required <= 0) return SetError(config, 0, L"invalid UTF-8 config");
        characterCount = static_cast<SIZE_T>(required);
        wide.data = static_cast<wchar_t*>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (characterCount + 1) * sizeof(wchar_t))
        );
        if (!wide.data) return false;
        if (MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                reinterpret_cast<const char*>(bytes),
                static_cast<int>(byteCount),
                wide.data,
                required
            ) <= 0) {
            return SetError(config, 0, L"cannot decode UTF-8 config");
        }
    }

    if (!JoinPath(
            config.baseDirectory,
            sizeof(config.baseDirectory) / sizeof(config.baseDirectory[0]),
            L"",
            iniPath
        )) {
        return SetError(config, 0, L"config path too long");
    }
    wchar_t* separator = config.baseDirectory;
    wchar_t* lastSeparator = nullptr;
    while (*separator) {
        if (*separator == L'\\' || *separator == L'/') lastSeparator = separator;
        ++separator;
    }
    if (lastSeparator) {
        *lastSeparator = L'\0';
    } else {
        CopyString(config.baseDirectory, 1024, L".");
    }

    bool inPack = false;
    bool inFiles = false;
    U32 lineNumber = 0;
    wchar_t* cursor = wide.data;
    wchar_t* end = wide.data + characterCount;

    while (cursor < end) {
        ++lineNumber;
        wchar_t* line = cursor;
        while (cursor < end && *cursor != L'\n' && *cursor != L'\r') ++cursor;
        *cursor = L'\0';
        if (cursor < end) {
            if (*cursor == L'\r' && cursor + 1 < end && cursor[1] == L'\n') ++cursor;
            ++cursor;
        }

        Trim(line);
        if (!*line || *line == L';' || *line == L'#') continue;

        if (*line == L'[') {
            SIZE_T length = 0;
            while (line[length]) ++length;
            if (length < 3 || line[length - 1] != L']') {
                return SetError(config, lineNumber, L"invalid section line");
            }
            line[length - 1] = L'\0';
            const wchar_t* section = line + 1;
            inPack = EqualsNoCase(section, L"Pack");
            inFiles = EqualsNoCase(section, L"Files");
            if (!inPack && !inFiles && !EqualsNoCase(section, L"Config")) {
                return SetError(config, lineNumber, L"unknown config section");
            }
            continue;
        }

        wchar_t* equals = line;
        while (*equals && *equals != L'=') ++equals;
        if (!*equals) return SetError(config, lineNumber, L"missing '='");
        *equals = L'\0';
        Trim(line);
        wchar_t* value = equals + 1;
        Trim(value);

        if (inPack) {
            if (EqualsNoCase(line, L"Output")) {
                if (!CopyTrimmedValue(value, config.outputPath, 1024)) {
                    return SetError(config, lineNumber, L"invalid Pack.Output");
                }
            } else if (EqualsNoCase(line, L"EntryName")) {
                if (!CopyTrimmedValue(value, config.entryName, 128)) {
                    return SetError(config, lineNumber, L"invalid Pack.EntryName");
                }
            } else if (EqualsNoCase(line, L"Template")) {
                if (!CopyTrimmedValue(value, config.templatePath, 1024)) {
                    return SetError(config, lineNumber, L"invalid Pack.Template");
                }
            } else if (EqualsNoCase(line, L"StripPe")) {
                if (!ParseBoolean(value, config.stripPe)) {
                    return SetError(config, lineNumber, L"invalid Pack.StripPe");
                }
            } else if (EqualsNoCase(line, L"XorMode")) {
                if (!ParseXorMode(value, config.xorMode)) {
                    return SetError(config, lineNumber, L"invalid Pack.XorMode");
                }
            } else if (EqualsNoCase(line, L"XorKeyHex")) {
                if (!ParseHexKey(value, config.xorKey, config.xorKeyLength)) {
                    return SetError(config, lineNumber, L"invalid Pack.XorKeyHex");
                }
            } else {
                return SetError(config, lineNumber, L"unknown [Pack] key");
            }
        } else if (inFiles) {
            U32 number = 0;
            const wchar_t* digit = line;
            while (*digit >= L'0' && *digit <= L'9') {
                const U32 next = number * 10 + static_cast<U32>(*digit - L'0');
                if (next < number || next > kMaxFiles) {
                    return SetError(config, lineNumber, L"file index out of range");
                }
                number = next;
                ++digit;
            }
            if (!number || *digit) {
                return SetError(config, lineNumber, L"file key must be 1..64");
            }
            if (config.files[number - 1].path[0]) {
                return SetError(config, lineNumber, L"duplicate file index");
            }

            WideLease pathStorage;
            pathStorage.data = static_cast<wchar_t*>(HeapAlloc(
                GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                2048 * sizeof(wchar_t)
            ));
            if (!pathStorage.data) return false;
            wchar_t* filePath = pathStorage.data;
            wchar_t* absolute = pathStorage.data + 1024;
            if (!CopyTrimmedValue(value, filePath, 1024)) {
                return SetError(config, lineNumber, L"invalid file path");
            }
            if (!ExpandPath(filePath, 1024)) {
                return SetError(config, lineNumber, L"cannot expand file path");
            }
            if (!IsAbsolutePath(filePath)) {
                if (!JoinPath(absolute, 1024, config.baseDirectory, filePath)) {
                    return SetError(config, lineNumber, L"file path too long");
                }
                CopyString(filePath, 1024, absolute);
            }
            CopyString(config.files[number - 1].path, 1024, filePath);
            CopyString(config.files[number - 1].name, 128, BaseName(filePath));
        } else if (EqualsNoCase(line, L"Version")) {
            if (!EqualsNoCase(value, L"1")) {
                return SetError(config, lineNumber, L"unsupported Config.Version");
            }
        } else {
            return SetError(config, lineNumber, L"key outside [Pack]/[Files]");
        }
    }

    for (U32 index = 0; index < kMaxFiles; ++index) {
        if (!config.files[index].path[0]) continue;
        if (index != config.fileCount) {
            return SetError(config, 0, L"[Files] indexes must be contiguous from 1");
        }
        ++config.fileCount;
    }

    return ValidateAndFinalize(config);
}

} // namespace impl
