#include "core.h"

#include <fcntl.h>

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

namespace impl {

namespace {

constexpr SIZE_T kChunkSize = 1024 * 1024;

struct HeapLease {
    void* memory = nullptr;
    ~HeapLease() {
        if (memory) HeapFree(GetProcessHeap(), 0, memory);
    }
};

bool AddSize(SIZE_T left, SIZE_T right, SIZE_T& result) noexcept {
    if (right > ~static_cast<SIZE_T>(0) - left) return false;
    result = left + right;
    return true;
}

double Log2Approx(double value) noexcept {
    if (value <= 0.0) return 0.0;

    ULONGLONG bits = 0;
    memcpy(&bits, &value, sizeof(bits));
    const int exponent = static_cast<int>((bits >> 52) & 0x7FF) - 1023;
    const ULONGLONG fractionMask = (1ull << 52) - 1;
    const double mantissa =
        1.0 + static_cast<double>(bits & fractionMask) / 4503599627370496.0;

    const double z = (mantissa - 1.0) / (mantissa + 1.0);
    const double z2 = z * z;
    const double ln =
        2.0 * z *
        (1.0 + z2 / 3.0 + (z2 * z2) / 5.0 + (z2 * z2 * z2) / 7.0);
    return static_cast<double>(exponent) + ln * 1.4426950408889634;
}

void SortFiles(InputFileSpec* files, U32 count) noexcept {
    for (U32 index = 1; index < count; ++index) {
        InputFileSpec value = files[index];
        U32 position = index;
        while (position > 0
            && CompareStringOrdinal(
                value.name, -1,
                files[position - 1].name, -1,
                TRUE
            ) == CSTR_LESS_THAN) {
            files[position] = files[position - 1];
            --position;
        }
        files[position] = value;
    }
}

U32 ReadU32LittleEndian(const U8* data) noexcept {
    return static_cast<U32>(data[0])
        | (static_cast<U32>(data[1]) << 8)
        | (static_cast<U32>(data[2]) << 16)
        | (static_cast<U32>(data[3]) << 24);
}

void WriteU32LittleEndian(U8* data, U32 value) noexcept {
    data[0] = static_cast<U8>(value);
    data[1] = static_cast<U8>(value >> 8);
    data[2] = static_cast<U8>(value >> 16);
    data[3] = static_cast<U8>(value >> 24);
}

bool GetPeHeaderOffset(
    const U8* data,
    SIZE_T size,
    U32& headerOffset
) noexcept {
    if (!data
        || size < 0x80
        || data[0] != 'M'
        || data[1] != 'Z') {
        return false;
    }

    const U32 offset = ReadU32LittleEndian(data + 0x3C);
    if (offset < 0x80
        || offset > size - 4
        || data[offset] != 'P'
        || data[offset + 1] != 'E'
        || data[offset + 2] != 0
        || data[offset + 3] != 0) {
        return false;
    }

    headerOffset = offset;
    return true;
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

bool SplitCabPath(
    const wchar_t* path,
    char* directory,
    SIZE_T directoryCapacity,
    char* file,
    SIZE_T fileCapacity
) noexcept {
    wchar_t directoryWide[1024]{};
    CopyString(directoryWide, 1024, path);
    wchar_t* slash = directoryWide;
    wchar_t* lastSlash = nullptr;
    while (*slash) {
        if (*slash == L'\\' || *slash == L'/') lastSlash = slash;
        ++slash;
    }
    if (!lastSlash) return false;

    *lastSlash = L'\0';
    const wchar_t* name = lastSlash + 1;
    if (!WideToAnsi(directoryWide, directory, directoryCapacity)
        || !WideToAnsi(name, file, fileCapacity)) {
        return false;
    }

    SIZE_T length = 0;
    while (directory[length]) ++length;
    if (length + 1 < directoryCapacity
        && length > 0
        && directory[length - 1] != '\\'
        && directory[length - 1] != '/') {
        directory[length++] = '\\';
        directory[length] = '\0';
    }
    return true;
}

struct FciContext {
    U32 tempIndex = 0;
    char tempDirectory[MAX_PATH]{};
};

FNFCIALLOC(FciAlloc) {
    return HeapAlloc(GetProcessHeap(), 0, cb);
}

FNFCIFREE(FciFree) {
    if (memory) HeapFree(GetProcessHeap(), 0, memory);
}

FNFCIOPEN(FciOpen) {
    (void)pmode;
    (void)err;
    (void)pv;
    if (!pszFile) return -1;

    DWORD access = GENERIC_READ;
    if ((oflag & _O_RDWR) == _O_RDWR) {
        access = GENERIC_READ | GENERIC_WRITE;
    } else if (oflag & _O_WRONLY) {
        access = GENERIC_WRITE;
    }

    DWORD creation = OPEN_EXISTING;
    if (oflag & _O_CREAT) {
        creation = (oflag & _O_TRUNC) ? CREATE_ALWAYS : OPEN_ALWAYS;
    }

    const HANDLE handle = CreateFileA(
        pszFile,
        access,
        FILE_SHARE_READ,
        nullptr,
        creation,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    return reinterpret_cast<INT_PTR>(handle);
}

FNFCIREAD(FciRead) {
    (void)err;
    (void)pv;
    if (hf == -1) return static_cast<UINT>(-1);
    DWORD read = 0;
    if (!ReadFile(
            reinterpret_cast<HANDLE>(hf),
            memory,
            cb,
            &read,
            nullptr
        )) {
        return static_cast<UINT>(-1);
    }
    return static_cast<UINT>(read);
}

FNFCIWRITE(FciWrite) {
    (void)err;
    (void)pv;
    if (hf == -1) return static_cast<UINT>(-1);
    DWORD written = 0;
    if (!WriteFile(
            reinterpret_cast<HANDLE>(hf),
            memory,
            cb,
            &written,
            nullptr
        )) {
        return static_cast<UINT>(-1);
    }
    return static_cast<UINT>(written);
}

FNFCICLOSE(FciClose) {
    (void)err;
    (void)pv;
    if (hf == -1) return -1;
    return CloseHandle(reinterpret_cast<HANDLE>(hf)) ? 0 : -1;
}

FNFCISEEK(FciSeek) {
    (void)err;
    (void)pv;
    if (hf == -1) return -1;
    LONG high = 0;
    const DWORD low = SetFilePointer(
        reinterpret_cast<HANDLE>(hf),
        static_cast<LONG>(dist),
        &high,
        seektype
    );
    if (low == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) return -1;
    return static_cast<long>(low);
}

FNFCIDELETE(FciDelete) {
    (void)err;
    (void)pv;
    return DeleteFileA(pszFile) ? 0 : -1;
}

FNFCIGETTEMPFILE(FciGetTempFile) {
    auto* context = static_cast<FciContext*>(pv);
    if (!context || cbTempName == 0) return FALSE;
    return GetTempFileNameA(
        context->tempDirectory,
        "imp",
        context->tempIndex++,
        pszTempName
    ) != 0;
}

FNFCIGETNEXTCABINET(FciGetNextCabinet) {
    (void)pccab;
    (void)cbPrevCab;
    (void)pv;
    return TRUE;
}

FNFCIFILEPLACED(FciFilePlaced) {
    (void)pccab;
    (void)pszFile;
    (void)cbFile;
    (void)fContinuation;
    (void)pv;
    return 0;
}

FNFCISTATUS(FciStatus) {
    (void)typeStatus;
    (void)cb1;
    (void)cb2;
    (void)pv;
    return 0;
}

FNFCIGETOPENINFO(FciGetOpenInfo) {
    (void)err;
    (void)pv;
    if (!pszName) return -1;
    WIN32_FIND_DATAA info{};
    HANDLE find = FindFirstFileA(pszName, &info);
    if (find == INVALID_HANDLE_VALUE) return -1;
    FindClose(find);

    FILETIME local{};
    if (!FileTimeToLocalFileTime(&info.ftLastWriteTime, &local)
        || !FileTimeToDosDateTime(&local, pdate, ptime)) {
        return -1;
    }
    *pattribs = static_cast<USHORT>(
        info.dwFileAttributes
        & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
            | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE)
    );

    const HANDLE handle = CreateFileA(
        pszName,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    return reinterpret_cast<INT_PTR>(handle);
}

struct FdiInput {
    SIZE_T offset = 0;
    bool active = false;
};

struct FdiState {
    const U8* data = nullptr;
    SIZE_T size = 0;
    FdiInput inputs[8];
    Buffer output;
    SIZE_T position = 0;
    bool active = false;
    bool complete = false;
};

FdiState* g_fdi = nullptr;

LPVOID DIAMONDAPI FdiAlloc(ULONG size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void DIAMONDAPI FdiFree(LPVOID memory) {
    if (memory) HeapFree(GetProcessHeap(), 0, memory);
}

INT_PTR DIAMONDAPI FdiOpen(char*, int, int) {
    if (!g_fdi) return -1;
    for (int index = 0; index < 8; ++index) {
        if (!g_fdi->inputs[index].active) {
            g_fdi->inputs[index].active = true;
            g_fdi->inputs[index].offset = 0;
            return index + 1;
        }
    }
    return -1;
}

UINT DIAMONDAPI FdiRead(INT_PTR handle, void* destination, UINT requested) {
    if (!g_fdi || handle < 1 || handle > 8) return 0;
    FdiInput& input = g_fdi->inputs[handle - 1];
    if (!input.active || input.offset >= g_fdi->size) return 0;

    SIZE_T available = g_fdi->size - input.offset;
    SIZE_T amount = requested < available ? requested : available;
    if (amount == 0) return 0;
    memcpy(destination, g_fdi->data + input.offset, amount);
    input.offset += amount;
    return static_cast<UINT>(amount);
}

UINT DIAMONDAPI FdiWrite(INT_PTR handle, void* source, UINT count) {
    if (!g_fdi || handle != 0x1001 || !g_fdi->active || count == 0) return 0;
    SIZE_T end = 0;
    if (!AddSize(g_fdi->position, count, end)
        || !g_fdi->output.Resize(end)) {
        return 0;
    }
    memcpy(g_fdi->output.data + g_fdi->position, source, count);
    g_fdi->position = end;
    return count;
}

int DIAMONDAPI FdiClose(INT_PTR handle) {
    if (!g_fdi) return -1;
    if (handle >= 1 && handle <= 8) {
        g_fdi->inputs[handle - 1].active = false;
        return 0;
    }
    if (handle == 0x1001) {
        g_fdi->complete = true;
        return 0;
    }
    return -1;
}

long DIAMONDAPI FdiSeek(INT_PTR handle, long distance, int origin) {
    if (!g_fdi) return -1;
    if (handle >= 1 && handle <= 8) {
        FdiInput& input = g_fdi->inputs[handle - 1];
        LONGLONG next = 0;
        if (origin == SEEK_SET) next = distance;
        else if (origin == SEEK_CUR) next = static_cast<LONGLONG>(input.offset) + distance;
        else if (origin == SEEK_END) next = static_cast<LONGLONG>(g_fdi->size) + distance;
        else return -1;
        if (next < 0 || static_cast<SIZE_T>(next) > g_fdi->size) return -1;
        input.offset = static_cast<SIZE_T>(next);
        return static_cast<long>(input.offset);
    }
    if (handle == 0x1001) {
        LONGLONG next = 0;
        if (origin == SEEK_SET) next = distance;
        else if (origin == SEEK_CUR) next = static_cast<LONGLONG>(g_fdi->position) + distance;
        else if (origin == SEEK_END) next = static_cast<LONGLONG>(g_fdi->output.size) + distance;
        else return -1;
        if (next < 0) return -1;
        if (!g_fdi->output.Resize(static_cast<SIZE_T>(next))) return -1;
        g_fdi->position = static_cast<SIZE_T>(next);
        return static_cast<long>(g_fdi->position);
    }
    return -1;
}

INT_PTR DIAMONDAPI FdiNotify(
    FDINOTIFICATIONTYPE type,
    PFDINOTIFICATION notification
) {
    if (!g_fdi || !notification) return -1;
    switch (type) {
    case fdintCOPY_FILE:
        if (g_fdi->active) return 0;
        g_fdi->active = true;
        g_fdi->position = 0;
        g_fdi->output.Clear();
        return 0x1001;
    case fdintCLOSE_FILE_INFO:
        if (notification->hf == 0x1001) g_fdi->complete = true;
        return TRUE;
    default:
        return 0;
    }
}

} // namespace

Buffer::~Buffer() {
    Clear();
}

Buffer::Buffer(Buffer&& other) noexcept
    : data(other.data), size(other.size), capacity(other.capacity) {
    other.data = nullptr;
    other.size = 0;
    other.capacity = 0;
}

Buffer& Buffer::operator=(Buffer&& other) noexcept {
    if (this != &other) {
        Clear();
        data = other.data;
        size = other.size;
        capacity = other.capacity;
        other.data = nullptr;
        other.size = 0;
        other.capacity = 0;
    }
    return *this;
}

bool Buffer::Reserve(SIZE_T requested) {
    if (requested <= capacity) return true;
    if (requested > kMaxInputBytes * 4) return false;

    SIZE_T next = capacity == 0 ? 4096 : capacity;
    while (next < requested) {
        if (next > kMaxInputBytes * 2) {
            next = requested;
            break;
        }
        next *= 2;
    }

    void* memory = data
        ? HeapReAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            data,
            next
        )
        : HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            next
        );
    if (!memory) return false;
    data = static_cast<U8*>(memory);
    capacity = next;
    return true;
}

bool Buffer::Resize(SIZE_T requested) {
    if (!Reserve(requested)) return false;
    if (requested > size) {
        memset(data + size, 0, requested - size);
    }
    size = requested;
    return true;
}

bool Buffer::Append(const void* source, SIZE_T bytes) {
    if (bytes == 0) return true;
    SIZE_T requested = 0;
    if (!AddSize(size, bytes, requested) || !Resize(requested)) {
        return false;
    }
    memcpy(data + size - bytes, source, bytes);
    return true;
}

void Buffer::Clear() {
    if (data) HeapFree(GetProcessHeap(), 0, data);
    data = nullptr;
    size = 0;
    capacity = 0;
}

U8* Buffer::Release() {
    U8* result = data;
    data = nullptr;
    size = 0;
    capacity = 0;
    return result;
}

bool EqualsNoCase(const wchar_t* left, const wchar_t* right) {
    return left && right
        && CompareStringOrdinal(left, -1, right, -1, TRUE) == CSTR_EQUAL;
}

bool EndsWithNoCase(const wchar_t* text, const wchar_t* suffix) {
    if (!text || !suffix) return false;
    SIZE_T textLength = 0;
    SIZE_T suffixLength = 0;
    while (text[textLength]) ++textLength;
    while (suffix[suffixLength]) ++suffixLength;
    if (suffixLength > textLength) return false;
    return EqualsNoCase(text + textLength - suffixLength, suffix);
}

void CopyString(wchar_t* destination, SIZE_T capacity, const wchar_t* source) {
    if (!destination || capacity == 0) return;
    SIZE_T index = 0;
    if (source) {
        while (source[index] && index + 1 < capacity) {
            destination[index] = source[index];
            ++index;
        }
    }
    destination[index] = L'\0';
}

bool JoinPath(
    wchar_t* output,
    SIZE_T capacity,
    const wchar_t* directory,
    const wchar_t* leaf
) {
    if (!output || capacity == 0 || !directory || !leaf) return false;
    SIZE_T index = 0;
    while (directory[index] && index + 1 < capacity) {
        output[index] = directory[index];
        ++index;
    }
    if (index + 1 >= capacity) return false;
    if (index > 0 && directory[index - 1] != L'\\' && directory[index - 1] != L'/') {
        output[index++] = L'\\';
    }
    SIZE_T source = 0;
    while (leaf[source] && index + 1 < capacity) {
        output[index++] = leaf[source++];
    }
    output[index] = L'\0';
    return leaf[source] == L'\0';
}

const wchar_t* BaseName(const wchar_t* path) {
    if (!path) return L"";
    const wchar_t* result = path;
    for (const wchar_t* cursor = path; *cursor; ++cursor) {
        if (*cursor == L'\\' || *cursor == L'/') result = cursor + 1;
    }
    return result;
}

bool EnsureDirectory(const wchar_t* path) {
    if (!path || !*path) return false;
    const DWORD attributes = GetFileAttributesW(path);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    return CreateDirectoryW(path, nullptr) != FALSE;
}

bool ReadFileToBuffer(const wchar_t* path, Buffer& output) {
    const HANDLE file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    bool ok = GetFileSizeEx(file, &size) != FALSE
        && size.QuadPart >= 0
        && static_cast<U64>(size.QuadPart) <= kMaxInputBytes
        && output.Resize(static_cast<SIZE_T>(size.QuadPart));

    SIZE_T offset = 0;
    while (ok && offset < output.size) {
        DWORD read = 0;
        const DWORD requested = static_cast<DWORD>(
            output.size - offset < kChunkSize
                ? output.size - offset
                : kChunkSize
        );
        if (!ReadFile(
                file,
                output.data + offset,
                requested,
                &read,
                nullptr
            ) || read == 0) {
            ok = false;
            break;
        }
        offset += read;
    }
    CloseHandle(file);
    return ok && offset == output.size;
}

bool WriteFileFromBuffer(const wchar_t* path, const U8* data, SIZE_T size) {
    const HANDLE file = CreateFileW(
        path,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) return false;

    bool ok = true;
    SIZE_T offset = 0;
    while (offset < size) {
        DWORD written = 0;
        const DWORD requested = static_cast<DWORD>(
            size - offset < kChunkSize ? size - offset : kChunkSize
        );
        if (!WriteFile(file, data + offset, requested, &written, nullptr)
            || written == 0) {
            ok = false;
            break;
        }
        offset += written;
    }
    CloseHandle(file);
    if (!ok) DeleteFileW(path);
    return ok;
}

bool WriteTemporaryFile(
    const wchar_t* directory,
    const wchar_t* prefix,
    Buffer& data,
    wchar_t* outputPath,
    SIZE_T capacity
) {
    if (!directory || !prefix || !outputPath || capacity == 0) return false;
    if (GetTempFileNameW(directory, prefix, 0, outputPath) == 0) return false;
    if (!WriteFileFromBuffer(outputPath, data.data, data.size)) return false;

    SYSTEMTIME fixedTime{};
    fixedTime.wYear = 2027;
    fixedTime.wMonth = 1;
    fixedTime.wDay = 1;
    FILETIME fileTime{};
    if (!SystemTimeToFileTime(&fixedTime, &fileTime)) return false;

    const HANDLE file = CreateFileW(
        outputPath,
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) return false;
    const BOOL changed = SetFileTime(file, nullptr, nullptr, &fileTime);
    CloseHandle(file);
    return changed != FALSE;
}

bool ComputeSha256(const U8* data, SIZE_T size, U8 output[32]) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    PUCHAR object = nullptr;
    bool ok = false;

    do {
        if (BCryptOpenAlgorithmProvider(
                &algorithm,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                0
            ) < 0) {
            break;
        }

        DWORD objectSize = 0;
        DWORD resultSize = 0;
        if (BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectSize),
                sizeof(objectSize),
                &resultSize,
                0
            ) < 0) {
            break;
        }

        object = static_cast<PUCHAR>(
            HeapAlloc(GetProcessHeap(), 0, objectSize)
        );
        if (!object) break;

        if (BCryptCreateHash(
                algorithm,
                &hash,
                object,
                objectSize,
                nullptr,
                0,
                0
            ) < 0) {
            break;
        }

        SIZE_T offset = 0;
        while (offset < size) {
            const ULONG amount = static_cast<ULONG>(
                size - offset < 1024 * 1024
                    ? size - offset
                    : 1024 * 1024
            );
            if (BCryptHashData(hash, const_cast<PUCHAR>(data + offset), amount, 0) < 0) {
                break;
            }
            offset += amount;
        }
        if (offset != size) break;

        if (BCryptFinishHash(hash, output, 32, 0) < 0) break;
        ok = true;
    } while (false);

    if (hash) BCryptDestroyHash(hash);
    if (object) HeapFree(GetProcessHeap(), 0, object);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

bool Sha256Equals(const U8 left[32], const U8 right[32]) {
    U8 difference = 0;
    for (int index = 0; index < 32; ++index) {
        difference |= static_cast<U8>(left[index] ^ right[index]);
    }
    return difference == 0;
}

double CalculateEntropy(const U8* data, SIZE_T size) {
    if (!data || size == 0) return 0.0;
    U64 counts[256]{};
    for (SIZE_T index = 0; index < size; ++index) {
        ++counts[data[index]];
    }

    double entropy = 0.0;
    for (U32 value = 0; value < 256; ++value) {
        if (counts[value] == 0) continue;
        const double probability =
            static_cast<double>(counts[value]) / static_cast<double>(size);
        entropy -= probability * Log2Approx(probability);
    }
    return entropy;
}

static bool BuildContainerCore(
    const InputFileSpec* files,
    U32 fileCount,
    const PackOptions& options,
    Buffer& output
) {
    if (!files || fileCount == 0 || fileCount > kMaxFiles) return false;

    Buffer templateFile;
    U8 templateSha256[32]{};
    if (options.stripPe) {
        if (!options.templatePath
            || !ReadFileToBuffer(options.templatePath, templateFile)
            || templateFile.size < 0x80
            || templateFile.data[0] != 'M'
            || templateFile.data[1] != 'Z'
            || !ComputeSha256(
                templateFile.data,
                0x80,
                templateSha256
            )) {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }
    }

    U64 totalData = 0;
    for (U32 index = 0; index < fileCount; ++index) {
        Buffer fileData;
        U32 peOffset = 0;
        if (!ReadFileToBuffer(files[index].path, fileData)
            || fileData.size > kMaxInputBytes) {
            return false;
        }

        U64 storedSize = fileData.size;
        if (options.stripPe
            && GetPeHeaderOffset(fileData.data, fileData.size, peOffset)) {
            storedSize -= 0x80;
        }
        totalData += storedSize;
        if (totalData > kMaxInputBytes) {
            SetLastError(ERROR_FILE_TOO_LARGE);
            return false;
        }
    }

    const SIZE_T headerSize = sizeof(ContainerHeader);
    const SIZE_T recordsSize = sizeof(FileRecord) * fileCount;
    const SIZE_T dataOffset = headerSize + recordsSize;
    if (dataOffset > kMaxInputBytes
        || totalData > kMaxInputBytes - dataOffset
        || !output.Resize(dataOffset + static_cast<SIZE_T>(totalData))) {
        return false;
    }

    auto* header = reinterpret_cast<ContainerHeader*>(output.data);
    memcpy(header->magic, kContainerMagic, sizeof(header->magic));
    header->version = kContainerVersion;
    header->count = fileCount;
    header->headerSize = static_cast<U32>(headerSize);
    header->dataOffset = static_cast<U32>(dataOffset);
    header->dataSize = totalData;
    memcpy(header->templateSha256, templateSha256, 32);
    header->flags = 0;
    if (options.stripPe) header->flags |= kContainerFlagPeStripped;
    if (options.xorMode != XorMode::None) {
        header->flags |= kContainerFlagCabXor;
    }
    header->xorMode = static_cast<U32>(options.xorMode);
    header->xorKeyLength = options.xorKeyLength;
    if (options.xorMode == XorMode::FullCab) {
        if (!options.xorKey
            || options.xorKeyLength == 0
            || options.xorKeyLength > 256
            || !ComputeSha256(
                options.xorKey,
                options.xorKeyLength,
                header->xorKeySha256
            )) {
            return false;
        }
    }
    header->reserved = 0;

    auto* records = reinterpret_cast<FileRecord*>(output.data + headerSize);
    U64 dataPosition = 0;
    for (U32 index = 0; index < fileCount; ++index) {
        Buffer fileData;
        if (!ReadFileToBuffer(files[index].path, fileData)) {
            return false;
        }

        FileRecord& record = records[index];
        memset(&record, 0, sizeof(record));
        CopyString(record.name, 128, files[index].name);
        record.offset = dataPosition;
        record.originalSize = fileData.size;

        U32 peOffset = 0;
        U32 storedOffset = 0;
        U64 storedSize = fileData.size;
        if (options.stripPe
            && GetPeHeaderOffset(fileData.data, fileData.size, peOffset)) {
            storedOffset = 0x80;
            storedSize = fileData.size - 0x80;
            record.flags = kFileFlagDosHeaderStripped;
            record.eLfanew = peOffset;
        }
        record.storedSize = storedSize;

        if (!ComputeSha256(
                fileData.data + storedOffset,
                static_cast<SIZE_T>(storedSize),
                record.storedSha256
            )
            || !ComputeSha256(
                fileData.data,
                fileData.size,
                record.originalSha256
            )) {
            return false;
        }

        memcpy(
            output.data + dataOffset + static_cast<SIZE_T>(dataPosition),
            fileData.data + storedOffset,
            static_cast<SIZE_T>(storedSize)
        );
        dataPosition += storedSize;
    }

    return dataPosition == totalData;
}

bool BuildContainerFromFiles(
    const PackOptions& options,
    Buffer& output,
    U32& fileCount
) {
    fileCount = options.fileCount;
    return BuildContainerCore(options.files, options.fileCount, options, output);
}

bool BuildContainer(
    const wchar_t* inputDirectory,
    const PackOptions& options,
    Buffer& output,
    U32& fileCount
) {
    if (!inputDirectory) return false;

    HeapLease patternMemory;
    patternMemory.memory = HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        1024 * sizeof(wchar_t)
    );
    if (!patternMemory.memory) return false;
    auto* pattern = static_cast<wchar_t*>(patternMemory.memory);
    if (!JoinPath(pattern, 1024, inputDirectory, L"*")) return false;

    HeapLease filesMemory;
    filesMemory.memory = HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(InputFileSpec) * kMaxFiles
    );
    if (!filesMemory.memory) return false;
    auto* files = static_cast<InputFileSpec*>(filesMemory.memory);
    fileCount = 0;

    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) return false;

    bool ok = true;
    do {
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (fileCount >= kMaxFiles) {
            ok = false;
            break;
        }
        InputFileSpec& file = files[fileCount++];
        if (!JoinPath(file.path, 1024, inputDirectory, data.cFileName)) {
            ok = false;
            break;
        }
        CopyString(file.name, 128, data.cFileName);
    } while (FindNextFileW(find, &data));
    const DWORD findError = GetLastError();
    FindClose(find);
    if (findError != ERROR_NO_MORE_FILES || !ok || fileCount == 0) return false;

    if (options.sortFiles) SortFiles(files, fileCount);
    return BuildContainerCore(files, fileCount, options, output);
}

bool OpenContainer(const U8* data, SIZE_T size, ContainerView& output) {
    if (!data || size < sizeof(ContainerHeader)) return false;
    const auto* header = reinterpret_cast<const ContainerHeader*>(data);
    if (memcmp(header->magic, kContainerMagic, sizeof(header->magic)) != 0
        || header->version != kContainerVersion
        || header->count == 0
        || header->count > kMaxFiles
        || header->headerSize != sizeof(ContainerHeader)
        || header->xorMode > static_cast<U32>(XorMode::FullCab)) {
        return false;
    }
    if (header->xorMode == static_cast<U32>(XorMode::FullCab)
        && (header->xorKeyLength == 0 || header->xorKeyLength > 256)) {
        return false;
    }

    const SIZE_T recordsSize = sizeof(FileRecord) * header->count;
    if (recordsSize > size
        || header->dataOffset < sizeof(ContainerHeader) + recordsSize
        || header->dataOffset > size
        || header->dataSize > size - header->dataOffset) {
        return false;
    }

    const auto* records = reinterpret_cast<const FileRecord*>(
        data + header->headerSize
    );
    for (U32 index = 0; index < header->count; ++index) {
        const FileRecord& record = records[index];
        if (record.offset > header->dataSize
            || record.storedSize > header->dataSize - record.offset) {
            return false;
        }

        if ((record.flags & kFileFlagDosHeaderStripped) != 0) {
            if (record.eLfanew < 0x80
                || record.originalSize != 0x80 + record.storedSize) {
                return false;
            }
        } else if (record.originalSize != record.storedSize) {
            return false;
        }
    }

    output.header = header;
    output.records = records;
    output.data = data + header->dataOffset;
    return true;
}

bool ExtractContainer(
    const ContainerView& container,
    const wchar_t* outputDirectory,
    const wchar_t* templatePath
) {
    if (!container.header || !container.records || !container.data) return false;
    if (!EnsureDirectory(outputDirectory)) return false;

    Buffer templateFile;
    if ((container.header->flags & kContainerFlagPeStripped) != 0) {
        if (!templatePath
            || !ReadFileToBuffer(templatePath, templateFile)
            || templateFile.size < 0x80
            || templateFile.data[0] != 'M'
            || templateFile.data[1] != 'Z') {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }

        U8 templateDigest[32]{};
        if (!ComputeSha256(templateFile.data, 0x80, templateDigest)
            || !Sha256Equals(templateDigest, container.header->templateSha256)) {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }
    }

    wchar_t path[1024]{};
    for (U32 index = 0; index < container.header->count; ++index) {
        const FileRecord& record = container.records[index];
        const U8* stored =
            container.data + static_cast<SIZE_T>(record.offset);
        U8 digest[32]{};
        if (!ComputeSha256(
                stored,
                static_cast<SIZE_T>(record.storedSize),
                digest
            )
            || !Sha256Equals(digest, record.storedSha256)
            || !JoinPath(path, 1024, outputDirectory, record.name)) {
            return false;
        }

        if ((record.flags & kFileFlagDosHeaderStripped) != 0) {
            Buffer reconstructed;
            if (!reconstructed.Resize(
                    0x80 + static_cast<SIZE_T>(record.storedSize)
                )) {
                return false;
            }
            memcpy(reconstructed.data, templateFile.data, 0x80);
            WriteU32LittleEndian(
                reconstructed.data + 0x3C,
                record.eLfanew
            );
            memcpy(
                reconstructed.data + 0x80,
                stored,
                static_cast<SIZE_T>(record.storedSize)
            );
            if (record.eLfanew > reconstructed.size - 4
                || reconstructed.data[record.eLfanew] != 'P'
                || reconstructed.data[record.eLfanew + 1] != 'E'
                || reconstructed.data[record.eLfanew + 2] != 0
                || reconstructed.data[record.eLfanew + 3] != 0
                || !ComputeSha256(
                    reconstructed.data,
                    reconstructed.size,
                    digest
                )
                || !Sha256Equals(digest, record.originalSha256)
                || !WriteFileFromBuffer(
                    path,
                    reconstructed.data,
                    reconstructed.size
                )) {
                return false;
            }
        } else {
            if (record.originalSize != record.storedSize
                || !Sha256Equals(record.storedSha256, record.originalSha256)
                || !WriteFileFromBuffer(
                    path,
                    stored,
                    static_cast<SIZE_T>(record.storedSize)
                )) {
                return false;
            }
        }
    }
    return true;
}

bool CreateCab(
    const wchar_t* cabPath,
    const wchar_t* payloadPath,
    const char* entryName,
    Buffer& cabData
) {
    if (!cabPath || !payloadPath || !entryName) return false;

    char directory[MAX_PATH]{};
    char file[MAX_PATH]{};
    char payload[MAX_PATH]{};
    if (!SplitCabPath(cabPath, directory, MAX_PATH, file, MAX_PATH)
        || !WideToAnsi(payloadPath, payload, MAX_PATH)) {
        return false;
    }

    FciContext context{};
    lstrcpynA(context.tempDirectory, directory, MAX_PATH);

    ERF error{};
    HeapLease cabMemory;
    cabMemory.memory = HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(CCAB)
    );
    if (!cabMemory.memory) return false;
    auto* cab = static_cast<CCAB*>(cabMemory.memory);
    cab->cb = 0x7FFFFFFF;
    cab->cbFolderThresh = 0x7FFFFFFF;
    cab->iCab = 1;
    cab->iDisk = 0;
    cab->setID = 0;
    lstrcpynA(cab->szCab, file, sizeof(cab->szCab));
    lstrcpynA(cab->szCabPath, directory, sizeof(cab->szCabPath));

    HFCI fci = FCICreate(
        &error,
        FciFilePlaced,
        FciAlloc,
        FciFree,
        FciOpen,
        FciRead,
        FciWrite,
        FciClose,
        FciSeek,
        FciDelete,
        FciGetTempFile,
        cab,
        &context
    );
    if (!fci) return false;

    BOOL added = FCIAddFile(
        fci,
        payload,
        const_cast<char*>(entryName),
        FALSE,
        FciGetNextCabinet,
        FciStatus,
        FciGetOpenInfo,
        tcompTYPE_LZX | tcompLZX_WINDOW_HI
    );
    if (added) {
        added = FCIFlushCabinet(fci, FALSE, FciGetNextCabinet, FciStatus);
    }
    FCIDestroy(fci);
    if (!added) return false;

    return ReadFileToBuffer(cabPath, cabData) && cabData.size >= 4;
}

bool ExtractCab(const U8* cabData, SIZE_T cabSize, Buffer& payload) {
    if (!cabData || cabSize < 4) return false;

    FdiState state{};
    state.data = cabData;
    state.size = cabSize;
    g_fdi = &state;

    ERF error{};
    HFDI fdi = FDICreate(
        FdiAlloc,
        FdiFree,
        FdiOpen,
        FdiRead,
        FdiWrite,
        FdiClose,
        FdiSeek,
        cpuUNKNOWN,
        &error
    );
    if (!fdi) {
        g_fdi = nullptr;
        return false;
    }

    char name[] = "payload.cab";
    char path[] = "";
    const BOOL copied = FDICopy(fdi, name, path, 0, FdiNotify, nullptr, nullptr);
    FDIDestroy(fdi);
    g_fdi = nullptr;

    if (!copied || !state.complete) return false;
    payload = static_cast<Buffer&&>(state.output);
    return true;
}

} // namespace impl
