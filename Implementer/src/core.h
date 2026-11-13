#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <fci.h>
#include <fdi.h>

namespace impl {

using U8 = BYTE;
using U16 = WORD;
using U32 = DWORD;
using U64 = ULONGLONG;

constexpr U32 kMaxFiles = 64;
constexpr U32 kContainerVersion = 3;
constexpr SIZE_T kMaxInputBytes = 64ull * 1024ull * 1024ull;
constexpr char kContainerMagic[8] = {'I', 'M', 'P', 'L', '0', '0', '0', '3'};
constexpr U32 kFileFlagDosHeaderStripped = 0x00000001;
constexpr U32 kContainerFlagPeStripped = 0x00000001;
constexpr U32 kContainerFlagCabXor = 0x00000002;
constexpr BYTE kMaskedCabMagic[4] = {
    static_cast<BYTE>('M' ^ 0xA5),
    static_cast<BYTE>('S' ^ 0x5A),
    static_cast<BYTE>('C' ^ 0xF0),
    static_cast<BYTE>('F' ^ 0x0F)
};

struct Buffer {
    U8* data = nullptr;
    SIZE_T size = 0;
    SIZE_T capacity = 0;

    Buffer() = default;
    ~Buffer();
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    Buffer(Buffer&& other) noexcept;
    Buffer& operator=(Buffer&& other) noexcept;

    bool Reserve(SIZE_T requested);
    bool Resize(SIZE_T requested);
    bool Append(const void* source, SIZE_T bytes);
    void Clear();
    U8* Release();
};

struct FileRecord {
    wchar_t name[128];
    U64 offset;
    U64 storedSize;
    U64 originalSize;
    U8 storedSha256[32];
    U8 originalSha256[32];
    U32 flags;
    U32 eLfanew;
};

struct ContainerHeader {
    char magic[8];
    U32 version;
    U32 count;
    U32 headerSize;
    U32 dataOffset;
    U64 dataSize;
    U8 templateSha256[32];
    U8 xorKeySha256[32];
    U32 xorMode;
    U32 xorKeyLength;
    U32 flags;
    U32 reserved;
};

struct ContainerView {
    const ContainerHeader* header = nullptr;
    const FileRecord* records = nullptr;
    const U8* data = nullptr;
};

enum class XorMode : U32 {
    None = 0,
    MaskMagic = 1,
    FullCab = 2
};

struct InputFileSpec {
    wchar_t path[1024];
    wchar_t name[128];
};

struct PackOptions {
    const wchar_t* templatePath;
    bool stripPe;
    bool sortFiles;
    const InputFileSpec* files;
    U32 fileCount;
    XorMode xorMode;
    const U8* xorKey;
    U32 xorKeyLength;
};

bool EqualsNoCase(const wchar_t* left, const wchar_t* right);
bool EndsWithNoCase(const wchar_t* text, const wchar_t* suffix);
void CopyString(wchar_t* destination, SIZE_T capacity, const wchar_t* source);
bool JoinPath(
    wchar_t* output,
    SIZE_T capacity,
    const wchar_t* directory,
    const wchar_t* leaf
);
const wchar_t* BaseName(const wchar_t* path);
bool EnsureDirectory(const wchar_t* path);

bool ReadFileToBuffer(const wchar_t* path, Buffer& output);
bool WriteFileFromBuffer(const wchar_t* path, const U8* data, SIZE_T size);
bool WriteTemporaryFile(
    const wchar_t* directory,
    const wchar_t* prefix,
    Buffer& data,
    wchar_t* outputPath,
    SIZE_T capacity
);

bool ComputeSha256(const U8* data, SIZE_T size, U8 output[32]);
bool Sha256Equals(const U8 left[32], const U8 right[32]);
double CalculateEntropy(const U8* data, SIZE_T size);

bool BuildContainer(
    const wchar_t* inputDirectory,
    const PackOptions& options,
    Buffer& output,
    U32& fileCount
);
bool BuildContainerFromFiles(
    const PackOptions& options,
    Buffer& output,
    U32& fileCount
);
bool OpenContainer(const U8* data, SIZE_T size, ContainerView& output);
bool ExtractContainer(
    const ContainerView& container,
    const wchar_t* outputDirectory,
    const wchar_t* templatePath
);

bool CreateCab(
    const wchar_t* cabPath,
    const wchar_t* payloadPath,
    const char* entryName,
    Buffer& cabData
);
bool ExtractCab(const U8* cabData, SIZE_T cabSize, Buffer& payload);

bool WrapCabInBitmap(const U8* cabData, SIZE_T cabSize, Buffer& bitmap);
bool UnwrapBitmap(const U8* bitmap, SIZE_T bitmapSize, Buffer& cabData);

bool ApplyCabXor(Buffer& cab, XorMode mode, const U8* key, U32 keyLength);
bool UndoCabXor(Buffer& cab, XorMode mode, const U8* key, U32 keyLength);

} // namespace impl
