#include "core.h"

namespace impl {

namespace {

U32 IntegerSquareRoot(U64 value) noexcept {
    U32 result = 0;
    U32 bit = 1u << 30;
    while (bit > value) bit >>= 2;
    while (bit != 0) {
        if (value >= static_cast<U64>(result) + bit) {
            value -= static_cast<U64>(result) + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    return result;
}

void WriteU16(U8* destination, U16 value) noexcept {
    destination[0] = static_cast<U8>(value);
    destination[1] = static_cast<U8>(value >> 8);
}

void WriteU32(U8* destination, U32 value) noexcept {
    destination[0] = static_cast<U8>(value);
    destination[1] = static_cast<U8>(value >> 8);
    destination[2] = static_cast<U8>(value >> 16);
    destination[3] = static_cast<U8>(value >> 24);
}

U16 ReadU16(const U8* source) noexcept {
    return static_cast<U16>(
        static_cast<U16>(source[0])
        | (static_cast<U16>(source[1]) << 8)
    );
}

U32 ReadU32(const U8* source) noexcept {
    return static_cast<U32>(source[0])
        | (static_cast<U32>(source[1]) << 8)
        | (static_cast<U32>(source[2]) << 16)
        | (static_cast<U32>(source[3]) << 24);
}

} // namespace

bool WrapCabInBitmap(const U8* cabData, SIZE_T cabSize, Buffer& bitmap) {
    if (!cabData || cabSize < 4 || cabSize > 0xFFFFFFFFull) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    const U64 pixelCount = (cabSize + 2) / 3;
    U32 width = IntegerSquareRoot(pixelCount);
    if (width == 0) width = 4;
    width = (width + 3) & ~3u;
    U32 height = static_cast<U32>((pixelCount + width - 1) / width);
    if (height == 0) height = 1;

    const U64 imageSize64 = static_cast<U64>(width) * height * 3;
    if (imageSize64 > 0xFFFFFFFFull - 54) {
        SetLastError(ERROR_FILE_TOO_LARGE);
        return false;
    }
    const U32 imageSize = static_cast<U32>(imageSize64);
    const U32 totalSize = 54 + imageSize;

    if (!bitmap.Resize(totalSize)) {
        if (GetLastError() == ERROR_SUCCESS) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    memset(bitmap.data, 0, bitmap.size);

    bitmap.data[0] = 'B';
    bitmap.data[1] = 'M';
    WriteU32(bitmap.data + 2, totalSize);
    WriteU32(bitmap.data + 6, static_cast<U32>(cabSize));
    WriteU32(bitmap.data + 10, 54);

    WriteU32(bitmap.data + 14, 40);
    WriteU32(bitmap.data + 18, width);
    WriteU32(bitmap.data + 22, height);
    WriteU16(bitmap.data + 26, 1);
    WriteU16(bitmap.data + 28, 24);
    WriteU32(bitmap.data + 30, 0);
    WriteU32(bitmap.data + 34, imageSize);
    WriteU32(bitmap.data + 38, 2835);
    WriteU32(bitmap.data + 42, 2835);
    WriteU32(bitmap.data + 46, 0);
    // RT_BITMAP stores only the DIB and drops BITMAPFILEHEADER. Preserve the
    // CAB length in biClrImportant, which is unused for uncompressed 24-bit RGB.
    WriteU32(bitmap.data + 50, static_cast<U32>(cabSize));

    memcpy(bitmap.data + 54, cabData, cabSize);
    return true;
}

bool UnwrapBitmap(const U8* bitmapData, SIZE_T bitmapSize, Buffer& cabData) {
    if (!bitmapData || bitmapSize < 40) return false;

    U32 cabSize = 0;
    SIZE_T pixelOffset = 0;
    if (bitmapSize >= 54 && bitmapData[0] == 'B' && bitmapData[1] == 'M') {
        cabSize = ReadU32(bitmapData + 6);
        pixelOffset = ReadU32(bitmapData + 10);
        const U32 declaredSize = ReadU32(bitmapData + 2);
        if (declaredSize > bitmapSize) return false;
    } else {
        const U32 dibSize = ReadU32(bitmapData);
        const U16 bitsPerPixel = ReadU16(bitmapData + 14);
        const U32 compression = ReadU32(bitmapData + 16);
        const U32 colorsUsed = ReadU32(bitmapData + 32);
        if (dibSize < 40 || dibSize > bitmapSize
            || bitsPerPixel != 24 || compression != 0
            || colorsUsed > (bitmapSize - dibSize) / 4) {
            return false;
        }
        cabSize = ReadU32(bitmapData + 36);
        pixelOffset = static_cast<SIZE_T>(dibSize)
            + static_cast<SIZE_T>(colorsUsed) * 4;
    }

    if (cabSize < 4 || pixelOffset > bitmapSize
        || cabSize > bitmapSize - pixelOffset) {
        return false;
    }

    if (!cabData.Resize(cabSize)) return false;
    memcpy(cabData.data, bitmapData + pixelOffset, cabSize);
    return true;
}

bool ApplyCabXor(
    Buffer& cab,
    XorMode mode,
    const U8* key,
    U32 keyLength
) {
    if (!cab.data || cab.size < 4) return false;
    switch (mode) {
    case XorMode::None:
        return true;
    case XorMode::MaskMagic:
        for (SIZE_T index = 0; index < 4; ++index) {
            cab.data[index] ^= kMaskedCabMagic[index];
        }
        return true;
    case XorMode::FullCab:
        if (!key || keyLength == 0 || keyLength > 256) return false;
        for (SIZE_T index = 0; index < cab.size; ++index) {
            cab.data[index] ^= key[index % keyLength];
        }
        return true;
    default:
        return false;
    }
}

bool UndoCabXor(
    Buffer& cab,
    XorMode mode,
    const U8* key,
    U32 keyLength
) {
    if (!ApplyCabXor(cab, mode, key, keyLength)) return false;
    return cab.size >= 4
        && cab.data[0] == 'M'
        && cab.data[1] == 'S'
        && cab.data[2] == 'C'
        && cab.data[3] == 'F';
}

} // namespace impl
