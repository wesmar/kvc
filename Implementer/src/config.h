#pragma once

#include "core.h"

namespace impl {

constexpr U8 kDefaultXorKey[] = {
    0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C
};

struct PackConfig {
    wchar_t iniPath[1024];
    wchar_t baseDirectory[1024];
    wchar_t outputPath[1024];
    wchar_t entryName[128];
    wchar_t templatePath[1024];
    bool stripPe = true;
    XorMode xorMode = XorMode::FullCab;
    U8 xorKey[256]{};
    U32 xorKeyLength = sizeof(kDefaultXorKey);
    InputFileSpec files[kMaxFiles];
    U32 fileCount = 0;
    wchar_t error[256];
    U32 errorLine = 0;
};

bool LoadPackConfig(const wchar_t* iniPath, PackConfig& config);

} // namespace impl
