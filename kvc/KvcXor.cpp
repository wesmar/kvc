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

#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <string>
#include <string_view>
#include <span>
#include <ranges>
#include <algorithm>
#include <filesystem>
#include <optional>
#include <variant>
#include <cstdint>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace fs = std::filesystem;
namespace rng = std::ranges;

// XOR key
constexpr std::array<uint8_t, 7> XOR_KEY = { 0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C };

// File paths
constexpr std::string_view KVC_PASS_EXE = "kvc_pass.exe";
constexpr std::string_view KVC_CRYPT_DLL = "kvc_crypt.dll";
constexpr std::string_view KVC_RAW = "kvc.raw";
constexpr std::string_view KVC_DAT = "kvc.dat";
constexpr std::string_view KVC_EXE = "kvc.exe";
constexpr std::string_view KVC_ENC = "kvc.enc";

// Helper for string concatenation (replaces std::format)
inline std::string concat(std::string_view a) {
    return std::string(a);
}

inline std::string concat(std::string_view a, std::string_view b) {
    std::string result;
    result.reserve(a.size() + b.size());
    result.append(a);
    result.append(b);
    return result;
}

inline std::string concat(std::string_view a, std::string_view b, std::string_view c) {
    std::string result;
    result.reserve(a.size() + b.size() + c.size());
    result.append(a);
    result.append(b);
    result.append(c);
    return result;
}

inline std::string concat(std::string_view a, std::string_view b, std::string_view c, std::string_view d) {
    std::string result;
    result.reserve(a.size() + b.size() + c.size() + d.size());
    result.append(a);
    result.append(b);
    result.append(c);
    result.append(d);
    return result;
}

inline std::string concat(std::string_view a, std::string_view b, std::string_view c, 
                         std::string_view d, std::string_view e) {
    std::string result;
    result.reserve(a.size() + b.size() + c.size() + d.size() + e.size());
    result.append(a);
    result.append(b);
    result.append(c);
    result.append(d);
    result.append(e);
    return result;
}

inline std::string concat(std::string_view a, std::string_view b, std::string_view c, 
                         std::string_view d, std::string_view e, std::string_view f) {
    std::string result;
    result.reserve(a.size() + b.size() + c.size() + d.size() + e.size() + f.size());
    result.append(a);
    result.append(b);
    result.append(c);
    result.append(d);
    result.append(e);
    result.append(f);
    return result;
}

inline std::string concat(std::string_view a, std::string_view b, std::string_view c, 
                         std::string_view d, std::string_view e, std::string_view f,
                         std::string_view g) {
    std::string result;
    result.reserve(a.size() + b.size() + c.size() + d.size() + e.size() + f.size() + g.size());
    result.append(a);
    result.append(b);
    result.append(c);
    result.append(d);
    result.append(e);
    result.append(f);
    result.append(g);
    return result;
}

// Simple Result type (replacement for std::expected which MSVC doesn't fully support yet)
template<typename T>
class Result {
    std::variant<T, std::string> data;
    
public:
    Result(T value) : data(std::move(value)) {}
    Result(std::string error) : data(std::move(error)) {}
    
    bool has_value() const { return std::holds_alternative<T>(data); }
    explicit operator bool() const { return has_value(); }
    
    T& value() { return std::get<T>(data); }
    const T& value() const { return std::get<T>(data); }
    
    const std::string& error() const { return std::get<std::string>(data); }
    
    T* operator->() { return &std::get<T>(data); }
    const T* operator->() const { return &std::get<T>(data); }
};

// Specialization for void
template<>
class Result<void> {
    std::optional<std::string> error_msg;
    
public:
    Result() : error_msg(std::nullopt) {}
    Result(std::string error) : error_msg(std::move(error)) {}
    
    bool has_value() const { return !error_msg.has_value(); }
    explicit operator bool() const { return has_value(); }
    
    const std::string& error() const { return *error_msg; }
};

// Console colors
enum class Color : int {
    Default = 7,
    Green = 10,
    Red = 12,
    Yellow = 14
};

void set_color(Color color) {
#ifdef _WIN32
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<int>(color));
#else
    switch (color) {
        case Color::Green:   std::cout << "\033[32m"; break;
        case Color::Red:     std::cout << "\033[31m"; break;
        case Color::Yellow:  std::cout << "\033[33m"; break;
        case Color::Default: std::cout << "\033[0m";  break;
    }
#endif
}

void reset_color() {
    set_color(Color::Default);
}

// RAII color guard
class ColorGuard {
public:
    explicit ColorGuard(Color new_color) {
        set_color(new_color);
    }
    ~ColorGuard() {
        reset_color();
    }
    ColorGuard(const ColorGuard&) = delete;
    ColorGuard& operator=(const ColorGuard&) = delete;
};

// XOR operation
void xor_data(std::span<uint8_t> data, std::span<const uint8_t> key) noexcept {
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.size()];
    }
}

// Read entire file into vector
Result<std::vector<uint8_t>> read_file(const fs::path& path) {
    if (!fs::exists(path)) {
        return Result<std::vector<uint8_t>>(
            concat("File '", path.string(), "' does not exist")
        );
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return Result<std::vector<uint8_t>>(
            concat("Cannot open file '", path.string(), "'")
        );
    }

    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    return data;
}

// Write data to file
Result<void> write_file(const fs::path& path, std::span<const uint8_t> data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return Result<void>(
            concat("Cannot create file '", path.string(), "'")
        );
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    
    if (!file) {
        return Result<void>(
            concat("Error writing to file '", path.string(), "'")
        );
    }

    return Result<void>();
}

// Helper to read uint16_t from buffer
constexpr uint16_t read_uint16(std::span<const uint8_t> data, size_t offset) {
    return static_cast<uint16_t>(data[offset]) | 
           (static_cast<uint16_t>(data[offset + 1]) << 8);
}

// Helper to read uint32_t from buffer
constexpr uint32_t read_uint32(std::span<const uint8_t> data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) | 
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) |
           (static_cast<uint32_t>(data[offset + 3]) << 24);
}

// Determine PE file length from buffer
std::optional<size_t> get_pe_file_length(std::span<const uint8_t> data, size_t offset = 0) noexcept {
    try {
        // Check if we have enough data for DOS header
        if (data.size() < offset + 0x40) {
            return std::nullopt;
        }

        // Check for MZ signature
        if (data[offset] != 'M' || data[offset + 1] != 'Z') {
            return std::nullopt;
        }

        // Get e_lfanew from offset 0x3C
        const uint32_t e_lfanew = read_uint32(data, offset + 0x3C);
        const size_t pe_header_offset = offset + e_lfanew;

        // Check if we have enough data for PE header
        if (pe_header_offset + 6 > data.size()) {
            return std::nullopt;
        }

        // Check for PE signature
        if (data[pe_header_offset] != 'P' || data[pe_header_offset + 1] != 'E' ||
            data[pe_header_offset + 2] != 0 || data[pe_header_offset + 3] != 0) {
            return std::nullopt;
        }

        // Get number of sections and size of optional header
        const uint16_t number_of_sections = read_uint16(data, pe_header_offset + 6);
        const uint16_t size_of_optional_header = read_uint16(data, pe_header_offset + 20);

        // Calculate section table offset
        const size_t section_table_offset = pe_header_offset + 24 + size_of_optional_header;

        // Check if we have enough data for section table
        if (section_table_offset + number_of_sections * 40 > data.size()) {
            return std::nullopt;
        }

        // Find the maximum end of section raw data
        size_t max_end = 0;
        for (uint16_t i = 0; i < number_of_sections; ++i) {
            const size_t sh_offset = section_table_offset + i * 40;

            const uint32_t size_of_raw = read_uint32(data, sh_offset + 16);
            const uint32_t pointer_to_raw = read_uint32(data, sh_offset + 20);

            if (pointer_to_raw == 0) continue;

            const size_t end = pointer_to_raw + size_of_raw;
            max_end = std::max(max_end, end);
        }

        // If we found section data, use it
        if (max_end > 0) {
            const size_t header_end = section_table_offset + number_of_sections * 40;
            return std::max(max_end, header_end);
        }

        // Fallback: Use SizeOfHeaders from optional header
        const size_t optional_header_offset = pe_header_offset + 24;
        if (optional_header_offset + 64 <= data.size()) {
            const uint32_t size_of_headers = read_uint32(data, optional_header_offset + 60);
            if (size_of_headers > 0) {
                return size_of_headers;
            }
        }
    }
    catch (...) {
        return std::nullopt;
    }

    return std::nullopt;
}

// Find next MZ header in buffer
std::optional<size_t> find_next_mz_header(std::span<const uint8_t> data, size_t start_offset) {
    constexpr std::array<uint8_t, 2> pattern = { 'M', 'Z' };
    
    auto search_range = rng::subrange(
        data.begin() + start_offset,
        data.end()
    );

    auto result = rng::search(search_range, pattern);
    
    if (result.empty()) {
        return std::nullopt;
    }

    return std::distance(data.begin(), result.begin());
}

// Ask user Y/N question
bool ask_yes_no(std::string_view question) {
    std::cout << question << " (Y/N): ";
    std::string answer;
    std::getline(std::cin, answer);
    
    return !answer.empty() && (answer[0] == 'Y' || answer[0] == 'y');
}

// Encode files: kvc_pass.exe + kvc_crypt.dll -> kvc.raw + kvc.dat
Result<void> encode_files() {
    std::cout << "Step 1: Encoding " << KVC_PASS_EXE << " + " << KVC_CRYPT_DLL << "...\n";
    
    // Read both files
    auto exe_result = read_file(KVC_PASS_EXE);
    if (!exe_result) {
        return Result<void>(exe_result.error());
    }

    auto dll_result = read_file(KVC_CRYPT_DLL);
    if (!dll_result) {
        return Result<void>(dll_result.error());
    }

    // Combine files
    std::vector<uint8_t> combined_data;
    combined_data.reserve(exe_result->size() + dll_result->size());
    combined_data.insert(combined_data.end(), exe_result->begin(), exe_result->end());
    combined_data.insert(combined_data.end(), dll_result->begin(), dll_result->end());

    // Write raw file
    if (auto result = write_file(KVC_RAW, combined_data); !result) {
        return result;
    }

    // XOR encode the data
    xor_data(combined_data, XOR_KEY);

    // Write encoded file
    if (auto result = write_file(KVC_DAT, combined_data); !result) {
        return result;
    }

    std::cout << "  -> Files combined -> " << KVC_RAW << "\n";
    std::cout << "  -> Combined file XOR-encoded -> " << KVC_DAT << "\n";
    
    return Result<void>();
}

// Decode files: kvc.dat -> kvc.raw + kvc_pass.exe + kvc_crypt.dll
Result<void> decode_files() {
    std::cout << "Decoding " << KVC_DAT << "...\n";
    
    auto enc_result = read_file(KVC_DAT);
    if (!enc_result) {
        return Result<void>(enc_result.error());
    }

    // XOR decode the data
    std::vector<uint8_t> dec_data = std::move(enc_result.value());
    xor_data(dec_data, XOR_KEY);

    // Write decoded raw file
    if (auto result = write_file(KVC_RAW, dec_data); !result) {
        return result;
    }

    // Try to determine the exact size of the first PE file
    auto first_size = get_pe_file_length(dec_data, 0);

    // Fallback if PE parsing failed
    if (!first_size || *first_size >= dec_data.size()) {
        std::cout << "  -> PE parsing failed, using fallback search for MZ header...\n";

        const size_t search_start = std::min<size_t>(0x200, dec_data.size() - 1);
        first_size = find_next_mz_header(dec_data, search_start);

        if (!first_size) {
            // Ultimate fallback: don't split
            first_size = dec_data.size();
        }
    }

    // Split the files
    if (auto result = write_file(KVC_PASS_EXE, std::span(dec_data.data(), *first_size)); !result) {
        return result;
    }

    if (auto result = write_file(KVC_CRYPT_DLL, std::span(dec_data.data() + *first_size, dec_data.size() - *first_size)); !result) {
        return result;
    }

    std::cout << "  -> Decoded -> " << KVC_RAW << "\n";
    std::cout << "  -> Split into " << KVC_PASS_EXE << " and " << KVC_CRYPT_DLL << "\n";
    
    return Result<void>();
}

// Build distribution package: kvc.exe + kvc.dat -> kvc.enc
Result<void> build_distribution() {
    std::cout << "Building distribution package...\n";
    
    // Check if kvc.dat exists
    if (!fs::exists(KVC_DAT)) {
        std::cout << "  -> " << KVC_DAT << " not found.\n";
        
        // Check if source files exist
        if (!fs::exists(KVC_PASS_EXE) || !fs::exists(KVC_CRYPT_DLL)) {
            return Result<void>(
                concat("Cannot create ", KVC_DAT, ": missing ", KVC_PASS_EXE, " or ", KVC_CRYPT_DLL)
            );
        }

        // Ask if we should create it
        if (ask_yes_no(concat("Create ", KVC_DAT, " from ", KVC_PASS_EXE, " and ", KVC_CRYPT_DLL, "?"))) {
            if (auto result = encode_files(); !result) {
                return result;
            }
        } else {
            return Result<void>("Operation cancelled by user");
        }
    }

    // Read both files
    auto exe_result = read_file(KVC_EXE);
    if (!exe_result) {
        return Result<void>(exe_result.error());
    }

    auto dat_result = read_file(KVC_DAT);
    if (!dat_result) {
        return Result<void>(dat_result.error());
    }

    // Combine files
    std::vector<uint8_t> combined_data;
    combined_data.reserve(exe_result->size() + dat_result->size());
    combined_data.insert(combined_data.end(), exe_result->begin(), exe_result->end());
    combined_data.insert(combined_data.end(), dat_result->begin(), dat_result->end());

    // XOR encode the combined data
    xor_data(combined_data, XOR_KEY);

    // Write encoded distribution file
    if (auto result = write_file(KVC_ENC, combined_data); !result) {
        return result;
    }

    std::cout << "  -> Distribution package created -> " << KVC_ENC << "\n";
    std::cout << "  -> Ready for remote deployment!\n";
    
    return Result<void>();
}

// Decode distribution package: kvc.enc -> kvc.exe + kvc.dat
Result<void> decode_distribution() {
    std::cout << "Decoding distribution package...\n";
    
    auto enc_result = read_file(KVC_ENC);
    if (!enc_result) {
        return Result<void>(enc_result.error());
    }

    // XOR decode the data
    std::vector<uint8_t> dec_data = std::move(enc_result.value());
    xor_data(dec_data, XOR_KEY);

    // Try to determine the exact size of kvc.exe
    auto exe_size = get_pe_file_length(dec_data, 0);

    // Fallback if PE parsing failed
    if (!exe_size || *exe_size >= dec_data.size()) {
        std::cout << "  -> PE parsing failed, using fallback search for MZ header...\n";

        const size_t search_start = std::min<size_t>(0x200, dec_data.size() - 1);
        exe_size = find_next_mz_header(dec_data, search_start);

        if (!exe_size) {
            // Ultimate fallback: use half
            exe_size = dec_data.size() / 2;
        }
    }

    // Split the files
    if (auto result = write_file(KVC_EXE, std::span(dec_data.data(), *exe_size)); !result) {
        return result;
    }

    if (auto result = write_file(KVC_DAT, std::span(dec_data.data() + *exe_size, dec_data.size() - *exe_size)); !result) {
        return result;
    }

    std::cout << "  -> Distribution package decoded -> " << KVC_EXE << " + " << KVC_DAT << "\n";
    
    return Result<void>();
}

// Decode everything: kvc.enc -> kvc.exe + kvc_pass.exe + kvc_crypt.dll
Result<void> decode_everything() {
    std::cout << "Complete decoding of distribution package...\n";
    
    // Check if kvc.enc exists
    if (!fs::exists(KVC_ENC)) {
        std::cout << "  -> " << KVC_ENC << " not found.\n";
        
        // Check if we can create it from existing files
        if (fs::exists(KVC_EXE) && fs::exists(KVC_DAT)) {
            if (ask_yes_no(concat("Create ", KVC_ENC, " from ", KVC_EXE, " and ", KVC_DAT, "?"))) {
                if (auto result = build_distribution(); !result) {
                    return result;
                }
            } else {
                return Result<void>("Operation cancelled by user");
            }
        } else {
            return Result<void>(concat("File '", KVC_ENC, "' does not exist"));
        }
    }

    auto enc_result = read_file(KVC_ENC);
    if (!enc_result) {
        return Result<void>(enc_result.error());
    }

    // XOR decode the data
    std::vector<uint8_t> dec_data = std::move(enc_result.value());
    xor_data(dec_data, XOR_KEY);

    // Find first PE file (kvc.exe)
    auto first_pe_size = get_pe_file_length(dec_data, 0);
    
    if (!first_pe_size || *first_pe_size >= dec_data.size()) {
        return Result<void>("Cannot determine first PE file size");
    }

    // Extract kvc.exe
    std::vector<uint8_t> kvc_exe_data(dec_data.begin(), dec_data.begin() + *first_pe_size);
    
    // The remaining data should be kvc.dat
    std::vector<uint8_t> kvc_dat_data(dec_data.begin() + *first_pe_size, dec_data.end());
    
    // Decode kvc.dat to get kvc_pass.exe and kvc_crypt.dll
    xor_data(kvc_dat_data, XOR_KEY);
    
    // Find the PE file in kvc.dat (kvc_pass.exe)
    auto second_pe_size = get_pe_file_length(kvc_dat_data, 0);
    
    if (!second_pe_size || *second_pe_size >= kvc_dat_data.size()) {
        return Result<void>("Cannot determine second PE file size in kvc.dat");
    }

    // Write all files
    if (auto result = write_file(KVC_EXE, kvc_exe_data); !result) {
        return result;
    }

    if (auto result = write_file(KVC_PASS_EXE, std::span(kvc_dat_data.data(), *second_pe_size)); !result) {
        return result;
    }

    if (auto result = write_file(KVC_CRYPT_DLL, std::span(kvc_dat_data.data() + *second_pe_size, kvc_dat_data.size() - *second_pe_size)); !result) {
        return result;
    }

    std::cout << "  -> Complete decoding successful!\n";
    std::cout << "  -> Extracted: " << KVC_EXE << ", " << KVC_PASS_EXE << ", " << KVC_CRYPT_DLL << "\n";
    
    return Result<void>();
}

// Display menu
void display_menu() {
    std::cout << "==================================================\n";
    std::cout << "|           FILE ENCODER/DECODER TOOL           |\n";
    std::cout << "==================================================\n";
    std::cout << "| 1. ENCODE: kvc_pass.exe + kvc_crypt.dll       |\n";
    std::cout << "|               -> kvc.raw + kvc.dat            |\n";
    std::cout << "| 2. DECODE: kvc.dat -> kvc.raw +               |\n";
    std::cout << "|               kvc_pass.exe + kvc_crypt.dll    |\n";
    std::cout << "| 3. BUILD DISTRIBUTION: kvc.exe + kvc.dat      |\n";
    std::cout << "|               -> kvc.enc                      |\n";
    std::cout << "| 4. DECODE DISTRIBUTION: kvc.enc ->            |\n";
    std::cout << "|               kvc.exe + kvc.dat               |\n";
    std::cout << "| 5. DECODE EVERYTHING: kvc.enc ->              |\n";
    std::cout << "|               kvc.exe + kvc_pass.exe +        |\n";
    std::cout << "|               kvc_crypt.dll                   |\n";
    std::cout << "==================================================\n\n";
    std::cout << "kvc.enc is used for remote installation via command:\n";
    
    ColorGuard green(Color::Green);
    std::cout << "irm https://kvc.pl/run | iex\n\n";
}

int main() {
    display_menu();
    std::cout << "Select operation (1-5): ";

    int choice;
    std::cin >> choice;
    std::cin.ignore(); // Clear newline from buffer

    Result<void> result = Result<void>("Invalid choice");

    switch (choice) {
        case 1: result = encode_files(); break;
        case 2: result = decode_files(); break;
        case 3: result = build_distribution(); break;
        case 4: result = decode_distribution(); break;
        case 5: result = decode_everything(); break;
        default:
            ColorGuard red(Color::Red);
            std::cerr << "Invalid choice. Please select 1-5.\n";
            return 1;
    }

    if (!result) {
        ColorGuard red(Color::Red);
        std::cerr << "Error: " << result.error() << "\n";
        return 1;
    }

    return 0;
}