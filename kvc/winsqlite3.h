/* Windows SQLite3 header - Professional interface for winsqlite3.dll */
#ifndef WINSQLITE3_H
#define WINSQLITE3_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Windows SQLite3 Library Interface
 * 
 * This header provides interface definitions for Microsoft's built-in
 * SQLite3 implementation (winsqlite3.dll) available in Windows 10/11.
 * 
 * The API is fully compatible with standard SQLite3 but uses the
 * system-provided library for enhanced security and maintenance.
 */

/* SQLite3 Core Types */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int64_t sqlite3_int64;

/* SQLite3 Result Codes */
#define SQLITE_OK           0   /* Successful result */
#define SQLITE_ROW          100 /* Step has another row ready */

/* SQLite3 Open Flags */
#define SQLITE_OPEN_READONLY    0x00000001  /* Read-only database */
#define SQLITE_OPEN_URI         0x00000040  /* URI filename interpretation */

/* Windows SQLite3 Function Declarations */

/**
 * Open a database connection with extended parameters
 * @param filename Database file path or URI
 * @param ppDb Output parameter for database handle
 * @param flags Open flags (SQLITE_OPEN_*)
 * @param zVfs VFS module name (usually NULL)
 * @return SQLITE_OK on success
 */
__declspec(dllimport) int sqlite3_open_v2(
    const char *filename,
    sqlite3 **ppDb,
    int flags,
    const char *zVfs
);

/**
 * Close database connection (enhanced version)
 * @param db Database handle to close
 * @return SQLITE_OK on success
 */
__declspec(dllimport) int sqlite3_close_v2(sqlite3 *db);

/**
 * Prepare SQL statement for execution
 * @param db Database handle
 * @param zSql SQL statement text
 * @param nByte Length of SQL text (-1 for null-terminated)
 * @param ppStmt Output parameter for prepared statement
 * @param pzTail Pointer to unused portion of zSql
 * @return SQLITE_OK on success
 */
__declspec(dllimport) int sqlite3_prepare_v2(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);

/**
 * Execute one step of prepared statement
 * @param pStmt Prepared statement handle
 * @return SQLITE_ROW if row available, SQLITE_OK if done
 */
__declspec(dllimport) int sqlite3_step(sqlite3_stmt *pStmt);

/**
 * Finalize and destroy prepared statement
 * @param pStmt Prepared statement handle
 * @return SQLITE_OK on success
 */
__declspec(dllimport) int sqlite3_finalize(sqlite3_stmt *pStmt);

/* Column Data Access Functions */

/**
 * Get column value as text
 * @param pStmt Prepared statement handle
 * @param iCol Column index (0-based)
 * @return Pointer to UTF-8 text data
 */
__declspec(dllimport) const unsigned char *sqlite3_column_text(
    sqlite3_stmt *pStmt,
    int iCol
);

/**
 * Get column value as binary blob
 * @param pStmt Prepared statement handle
 * @param iCol Column index (0-based)
 * @return Pointer to binary data
 */
__declspec(dllimport) const void *sqlite3_column_blob(
    sqlite3_stmt *pStmt,
    int iCol
);

/**
 * Get size of column data in bytes
 * @param pStmt Prepared statement handle
 * @param iCol Column index (0-based)
 * @return Size in bytes
 */
__declspec(dllimport) int sqlite3_column_bytes(
    sqlite3_stmt *pStmt,
    int iCol
);

/**
 * Get column value as 32-bit integer
 * @param pStmt Prepared statement handle
 * @param iCol Column index (0-based)
 * @return Integer value
 */
__declspec(dllimport) int sqlite3_column_int(
    sqlite3_stmt *pStmt,
    int iCol
);

/**
 * Get column value as 64-bit integer
 * @param pStmt Prepared statement handle
 * @param iCol Column index (0-based)
 * @return 64-bit integer value
 */
__declspec(dllimport) sqlite3_int64 sqlite3_column_int64(
    sqlite3_stmt *pStmt,
    int iCol
);

/* Error Handling */

/**
 * Get last error message for database connection
 * @param db Database handle
 * @return UTF-8 encoded error message
 */
__declspec(dllimport) const char *sqlite3_errmsg(sqlite3 *db);

#ifdef __cplusplus
}
#endif

#endif /* WINSQLITE3_H */