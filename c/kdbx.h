#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define KDBX_ENOENT 2       // No such file or directory
#define KDBX_EIO 5          // Input/ output error
#define KDBX_ENOMEM 12      // Cannot allocate memory
#define KDBX_EACCES 13      // Permission denied

/*
 * Open a KDBX database using a password.
 *
 * On success, the function will populate db with a database instance and return 0.
 * On error, a non-zero error value is returned.
 */
extern int kdbx_open_with_password(void** db, uint8_t* path, size_t pathLen, uint8_t* pw, size_t pwLen);

/*
 * Close a KDBX database.
 * 
 * The passed database db must be valid.
 *
 * The function will always return success (0).
 */
extern int kdbx_close(void* db);

/*
 * Get the group specified by `path`.
 *
 * On success, the function will assign the group specified by `path` to `group`.
 * On error, a non-zero error value is returned.
 */
extern int kdbx_db_get_group(void** group, void* db, uint8_t* path, size_t pathLen);

/*
 * Get the entry of the `group` that matches the `value` for the given `key`.
 *
 * On success, the matching entry is assigned to `entry`.
 * On error, a non-zero error value is returned.
 */
extern int kdbx_group_get_entry_by_key(void** entry, void* group, uint8_t* key, size_t keyLen, uint8_t* value, size_t valueLen);

/*
 * Get the value for the specified `key`.
 *
 * On success, the function will return the value as null-terminated string.
 * Depending on the type of data returned, it might be base64 encoded.
 * The caller is responsible for freeing the string.
 *
 * On error, the function will return null.
 */
extern uint8_t* kdbx_entry_get_value(void* entry, uint8_t* key, size_t keyLen);

#ifdef __cplusplus
}
#endif
