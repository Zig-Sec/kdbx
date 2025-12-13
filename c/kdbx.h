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

#ifdef __cplusplus
}
#endif
