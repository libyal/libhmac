/*
 * Library to support support file format date and time values
 *
 * Copyright (C) 2011-2023, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#if !defined( _LIBHMAC_H )
#define _LIBHMAC_H

#include <libhmac/definitions.h>
#include <libhmac/error.h>
#include <libhmac/extern.h>
#include <libhmac/features.h>
#include <libhmac/types.h>

#include <stdio.h>

#if defined( __cplusplus )
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Support functions
 * ------------------------------------------------------------------------- */

/* Returns the library version
 */
LIBHMAC_EXTERN \
const char *libhmac_get_version(
             void );

/* -------------------------------------------------------------------------
 * Error functions
 * ------------------------------------------------------------------------- */

/* Frees an error
 */
LIBHMAC_EXTERN \
void libhmac_error_free(
      libhmac_error_t **error );

/* Prints a descriptive string of the error to the stream
 * Returns the amount of printed characters if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_error_fprint(
     libhmac_error_t *error,
     FILE *stream );

/* Prints a descriptive string of the error to the string
 * The end-of-string character is not included in the return value
 * Returns the amount of printed characters if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_error_sprint(
     libhmac_error_t *error,
     char *string,
     size_t size );

/* Prints a backtrace of the error to the stream
 * Returns the amount of printed characters if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_error_backtrace_fprint(
     libhmac_error_t *error,
     FILE *stream );

/* Prints a backtrace of the error to the string
 * The end-of-string character is not included in the return value
 * Returns the amount of printed characters if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_error_backtrace_sprint(
     libhmac_error_t *error,
     char *string,
     size_t size );

/* -------------------------------------------------------------------------
 * MD5 context functions
 * ------------------------------------------------------------------------- */

/* Creates a MD5 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_md5_context_initialize(
     libhmac_md5_context_t **context,
     libhmac_error_t **error );

/* Frees a MD5 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_md5_context_free(
     libhmac_md5_context_t **context,
     libhmac_error_t **error );

/* Updates the MD5 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_md5_context_update(
     libhmac_md5_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the MD5 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_md5_context_finalize(
     libhmac_md5_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * MD5 functions
 * ------------------------------------------------------------------------- */

/* Creates a MD5 context
 *
 * This function is deprecates use libhmac_md5_context_initialize instead
 *
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_md5_initialize(
     libhmac_md5_context_t **context,
     libhmac_error_t **error );

/* Frees a MD5 context
 *
 * This function is deprecates use libhmac_md5_context_free instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_md5_free(
     libhmac_md5_context_t **context,
     libhmac_error_t **error );

/* Updates the MD5 context
 *
 * This function is deprecates use libhmac_md5_context_update instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_md5_update(
     libhmac_md5_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the MD5 context
 *
 * This function is deprecates use libhmac_md5_context_finalize instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_md5_finalize(
     libhmac_md5_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the MD5 of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_md5_calculate(
     const uint8_t *buffer,
     size_t size,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the MD5 HMAC of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_md5_calculate_hmac(
     const uint8_t *key,
     size_t key_size,
     const uint8_t *buffer,
     size_t size,
     uint8_t *hmac,
     size_t hmac_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * SHA1 context functions
 * ------------------------------------------------------------------------- */

/* Creates a SHA1 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha1_context_initialize(
     libhmac_sha1_context_t **context,
     libhmac_error_t **error );

/* Frees a SHA1 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha1_context_free(
     libhmac_sha1_context_t **context,
     libhmac_error_t **error );

/* Updates the SHA1 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha1_context_update(
     libhmac_sha1_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the SHA1 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha1_context_finalize(
     libhmac_sha1_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * SHA1 functions
 * ------------------------------------------------------------------------- */

/* Creates a SHA1 context
 *
 * This function is deprecates use libhmac_sha1_context_initialize instead
 *
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha1_initialize(
     libhmac_sha1_context_t **context,
     libhmac_error_t **error );

/* Frees a SHA1 context
 *
 * This function is deprecates use libhmac_sha1_context_free instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha1_free(
     libhmac_sha1_context_t **context,
     libhmac_error_t **error );

/* Updates the SHA1 context
 *
 * This function is deprecates use libhmac_sha1_context_update instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha1_update(
     libhmac_sha1_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the SHA1 context
 *
 * This function is deprecates use libhmac_sha1_context_finalize instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha1_finalize(
     libhmac_sha1_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the SHA1 of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha1_calculate(
     const uint8_t *buffer,
     size_t size,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the SHA1 HMAC of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha1_calculate_hmac(
     const uint8_t *key,
     size_t key_size,
     const uint8_t *buffer,
     size_t size,
     uint8_t *hmac,
     size_t hmac_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * SHA-224 context functions
 * ------------------------------------------------------------------------- */

/* Creates a SHA-224 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha224_context_initialize(
     libhmac_sha224_context_t **context,
     libhmac_error_t **error );

/* Frees a SHA-224 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha224_context_free(
     libhmac_sha224_context_t **context,
     libhmac_error_t **error );

/* Updates the SHA-224 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha224_context_update(
     libhmac_sha224_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the SHA-224 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha224_context_finalize(
     libhmac_sha224_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * SHA-224 functions
 * ------------------------------------------------------------------------- */

/* Creates a SHA-224 context
 *
 * This function is deprecates use libhmac_sha224_context_initialize instead
 *
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha224_initialize(
     libhmac_sha224_context_t **context,
     libhmac_error_t **error );

/* Frees a SHA-224 context
 *
 * This function is deprecates use libhmac_sha224_context_free instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha224_free(
     libhmac_sha224_context_t **context,
     libhmac_error_t **error );

/* Updates the SHA-224 context
 *
 * This function is deprecates use libhmac_sha224_context_update instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha224_update(
     libhmac_sha224_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the SHA-224 context
 *
 * This function is deprecates use libhmac_sha224_context_finalize instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha224_finalize(
     libhmac_sha224_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the SHA-224 of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha224_calculate(
     const uint8_t *buffer,
     size_t size,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the SHA-224 HMAC of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha224_calculate_hmac(
     const uint8_t *key,
     size_t key_size,
     const uint8_t *buffer,
     size_t size,
     uint8_t *hmac,
     size_t hmac_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * SHA-256 context functions
 * ------------------------------------------------------------------------- */

/* Creates a SHA-256 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha256_context_initialize(
     libhmac_sha256_context_t **context,
     libhmac_error_t **error );

/* Frees a SHA-256 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha256_context_free(
     libhmac_sha256_context_t **context,
     libhmac_error_t **error );

/* Updates the SHA-256 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha256_context_update(
     libhmac_sha256_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the SHA-256 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha256_context_finalize(
     libhmac_sha256_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * SHA-256 functions
 * ------------------------------------------------------------------------- */

/* Creates a SHA-256 context
 *
 * This function is deprecates use libhmac_sha256_context_initialize instead
 *
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha256_initialize(
     libhmac_sha256_context_t **context,
     libhmac_error_t **error );

/* Frees a SHA-256 context
 *
 * This function is deprecates use libhmac_sha256_context_free instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha256_free(
     libhmac_sha256_context_t **context,
     libhmac_error_t **error );

/* Updates the SHA-256 context
 *
 * This function is deprecates use libhmac_sha256_context_update instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha256_update(
     libhmac_sha256_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the SHA-256 context
 *
 * This function is deprecates use libhmac_sha256_context_finalize instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha256_finalize(
     libhmac_sha256_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the SHA-256 of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha256_calculate(
     const uint8_t *buffer,
     size_t size,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the SHA-256 HMAC of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha256_calculate_hmac(
     const uint8_t *key,
     size_t key_size,
     const uint8_t *buffer,
     size_t size,
     uint8_t *hmac,
     size_t hmac_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * SHA-512 context functions
 * ------------------------------------------------------------------------- */

/* Creates a SHA-512 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha512_context_initialize(
     libhmac_sha512_context_t **context,
     libhmac_error_t **error );

/* Frees a SHA-512 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha512_context_free(
     libhmac_sha512_context_t **context,
     libhmac_error_t **error );

/* Updates the SHA-512 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha512_context_update(
     libhmac_sha512_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the SHA-512 context
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha512_context_finalize(
     libhmac_sha512_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* -------------------------------------------------------------------------
 * SHA-512 functions
 * ------------------------------------------------------------------------- */

/* Creates a SHA-512 context
 *
 * This function is deprecates use libhmac_sha512_context_initialize instead
 *
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha512_initialize(
     libhmac_sha512_context_t **context,
     libhmac_error_t **error );

/* Frees a SHA-512 context
 *
 * This function is deprecates use libhmac_sha512_context_free instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha512_free(
     libhmac_sha512_context_t **context,
     libhmac_error_t **error );

/* Updates the SHA-512 context
 *
 * This function is deprecates use libhmac_sha512_context_update instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha512_update(
     libhmac_sha512_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libhmac_error_t **error );

/* Finalizes the SHA-512 context
 *
 * This function is deprecates use libhmac_sha512_context_finalize instead
 *
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_DEPRECATED \
LIBHMAC_EXTERN \
int libhmac_sha512_finalize(
     libhmac_sha512_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the SHA-512 of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha512_calculate(
     const uint8_t *buffer,
     size_t size,
     uint8_t *hash,
     size_t hash_size,
     libhmac_error_t **error );

/* Calculates the SHA-512 HMAC of the buffer
 * Returns 1 if successful or -1 on error
 */
LIBHMAC_EXTERN \
int libhmac_sha512_calculate_hmac(
     const uint8_t *key,
     size_t key_size,
     const uint8_t *buffer,
     size_t size,
     uint8_t *hmac,
     size_t hmac_size,
     libhmac_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBHMAC_H ) */

