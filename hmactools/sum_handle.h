/*
 * Sum handle
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

#if !defined( _SUM_HANDLE_H )
#define _SUM_HANDLE_H

#include <common.h>
#include <types.h>

#include "hmactools_libcfile.h"
#include "hmactools_libcerror.h"
#include "hmactools_libhmac.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct sum_handle sum_handle_t;

struct sum_handle
{
	/* Input file handle
	 */
	libcfile_file_t *input_handle;

	/* Value to indicate if the MD5 digest hash should be calculated
	 */
	uint8_t calculate_md5;

	/* The MD5 digest context
	 */
	libhmac_md5_context_t *md5_context;

	/* Value to indicate the MD5 digest context was initialized
	 */
	uint8_t md5_context_initialized;

	/* The calculated MD5 digest hash string
	 */
	system_character_t *calculated_md5_hash_string;

	/* Value to indicate if the SHA1 digest hash should be calculated
	 */
	uint8_t calculate_sha1;

	/* The SHA1 digest context
	 */
	libhmac_sha1_context_t *sha1_context;

	/* Value to indicate the SHA1 digest context was initialized
	 */
	uint8_t sha1_context_initialized;

	/* The calculated SHA1 digest hash string
	 */
	system_character_t *calculated_sha1_hash_string;

	/* Value to indicate if the SHA224 digest hash should be calculated
	 */
	uint8_t calculate_sha224;

	/* The SHA224 digest context
	 */
	libhmac_sha224_context_t *sha224_context;

	/* Value to indicate the SHA224 digest context was initialized
	 */
	uint8_t sha224_context_initialized;

	/* The calculated SHA224 digest hash string
	 */
	system_character_t *calculated_sha224_hash_string;

	/* Value to indicate if the SHA256 digest hash should be calculated
	 */
	uint8_t calculate_sha256;

	/* The SHA256 digest context
	 */
	libhmac_sha256_context_t *sha256_context;

	/* Value to indicate the SHA256 digest context was initialized
	 */
	uint8_t sha256_context_initialized;

	/* The calculated SHA256 digest hash string
	 */
	system_character_t *calculated_sha256_hash_string;

	/* Value to indicate if the SHA512 digest hash should be calculated
	 */
	uint8_t calculate_sha512;

	/* The SHA512 digest context
	 */
	libhmac_sha512_context_t *sha512_context;

	/* Value to indicate the SHA512 digest context was initialized
	 */
	uint8_t sha512_context_initialized;

	/* The calculated SHA512 digest hash string
	 */
	system_character_t *calculated_sha512_hash_string;

	/* The process buffer size
	 */
	size_t process_buffer_size;

	/* Value to indicate if abort was signalled
	 */
	int abort;
};

int sum_handle_initialize(
     sum_handle_t **sum_handle,
     libcerror_error_t **error );

int sum_handle_free(
     sum_handle_t **sum_handle,
     libcerror_error_t **error );

int sum_handle_signal_abort(
     sum_handle_t *sum_handle,
     libcerror_error_t **error );

int sum_handle_open_input(
     sum_handle_t *sum_handle,
     const system_character_t *filename,
     libcerror_error_t **error );

int sum_handle_close(
     sum_handle_t *sum_handle,
     libcerror_error_t **error );

ssize_t sum_handle_read_buffer(
         sum_handle_t *sum_handle,
         uint8_t *buffer,
         size_t buffer_size,
         libcerror_error_t **error );

int sum_handle_initialize_integrity_hash(
     sum_handle_t *sum_handle,
     libcerror_error_t **error );

int sum_handle_update_integrity_hash(
     sum_handle_t *sum_handle,
     uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error );

int sum_handle_finalize_integrity_hash(
     sum_handle_t *sum_handle,
     libcerror_error_t **error );

int sum_handle_process_input(
     sum_handle_t *sum_handle,
     libcerror_error_t **error );

int sum_handle_set_digest_types(
     sum_handle_t *sum_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int sum_handle_set_process_buffer_size(
     sum_handle_t *sum_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int sum_handle_hash_values_fprint(
     sum_handle_t *sum_handle,
     FILE *stream,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _SUM_HANDLE_H ) */

