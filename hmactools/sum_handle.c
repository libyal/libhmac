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

#include <common.h>
#include <memory.h>
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>
#include <wide_string.h>

#include "byte_size_string.h"
#include "digest_hash.h"
#include "hmactools_libhmac.h"
#include "hmactools_libcerror.h"
#include "hmactools_libcfile.h"
#include "hmactools_libcpath.h"
#include "hmactools_libcsplit.h"
#include "hmactools_system_split_string.h"
#include "sum_handle.h"

#define MD5_STRING_SIZE		33
#define SHA1_STRING_SIZE	41
#define SHA224_STRING_SIZE	57
#define SHA256_STRING_SIZE	65
#define SHA512_STRING_SIZE	129

/* Creates a sum handle
 * Make sure the value sum_handle is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int sum_handle_initialize(
     sum_handle_t **sum_handle,
     libcerror_error_t **error )
{
	static char *function = "sum_handle_initialize";

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( *sum_handle != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid sum handle value already set.",
		 function );

		return( -1 );
	}
	*sum_handle = memory_allocate_structure(
	               sum_handle_t );

	if( *sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create sum handle.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *sum_handle,
	     0,
	     sizeof( sum_handle_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear sum handle.",
		 function );

		goto on_error;
	}
	if( libcfile_file_initialize(
	     &( ( *sum_handle )->input_handle ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize input handle.",
		 function );

		goto on_error;
	}
	( *sum_handle )->calculated_md5_hash_string = system_string_allocate(
	                                               MD5_STRING_SIZE );

	if( ( *sum_handle )->calculated_md5_hash_string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create calculated MD5 digest hash string.",
		 function );

		goto on_error;
	}
	( *sum_handle )->calculate_md5       = 1;
	( *sum_handle )->process_buffer_size = 32768;

	return( 1 );

on_error:
	if( *sum_handle != NULL )
	{
		memory_free(
		 *sum_handle );

		*sum_handle = NULL;
	}
	return( -1 );
}

/* Frees a sum handle
 * Returns 1 if successful or -1 on error
 */
int sum_handle_free(
     sum_handle_t **sum_handle,
     libcerror_error_t **error )
{
	static char *function = "sum_handle_free";
	int result            = 1;

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( *sum_handle != NULL )
	{
		if( ( *sum_handle )->md5_context != NULL )
		{
			if( libhmac_md5_context_free(
			     &( ( *sum_handle )->md5_context ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free MD5 context.",
				 function );

				result = -1;
			}
		}
		if( ( *sum_handle )->calculated_md5_hash_string != NULL )
		{
			memory_free(
			 ( *sum_handle )->calculated_md5_hash_string );
		}
		if( ( *sum_handle )->sha1_context != NULL )
		{
			if( libhmac_sha1_context_free(
			     &( ( *sum_handle )->sha1_context ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free SHA1 context.",
				 function );

				result = -1;
			}
		}
		if( ( *sum_handle )->calculated_sha1_hash_string != NULL )
		{
			memory_free(
			 ( *sum_handle )->calculated_sha1_hash_string );
		}
		if( ( *sum_handle )->sha224_context != NULL )
		{
			if( libhmac_sha224_context_free(
			     &( ( *sum_handle )->sha224_context ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free SHA224 context.",
				 function );

				result = -1;
			}
		}
		if( ( *sum_handle )->calculated_sha224_hash_string != NULL )
		{
			memory_free(
			 ( *sum_handle )->calculated_sha224_hash_string );
		}
		if( ( *sum_handle )->sha256_context != NULL )
		{
			if( libhmac_sha256_context_free(
			     &( ( *sum_handle )->sha256_context ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free SHA256 context.",
				 function );

				result = -1;
			}
		}
		if( ( *sum_handle )->calculated_sha256_hash_string != NULL )
		{
			memory_free(
			 ( *sum_handle )->calculated_sha256_hash_string );
		}
		if( ( *sum_handle )->sha512_context != NULL )
		{
			if( libhmac_sha512_context_free(
			     &( ( *sum_handle )->sha512_context ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free SHA512 context.",
				 function );

				result = -1;
			}
		}
		if( ( *sum_handle )->calculated_sha512_hash_string != NULL )
		{
			memory_free(
			 ( *sum_handle )->calculated_sha512_hash_string );
		}
		if( libcfile_file_free(
		     &( ( *sum_handle )->input_handle ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free input handle.",
			 function );

			result = -1;
		}
		memory_free(
		 *sum_handle );

		*sum_handle = NULL;
	}
	return( result );
}

/* Signals the sum handle to abort
 * Returns 1 if successful or -1 on error
 */
int sum_handle_signal_abort(
     sum_handle_t *sum_handle,
     libcerror_error_t **error )
{
	static char *function = "sum_handle_signal_abort";

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	sum_handle->abort = 1;

	return( 1 );
}

/* Opens the input of the sum handle
 * Returns 1 if successful or -1 on error
 */
int sum_handle_open_input(
     sum_handle_t *sum_handle,
     const system_character_t *filename,
     libcerror_error_t **error )
{
	static char *function = "sum_handle_open_input";

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	if( libcfile_file_open_wide(
	     sum_handle->input_handle,
	     filename,
	     LIBCFILE_OPEN_READ,
	     error ) != 1 )
#else
	if( libcfile_file_open(
	     sum_handle->input_handle,
	     filename,
	     LIBCFILE_OPEN_READ,
	     error ) != 1 )
#endif
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to open files.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Closes the sum handle
 * Returns the 0 if succesful or -1 on error
 */
int sum_handle_close(
     sum_handle_t *sum_handle,
     libcerror_error_t **error )
{
	static char *function = "sum_handle_close";

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( libcfile_file_close(
	     sum_handle->input_handle,
	     error ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_CLOSE_FAILED,
		 "%s: unable to close input handle.",
		 function );

		return( -1 );
	}
	return( 0 );
}

/* Reads a buffer from the input of the sum handle
 * Returns the number of bytes written or -1 on error
 */
ssize_t sum_handle_read_buffer(
         sum_handle_t *sum_handle,
         uint8_t *buffer,
         size_t buffer_size,
         libcerror_error_t **error )
{
	static char *function = "sum_handle_read_buffer";
	ssize_t read_count    = 0;

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( buffer_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid buffer size value out of bounds.",
		 function );

		return( -1 );
	}
	read_count = libcfile_file_read_buffer(
                      sum_handle->input_handle,
                      buffer,
                      buffer_size,
	              error );

	if( read_count == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read buffer.",
		 function );

		return( -1 );
	}
	return( read_count );
}

/* Initializes the integrity hash(es)
 * Returns 1 if successful or -1 on error
 */
int sum_handle_initialize_integrity_hash(
     sum_handle_t *sum_handle,
     libcerror_error_t **error )
{
	static char *function = "sum_handle_initialize_integrity_hash";

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( sum_handle->calculate_md5 != 0 )
	{
		if( libhmac_md5_context_initialize(
		     &( sum_handle->md5_context ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to initialize MD5 context.",
			 function );

			goto on_error;
		}
		sum_handle->md5_context_initialized = 1;
	}
	if( sum_handle->calculate_sha1 != 0 )
	{
		if( libhmac_sha1_context_initialize(
		     &( sum_handle->sha1_context ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to initialize SHA1 context.",
			 function );

			goto on_error;
		}
		sum_handle->sha1_context_initialized = 1;
	}
	if( sum_handle->calculate_sha224 != 0 )
	{
		if( libhmac_sha224_context_initialize(
		     &( sum_handle->sha224_context ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to initialize SHA224 context.",
			 function );

			goto on_error;
		}
		sum_handle->sha224_context_initialized = 1;
	}
	if( sum_handle->calculate_sha256 != 0 )
	{
		if( libhmac_sha256_context_initialize(
		     &( sum_handle->sha256_context ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to initialize SHA256 context.",
			 function );

			goto on_error;
		}
		sum_handle->sha256_context_initialized = 1;
	}
	if( sum_handle->calculate_sha512 != 0 )
	{
		if( libhmac_sha512_context_initialize(
		     &( sum_handle->sha512_context ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to initialize SHA512 context.",
			 function );

			goto on_error;
		}
		sum_handle->sha512_context_initialized = 1;
	}
	return( 1 );

on_error:
	if( sum_handle->sha1_context != NULL )
	{
		libhmac_sha1_context_free(
		 &( sum_handle->sha1_context ),
		 NULL );
	}
	if( sum_handle->md5_context != NULL )
	{
		libhmac_md5_context_free(
		 &( sum_handle->md5_context ),
		 NULL );
	}
	return( -1 );
}

/* Updates the integrity hash(es)
 * Returns 1 if successful or -1 on error
 */
int sum_handle_update_integrity_hash(
     sum_handle_t *sum_handle,
     uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error )
{
	static char *function = "sum_handle_update_integrity_hash";

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( ( buffer_size == 0 )
	 || ( buffer_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid buffer size value out of bounds.",
		 function );

		return( -1 );
	}
	if( sum_handle->calculate_md5 != 0 )
	{
		if( libhmac_md5_context_update(
		     sum_handle->md5_context,
		     buffer,
		     buffer_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to update MD5 digest hash.",
			 function );

			return( -1 );
		}
	}
	if( sum_handle->calculate_sha1 != 0 )
	{
		if( libhmac_sha1_context_update(
		     sum_handle->sha1_context,
		     buffer,
		     buffer_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to update SHA1 digest hash.",
			 function );

			return( -1 );
		}
	}
	if( sum_handle->calculate_sha224 != 0 )
	{
		if( libhmac_sha224_context_update(
		     sum_handle->sha224_context,
		     buffer,
		     buffer_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to update SHA224 digest hash.",
			 function );

			return( -1 );
		}
	}
	if( sum_handle->calculate_sha256 != 0 )
	{
		if( libhmac_sha256_context_update(
		     sum_handle->sha256_context,
		     buffer,
		     buffer_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to update SHA256 digest hash.",
			 function );

			return( -1 );
		}
	}
	if( sum_handle->calculate_sha512 != 0 )
	{
		if( libhmac_sha512_context_update(
		     sum_handle->sha512_context,
		     buffer,
		     buffer_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to update SHA512 digest hash.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

/* Finalizes the integrity hash(es)
 * Returns 1 if successful or -1 on error
 */
int sum_handle_finalize_integrity_hash(
     sum_handle_t *sum_handle,
     libcerror_error_t **error )
{
	uint8_t calculated_md5_hash[ LIBHMAC_MD5_HASH_SIZE ];
	uint8_t calculated_sha1_hash[ LIBHMAC_SHA1_HASH_SIZE ];
	uint8_t calculated_sha224_hash[ LIBHMAC_SHA224_HASH_SIZE ];
	uint8_t calculated_sha256_hash[ LIBHMAC_SHA256_HASH_SIZE ];
	uint8_t calculated_sha512_hash[ LIBHMAC_SHA512_HASH_SIZE ];

	static char *function = "sum_handle_finalize_integrity_hash";

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( sum_handle->calculate_md5 != 0 )
	{
		if( sum_handle->calculated_md5_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: invalid sum handle - missing calculated MD5 hash string.",
			 function );

			return( -1 );
		}
		if( libhmac_md5_context_finalize(
		     sum_handle->md5_context,
		     calculated_md5_hash,
		     LIBHMAC_MD5_HASH_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to finalize MD5 hash.",
			 function );

			return( -1 );
		}
		if( digest_hash_copy_to_string(
		     calculated_md5_hash,
		     LIBHMAC_MD5_HASH_SIZE,
		     sum_handle->calculated_md5_hash_string,
		     MD5_STRING_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBHMAC_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to set calculated MD5 hash string.",
			 function );

			return( -1 );
		}
	}
	if( sum_handle->calculate_sha1 != 0 )
	{
		if( sum_handle->calculated_sha1_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: invalid sum handle - missing calculated SHA1 hash string.",
			 function );

			return( -1 );
		}
		if( libhmac_sha1_context_finalize(
		     sum_handle->sha1_context,
		     calculated_sha1_hash,
		     LIBHMAC_SHA1_HASH_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to finalize SHA1 hash.",
			 function );

			return( -1 );
		}
		if( digest_hash_copy_to_string(
		     calculated_sha1_hash,
		     LIBHMAC_SHA1_HASH_SIZE,
		     sum_handle->calculated_sha1_hash_string,
		     SHA1_STRING_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create calculated SHA1 hash string.",
			 function );

			return( -1 );
		}
	}
	if( sum_handle->calculate_sha224 != 0 )
	{
		if( sum_handle->calculated_sha224_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: invalid sum handle - missing calculated SHA224 hash string.",
			 function );

			return( -1 );
		}
		if( libhmac_sha224_context_finalize(
		     sum_handle->sha224_context,
		     calculated_sha224_hash,
		     LIBHMAC_SHA224_HASH_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to finalize SHA224 hash.",
			 function );

			return( -1 );
		}
		if( digest_hash_copy_to_string(
		     calculated_sha224_hash,
		     LIBHMAC_SHA224_HASH_SIZE,
		     sum_handle->calculated_sha224_hash_string,
		     SHA224_STRING_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create calculated SHA224 hash string.",
			 function );

			return( -1 );
		}
	}
	if( sum_handle->calculate_sha256 != 0 )
	{
		if( sum_handle->calculated_sha256_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: invalid sum handle - missing calculated SHA256 hash string.",
			 function );

			return( -1 );
		}
		if( libhmac_sha256_context_finalize(
		     sum_handle->sha256_context,
		     calculated_sha256_hash,
		     LIBHMAC_SHA256_HASH_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to finalize SHA256 hash.",
			 function );

			return( -1 );
		}
		if( digest_hash_copy_to_string(
		     calculated_sha256_hash,
		     LIBHMAC_SHA256_HASH_SIZE,
		     sum_handle->calculated_sha256_hash_string,
		     SHA256_STRING_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create calculated SHA256 hash string.",
			 function );

			return( -1 );
		}
	}
	if( sum_handle->calculate_sha512 != 0 )
	{
		if( sum_handle->calculated_sha512_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: invalid sum handle - missing calculated SHA512 hash string.",
			 function );

			return( -1 );
		}
		if( libhmac_sha512_context_finalize(
		     sum_handle->sha512_context,
		     calculated_sha512_hash,
		     LIBHMAC_SHA512_HASH_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to finalize SHA512 hash.",
			 function );

			return( -1 );
		}
		if( digest_hash_copy_to_string(
		     calculated_sha512_hash,
		     LIBHMAC_SHA512_HASH_SIZE,
		     sum_handle->calculated_sha512_hash_string,
		     SHA512_STRING_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create calculated SHA512 hash string.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

/* Processes the input
 * Returns 1 if successful or -1 on error
 */
int sum_handle_process_input(
     sum_handle_t *sum_handle,
     libcerror_error_t **error )
{
	uint8_t *buffer        = NULL;
	static char *function  = "sum_handle_process_input";
	size64_t media_size    = 0;
	size64_t process_count = 0;
	size_t read_size       = 0;
	ssize_t read_count     = 0;

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( ( sum_handle->process_buffer_size == 0 )
	 || ( sum_handle->process_buffer_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid sum handle - process buffer size value out of bounds.",
		 function );

		return( -1 );
	}
	if( libcfile_file_get_size(
	     sum_handle->input_handle,
	     &media_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to determine media size.",
		 function );

		goto on_error;
	}
	buffer = (uint8_t *) memory_allocate(
	                      sizeof( uint8_t ) * sum_handle->process_buffer_size );

	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create buffer.",
		 function );

		goto on_error;
	}
	if( sum_handle_initialize_integrity_hash(
	     sum_handle,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize integrity hash(es).",
		 function );

		goto on_error;
	}
	while( process_count < media_size )
	{
		read_size = sum_handle->process_buffer_size;

		if( ( media_size - process_count ) < read_size )
		{
			read_size = (size_t) ( media_size - process_count );
		}
		read_count = sum_handle_read_buffer(
		              sum_handle,
		              buffer,
		              read_size,
		              error );

		if( read_count < 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			"%s: unable to read data.",
			 function );

			goto on_error;
		}
		if( read_count == 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unexpected end of data.",
			 function );

			goto on_error;
		}
		if( sum_handle_update_integrity_hash(
		     sum_handle,
		     buffer,
		     read_count,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GENERIC,
			 "%s: unable to update integrity hash(es).",
			 function );

			goto on_error;
		}
		process_count += read_count;

		if( sum_handle->abort != 0 )
		{
			break;
		}
  	}
	memory_free(
	 buffer );

	buffer = NULL;

	if( sum_handle_finalize_integrity_hash(
	     sum_handle,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to finalize integrity hash(es).",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( buffer != NULL )
	{
		memory_free(
		 buffer );
	}
	return( -1 );
}

/* Sets the digest types
 * Returns 1 if successful or -1 on error
 */
int sum_handle_set_digest_types(
     sum_handle_t *sum_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	system_character_t *string_segment     = NULL;
	system_split_string_t *string_elements = NULL;
	static char *function                  = "sum_handle_set_digest_types";
	size_t string_length                   = 0;
	size_t string_segment_size             = 0;
	uint8_t calculate_md5                  = 0;
	uint8_t calculate_sha1                 = 0;
	uint8_t calculate_sha224               = 0;
	uint8_t calculate_sha256               = 0;
	uint8_t calculate_sha512               = 0;
	int number_of_segments                 = 0;
	int segment_index                      = 0;
	int result                             = 0;

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	if( system_string_split(
	     string,
	     string_length + 1,
	     ',',
	     &string_elements,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to split string.",
		 function );

		goto on_error;
	}
	if( system_split_string_get_number_of_segments(
	     string_elements,
	     &number_of_segments,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of segments.",
		 function );

		return( -1 );
	}
	for( segment_index = 0;
	     segment_index < number_of_segments;
	     segment_index++ )
	{
		if( system_split_string_get_segment_by_index(
		     string_elements,
		     segment_index,
		     &string_segment,
		     &string_segment_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve string segment: %d.",
			 function,
			 segment_index );

			goto on_error;
		}
		if( string_segment == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: missing string segment: %d.",
			 function,
			 segment_index );

			return( -1 );
		}
		if( string_segment_size == 4 )
		{
			if( system_string_compare(
			     string_segment,
			     _SYSTEM_STRING( "md5" ),
			     4 ) == 0 )
			{
				calculate_md5 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "MD5" ),
			          4 ) == 0 )
			{
				calculate_md5 = 1;
			}
		}
		else if( string_segment_size == 5 )
		{
			if( system_string_compare(
			     string_segment,
			     _SYSTEM_STRING( "sha1" ),
			     4 ) == 0 )
			{
				calculate_sha1 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA1" ),
			          4 ) == 0 )
			{
				calculate_sha1 = 1;
			}
		}
		else if( string_segment_size == 6 )
		{
			if( system_string_compare(
			     string_segment,
			     _SYSTEM_STRING( "sha-1" ),
			     5 ) == 0 )
			{
				calculate_sha1 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "sha_1" ),
			          5 ) == 0 )
			{
				calculate_sha1 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA-1" ),
			          5 ) == 0 )
			{
				calculate_sha1 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA_1" ),
			          5 ) == 0 )
			{
				calculate_sha1 = 1;
			}
		}
		else if( string_segment_size == 7 )
		{
			if( system_string_compare(
			     string_segment,
			     _SYSTEM_STRING( "sha224" ),
			     6 ) == 0 )
			{
				calculate_sha224 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA224" ),
			          6 ) == 0 )
			{
				calculate_sha224 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "sha256" ),
			          6 ) == 0 )
			{
				calculate_sha256 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA256" ),
			          6 ) == 0 )
			{
				calculate_sha256 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "sha512" ),
			          6 ) == 0 )
			{
				calculate_sha512 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA512" ),
			          6 ) == 0 )
			{
				calculate_sha512 = 1;
			}
		}
		else if( string_segment_size == 8 )
		{
			if( system_string_compare(
			     string_segment,
			     _SYSTEM_STRING( "sha-224" ),
			     7 ) == 0 )
			{
				calculate_sha224 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "sha_224" ),
			          7 ) == 0 )
			{
				calculate_sha224 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA-224" ),
			          7 ) == 0 )
			{
				calculate_sha224 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA_224" ),
			          7 ) == 0 )
			{
				calculate_sha224 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "sha-256" ),
			          7 ) == 0 )
			{
				calculate_sha256 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "sha_256" ),
			          7 ) == 0 )
			{
				calculate_sha256 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA-256" ),
			          7 ) == 0 )
			{
				calculate_sha256 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA_256" ),
			          7 ) == 0 )
			{
				calculate_sha256 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "sha-512" ),
			          7 ) == 0 )
			{
				calculate_sha512 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "sha_512" ),
			          7 ) == 0 )
			{
				calculate_sha512 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA-512" ),
			          7 ) == 0 )
			{
				calculate_sha512 = 1;
			}
			else if( system_string_compare(
			          string_segment,
			          _SYSTEM_STRING( "SHA_512" ),
			          7 ) == 0 )
			{
				calculate_sha512 = 1;
			}
		}
	}
	if( ( calculate_md5 != 0 )
	 && ( sum_handle->calculate_md5 == 0 ) )
	{
		sum_handle->calculated_md5_hash_string = system_string_allocate(
		                                          MD5_STRING_SIZE );

		if( sum_handle->calculated_md5_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create calculated MD5 digest hash string.",
			 function );

			goto on_error;
		}
		sum_handle->calculate_md5 = 1;
	}
	if( ( calculate_sha1 != 0 )
	 && ( sum_handle->calculate_sha1 == 0 ) )
	{
		sum_handle->calculated_sha1_hash_string = system_string_allocate(
		                                           SHA1_STRING_SIZE );

		if( sum_handle->calculated_sha1_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create calculated SHA1 digest hash string.",
			 function );

			goto on_error;
		}
		sum_handle->calculate_sha1 = 1;
	}
	if( ( calculate_sha224 != 0 )
	 && ( sum_handle->calculate_sha224 == 0 ) )
	{
		sum_handle->calculated_sha224_hash_string = system_string_allocate(
		                                             SHA224_STRING_SIZE );

		if( sum_handle->calculated_sha224_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create calculated SHA224 digest hash string.",
			 function );

			goto on_error;
		}
		sum_handle->calculate_sha224 = 1;
	}
	if( ( calculate_sha256 != 0 )
	 && ( sum_handle->calculate_sha256 == 0 ) )
	{
		sum_handle->calculated_sha256_hash_string = system_string_allocate(
		                                             SHA256_STRING_SIZE );

		if( sum_handle->calculated_sha256_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create calculated SHA256 digest hash string.",
			 function );

			goto on_error;
		}
		sum_handle->calculate_sha256 = 1;
	}
	if( ( calculate_sha512 != 0 )
	 && ( sum_handle->calculate_sha512 == 0 ) )
	{
		sum_handle->calculated_sha512_hash_string = system_string_allocate(
		                                             SHA512_STRING_SIZE );

		if( sum_handle->calculated_sha512_hash_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create calculated SHA512 digest hash string.",
			 function );

			goto on_error;
		}
		sum_handle->calculate_sha512 = 1;
	}
	if( system_split_string_free(
	     &string_elements,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free split string.",
		 function );

		goto on_error;
	}
	return( result );

on_error:
	if( string_elements != NULL )
	{
		system_split_string_free(
		 &string_elements,
		 NULL );
	}
	return( -1 );
}

/* Sets the process buffer size
 * Returns 1 if successful, 0 if unsupported value or -1 on error
 */
int sum_handle_set_process_buffer_size(
     sum_handle_t *sum_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function  = "sum_handle_set_process_buffer_size";
	size_t string_length   = 0;
	uint64_t size_variable = 0;
	int result             = 0;

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum_handle.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	result = byte_size_string_convert(
	          string,
	          string_length,
	          &size_variable,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to determine process buffer size.",
		 function );

		return( -1 );
	}
	else if( result != 0 )
	{
		if( size_variable > (uint64_t) SSIZE_MAX )
		{
			result = 0;
		}
		else
		{
			sum_handle->process_buffer_size = (size_t) size_variable;
		}
	}
	return( result );
}

/* Print the hash values to a stream
 * Returns 1 if successful or -1 on error
 */
int sum_handle_hash_values_fprint(
     sum_handle_t *sum_handle,
     FILE *stream,
     libcerror_error_t **error )
{
	static char *function = "sum_handle_hash_values_fprint";

	if( sum_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sum handle.",
		 function );

		return( -1 );
	}
	if( stream == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid stream.",
		 function );

		return( -1 );
	}
	if( sum_handle->calculate_md5 != 0 )
	{
		fprintf(
		 stream,
		 "MD5 hash calculated over data:\t\t%" PRIs_SYSTEM "\n",
		 sum_handle->calculated_md5_hash_string );
	}
	if( sum_handle->calculate_sha1 != 0 )
	{
		fprintf(
		 stream,
		 "SHA1 hash calculated over data:\t\t%" PRIs_SYSTEM "\n",
		 sum_handle->calculated_sha1_hash_string );
	}
	if( sum_handle->calculate_sha224 != 0 )
	{
		fprintf(
		 stream,
		 "SHA224 hash calculated over data:\t%" PRIs_SYSTEM "\n",
		 sum_handle->calculated_sha224_hash_string );
	}
	if( sum_handle->calculate_sha256 != 0 )
	{
		fprintf(
		 stream,
		 "SHA256 hash calculated over data:\t%" PRIs_SYSTEM "\n",
		 sum_handle->calculated_sha256_hash_string );
	}
	if( sum_handle->calculate_sha512 != 0 )
	{
		fprintf(
		 stream,
		 "SHA512 hash calculated over data:\t%" PRIs_SYSTEM "\n",
		 sum_handle->calculated_sha512_hash_string );
	}
	return( 1 );
}

