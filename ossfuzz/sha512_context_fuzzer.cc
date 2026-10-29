/*
 * OSS-Fuzz target for libhmac SHA-512 context type
 *
 * Copyright (C) 2011-2026, Joachim Metz <joachim.metz@gmail.com>
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

#include <stddef.h>
#include <stdint.h>

/* Note that some of the OSS-Fuzz engines use C++
 */
extern "C" {

#include "ossfuzz_libhmac.h"

int LLVMFuzzerTestOneInput(
     const uint8_t *data,
     size_t size )
{
	uint8_t sha512_hash[ LIBHMAC_SHA512_HASH_SIZE ];
	uint8_t small_hash[ 1 ];

	libhmac_sha512_context_t *context = NULL;
	size_t maximum_update_size       = 0;
	size_t offset                    = 0;
	size_t update_size               = 0;

	libhmac_sha512_calculate(
	 data,
	 size,
	 sha512_hash,
	 LIBHMAC_SHA512_HASH_SIZE,
	 NULL );

	/* Exercise invalid argument handling
	 */
	libhmac_sha512_context_initialize(
	 NULL,
	 NULL );

	libhmac_sha512_context_update(
	 NULL,
	 data,
	 size,
	 NULL );

	libhmac_sha512_context_finalize(
	 NULL,
	 sha512_hash,
	 LIBHMAC_SHA512_HASH_SIZE,
	 NULL );

	libhmac_sha512_context_free(
	 NULL,
	 NULL );

	if( libhmac_sha512_context_initialize(
	     &context,
	     NULL ) != 1 )
	{
		return( 0 );
	}
	while( offset < size )
	{
		maximum_update_size = 1 + ( size_t ) ( data[ offset ] & 0x7f ) * 2;

		update_size = size - offset;

		if( update_size > maximum_update_size )
		{
			update_size = maximum_update_size;
		}
		libhmac_sha512_context_update(
		 context,
		 &( data[ offset ] ),
		 update_size,
		 NULL );

		offset += update_size;
	}
	/* Exercise invalid argument handling
	 */
	libhmac_sha512_context_finalize(
	 context,
	 small_hash,
	 sizeof( small_hash ),
	 NULL );

	libhmac_sha512_context_finalize(
	 context,
	 sha512_hash,
	 LIBHMAC_SHA512_HASH_SIZE,
	 NULL );

	libhmac_sha512_context_free(
	 &context,
	 NULL );

	return( 0 );
}

} /* extern "C" */

