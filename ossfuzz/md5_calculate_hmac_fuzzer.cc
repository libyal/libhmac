/*
 * OSS-Fuzz target for libhmac MD5 calculate HMAC
 *
 * The fuzzer input consists of:
 * [ 0, 3 ]  32-bit little-endian key size, clamped to the amount of remaining data
 * [ 4, 4 + key_size - 1 ]  optional key
 * [ 4 + key_size, ... ]  message
 * If the input is smaller than 4 bytes the key size is 0
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
	uint8_t md5_hmac[ LIBHMAC_MD5_HASH_SIZE ];
	const uint8_t *key                 = NULL;
	size_t key_size                    = 0;
	const uint8_t *message             = data;
	size_t message_size                = size;

	if( size >= 4 )
	{
		key_size          = (size_t) data[ 0 ] | ( (size_t) data[ 1 ] << 8 ) | ( (size_t) data[ 2 ] << 16 ) | ( (size_t) data[ 3 ] << 24 );

		if( key_size > size - 4 )
		{
			key_size = size - 4;
		}
		key             = &( data[ 4 ] );
		message         = &( data[ 4 + key_size ] );
		message_size    = size - 4 - key_size;
	}
	libhmac_md5_calculate_hmac(
	 key,
	 key_size,
	 message,
	 message_size,
	 md5_hmac,
	 LIBHMAC_MD5_HASH_SIZE,
	 NULL );

	/* Exercise invalid argument handling
	 */
	libhmac_md5_calculate_hmac(
	 NULL,
	 0,
	 message,
	 message_size,
	 md5_hmac,
	 LIBHMAC_MD5_HASH_SIZE,
	 NULL );

	libhmac_md5_calculate_hmac(
	 key,
	 key_size,
	 message,
	 message_size,
	 md5_hmac,
	 sizeof( uint8_t ),
	 NULL );

	return( 0 );
}

} /* extern "C" */
