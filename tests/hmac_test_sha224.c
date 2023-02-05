/*
 * Library SHA-224 context type testing program
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "hmac_test_libcerror.h"
#include "hmac_test_libhmac.h"
#include "hmac_test_macros.h"
#include "hmac_test_memory.h"
#include "hmac_test_unused.h"

typedef struct hmac_test_sha224_test_vector hmac_test_sha224_test_vector_t;

struct hmac_test_sha224_test_vector
{
	/* The description
	 */
	const char *description;

	/* The key
	 */
	uint8_t key[ 144 ];

	/* The key size
	 */
	size_t key_size;

	/* The data
	 */
	uint8_t data[ 164 ];

	/* The data size
	 */
	size_t data_size;

	/* The expected hmac
	 */
	uint8_t hmac[ LIBHMAC_SHA224_HASH_SIZE ];

	/* The hmac size
	 */
	size_t hmac_size;
};

/* Tests the libhmac_sha224_calculate function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_sha224_calculate(
     void )
{
	uint8_t data[ 208 ];
	uint8_t hash[ LIBHMAC_SHA224_HASH_SIZE ];

	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Initialize test
	 */
	memory_set(
	 data,
	 0,
	 208 );

	/* Test regular cases
	 */
	result = libhmac_sha224_calculate(
	          data,
	          208,
	          hash,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	HMAC_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
#if defined( HAVE_HMAC_TEST_MEMORY )

	/* Test libhmac_sha224_calculate with malloc failing in libhmac_sha224_initialize
	 */
	hmac_test_malloc_attempts_before_fail = 0;

	result = libhmac_sha224_calculate(
	          data,
	          208,
	          hash,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	if( hmac_test_malloc_attempts_before_fail != -1 )
	{
		hmac_test_malloc_attempts_before_fail = -1;
	}
	else
	{
		HMAC_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		HMAC_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_HMAC_TEST_MEMORY ) */

	/* Test libhmac_sha224_calculate with libhmac_sha224_update failing
	 */
	result = libhmac_sha224_calculate(
	          NULL,
	          208,
	          hash,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	HMAC_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Test libhmac_sha224_calculate with libhmac_sha224_finalize failing
	 */
	result = libhmac_sha224_calculate(
	          data,
	          208,
	          NULL,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	HMAC_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libhmac_sha224_calculate_hmac function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_sha224_calculate_hmac(
     void )
{
	uint8_t hmac[ LIBHMAC_SHA224_HASH_SIZE ];

	hmac_test_sha224_test_vector_t test_vectors[ 7 ] = {
		/* RFC 4231 test vectors
		 */
		{ "RFC 4231 test vector 1",
                  { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		    0x0b, 0x0b, 0x0b, 0x0b }, 20,
		  { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' }, 8,
		  { 0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19, 0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f,
		    0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f, 0x53, 0x68, 0x4b, 0x22 }, 28 },
		{ "RFC 4231 test vector 2",
                  { 'J', 'e', 'f', 'e' }, 4,
                  { 'w', 'h', 'a', 't', ' ', 'd', 'o', ' ', 'y', 'a', ' ', 'w', 'a', 'n', 't', ' ',
		    'f', 'o', 'r', ' ', 'n', 'o', 't', 'h', 'i', 'n', 'g', '?' }, 28,
		  { 0xa3, 0x0e, 0x01, 0x09, 0x8b, 0xc6, 0xdb, 0xbf, 0x45, 0x69, 0x0f, 0x3a, 0x7e, 0x9e, 0x6d, 0x0f,
		    0x8b, 0xbe, 0xa2, 0xa3, 0x9e, 0x61, 0x48, 0x00, 0x8f, 0xd0, 0x5e, 0x44 }, 28 },
		{ "RFC 4231 test vector 3",
                  { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		    0xaa, 0xaa, 0xaa, 0xaa }, 20,
                  { 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		    0xdd, 0xdd }, 50,
		  { 0x7f, 0xb3, 0xcb, 0x35, 0x88, 0xc6, 0xc1, 0xf6, 0xff, 0xa9, 0x69, 0x4d, 0x7d, 0x6a, 0xd2, 0x64,
		    0x93, 0x65, 0xb0, 0xc1, 0xf6, 0x5d, 0x69, 0xd1, 0xec, 0x83, 0x33, 0xea }, 28 },
		{ "RFC 4231 test vector 4",
		  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 }, 25,
                  { 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		    0xcd, 0xcd }, 50,
		  { 0x6c, 0x11, 0x50, 0x68, 0x74, 0x01, 0x3c, 0xac, 0x6a, 0x2a, 0xbc, 0x1b, 0xb3, 0x82, 0x62, 0x7c,
		    0xec, 0x6a, 0x90, 0xd8, 0x6e, 0xfc, 0x01, 0x2d, 0xe7, 0xaf, 0xec, 0x5a }, 28 },
		{ "RFC 4231 test vector 5",
                  { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
		    0x0c, 0x0c, 0x0c, 0x0c }, 20,
		  { 'T', 'e', 's', 't', ' ', 'W', 'i', 't', 'h', ' ', 'T', 'r', 'u', 'n', 'c', 'a',
		    't', 'i', 'o', 'n' }, 20,
		  { 0x0e, 0x2a, 0xea, 0x68, 0xa9, 0x0c, 0x8d, 0x37, 0xc9, 0x88, 0xbc, 0xdb, 0x9f, 0xca, 0x6f, 0xa8 }, 16 },
		{ "RFC 4231 test vector 6",
                  { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		    0xaa, 0xaa, 0xaa }, 131,
		  { 'T', 'e', 's', 't', ' ', 'U', 's', 'i', 'n', 'g', ' ', 'L', 'a', 'r', 'g', 'e',
		    'r', ' ', 'T', 'h', 'a', 'n', ' ', 'B', 'l', 'o', 'c', 'k', '-', 'S', 'i', 'z',
		    'e', ' ', 'K', 'e', 'y', ' ', '-', ' ', 'H', 'a', 's', 'h', ' ', 'K', 'e', 'y',
		    ' ', 'F', 'i', 'r', 's', 't' }, 54,
		  { 0x95, 0xe9, 0xa0, 0xdb, 0x96, 0x20, 0x95, 0xad, 0xae, 0xbe, 0x9b, 0x2d, 0x6f, 0x0d, 0xbc, 0xe2,
		    0xd4, 0x99, 0xf1, 0x12, 0xf2, 0xd2, 0xb7, 0x27, 0x3f, 0xa6, 0x87, 0x0e }, 28 },
		{ "RFC 4231 test vector 7",
                  { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		    0xaa, 0xaa, 0xaa }, 131,
		  { 'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 't', 'e', 's', 't', ' ', 'u',
		    's', 'i', 'n', 'g', ' ', 'a', ' ', 'l', 'a', 'r', 'g', 'e', 'r', ' ', 't', 'h',
		    'a', 'n', ' ', 'b', 'l', 'o', 'c', 'k', '-', 's', 'i', 'z', 'e', ' ', 'k', 'e',
		    'y', ' ', 'a', 'n', 'd', ' ', 'a', ' ', 'l', 'a', 'r', 'g', 'e', 'r', ' ', 't',
		    'h', 'a', 'n', ' ', 'b', 'l', 'o', 'c', 'k', '-', 's', 'i', 'z', 'e', ' ', 'd',
		    'a', 't', 'a', '.', ' ', 'T', 'h', 'e', ' ', 'k', 'e', 'y', ' ', 'n', 'e', 'e',
		    'd', 's', ' ', 't', 'o', ' ', 'b', 'e', ' ', 'h', 'a', 's', 'h', 'e', 'd', ' ',
		    'b', 'e', 'f', 'o', 'r', 'e', ' ', 'b', 'e', 'i', 'n', 'g', ' ', 'u', 's', 'e',
		    'd', ' ', 'b', 'y', ' ', 't', 'h', 'e', ' ', 'H', 'M', 'A', 'C', ' ', 'a', 'l',
		    'g', 'o', 'r', 'i', 't', 'h', 'm', '.' }, 152,
		  { 0x3a, 0x85, 0x41, 0x66, 0xac, 0x5d, 0x9f, 0x02, 0x3f, 0x54, 0xd5, 0x17, 0xd0, 0xb3, 0x9d, 0xbd,
		    0x94, 0x67, 0x70, 0xdb, 0x9c, 0x2b, 0x95, 0xc9, 0xf6, 0xf5, 0x65, 0xd1 }, 28 },
	};

	libcerror_error_t *error = NULL;
	int result               = 0;
	int test_number          = 0;

	/* Test regular cases
	 */
	for( test_number = 0;
	     test_number < 7;
	     test_number++ )
	{
		result = libhmac_sha224_calculate_hmac(
		          test_vectors[ test_number ].key,
		          test_vectors[ test_number ].key_size,
		          test_vectors[ test_number ].data,
		          test_vectors[ test_number ].data_size,
		          hmac,
		          LIBHMAC_SHA224_HASH_SIZE,
		          &error );

		HMAC_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		HMAC_TEST_ASSERT_IS_NULL(
		 "error",
		 error );

		result = memory_compare(
		          hmac,
		          test_vectors[ test_number ].hmac,
		          test_vectors[ test_number ].hmac_size );

		HMAC_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 0 );
	}
	/* Test error cases
	 */
	result = libhmac_sha224_calculate_hmac(
	          NULL,
	          test_vectors[ 0 ].key_size,
	          test_vectors[ 0 ].data,
	          test_vectors[ 0 ].data_size,
	          hmac,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	HMAC_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libhmac_sha224_calculate_hmac(
	          test_vectors[ 0 ].key,
	          (size_t) SSIZE_MAX + 1,
	          test_vectors[ 0 ].data,
	          test_vectors[ 0 ].data_size,
	          hmac,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	HMAC_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libhmac_sha224_calculate_hmac(
	          test_vectors[ 0 ].key,
	          test_vectors[ 0 ].key_size,
	          test_vectors[ 0 ].data,
	          test_vectors[ 0 ].data_size,
	          hmac,
	          0,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	HMAC_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

#if defined( HAVE_HMAC_TEST_MEMORY )

	/* Test libhmac_sha224_calculate_hmac with malloc failing
	 */
	hmac_test_malloc_attempts_before_fail = 0;

	result = libhmac_sha224_calculate_hmac(
	          test_vectors[ 0 ].key,
	          test_vectors[ 0 ].key_size,
	          test_vectors[ 0 ].data,
	          test_vectors[ 0 ].data_size,
	          hmac,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	if( hmac_test_malloc_attempts_before_fail != -1 )
	{
		hmac_test_malloc_attempts_before_fail = -1;
	}
	else
	{
		HMAC_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		HMAC_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_HMAC_TEST_MEMORY ) */

/* TODO add tests for key_size <= block_size and memcpy failing */

/* TODO add tests for key_size <= block_size and memset failing */

/* TODO add tests for key_size > block_size and libhmac_sha224_initialize failing */

/* TODO add tests for key_size > block_size and libhmac_sha224_update failing */

/* TODO add tests for key_size > block_size and libhmac_sha224_finalize failing */

/* TODO add tests for key_size > block_size and memset failing */

/* TODO add tests for key_size > block_size and memcpy failing */

/* TODO add tests for malloc of inner_padding failing */

/* TODO add tests for memset of inner_padding failing */

/* TODO add tests for malloc of outer_padding failing */

/* TODO add tests for memset of outer_padding failing */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc HMAC_TEST_ATTRIBUTE_UNUSED,
     wchar_t * const argv[] HMAC_TEST_ATTRIBUTE_UNUSED )
#else
int main(
     int argc HMAC_TEST_ATTRIBUTE_UNUSED,
     char * const argv[] HMAC_TEST_ATTRIBUTE_UNUSED )
#endif
{
	HMAC_TEST_UNREFERENCED_PARAMETER( argc )
	HMAC_TEST_UNREFERENCED_PARAMETER( argv )

	HMAC_TEST_RUN(
	 "libhmac_sha224_calculate",
	 hmac_test_sha224_calculate );

	HMAC_TEST_RUN(
	 "libhmac_sha224_calculate_hmac",
	 hmac_test_sha224_calculate_hmac );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

