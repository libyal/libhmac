/*
 * Library MD5 context type testing program
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

#include "../libhmac/libhmac_definitions.h"

/* Tests the libhmac_md5_calculate function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_md5_calculate(
     void )
{
	uint8_t data[ 208 ];
	uint8_t hash[ LIBHMAC_MD5_HASH_SIZE ];

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
	result = libhmac_md5_calculate(
	          data,
	          208,
	          hash,
	          LIBHMAC_MD5_HASH_SIZE,
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

	/* Test libhmac_md5_calculate with malloc failing in libhmac_md5_context_initialize
	 */
	hmac_test_malloc_attempts_before_fail = 0;

	result = libhmac_md5_calculate(
	          data,
	          208,
	          hash,
	          LIBHMAC_MD5_HASH_SIZE,
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

	/* Test libhmac_md5_calculate with libhmac_md5_context_update failing
	 */
	result = libhmac_md5_calculate(
	          NULL,
	          208,
	          hash,
	          LIBHMAC_MD5_HASH_SIZE,
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

	/* Test libhmac_md5_calculate with libhmac_md5_context_finalize failing
	 */
	result = libhmac_md5_calculate(
	          data,
	          208,
	          NULL,
	          LIBHMAC_MD5_HASH_SIZE,
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

/* Tests the libhmac_md5_calculate_hmac function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_md5_calculate_hmac(
     void )
{
	uint8_t data[ 208 ];
	uint8_t hmac[ LIBHMAC_MD5_HASH_SIZE ];
	uint8_t key[ 16 ];

	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Initialize test
	 */
	memory_set(
	 data,
	 0,
	 208 );

	memory_set(
	 key,
	 0,
	 16 );

	/* Test regular cases
	 */
	result = libhmac_md5_calculate_hmac(
	          key,
	          16,
	          data,
	          208,
	          hmac,
	          LIBHMAC_MD5_HASH_SIZE,
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
	result = libhmac_md5_calculate_hmac(
	          NULL,
	          16,
	          data,
	          208,
	          hmac,
	          LIBHMAC_MD5_HASH_SIZE,
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

	result = libhmac_md5_calculate_hmac(
	          key,
	          (size_t) SSIZE_MAX + 1,
	          data,
	          208,
	          hmac,
	          LIBHMAC_MD5_HASH_SIZE,
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

	result = libhmac_md5_calculate_hmac(
	          key,
	          0,
	          data,
	          208,
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

	/* Test libhmac_md5_calculate_hmac with malloc failing
	 */
	hmac_test_malloc_attempts_before_fail = 0;

	result = libhmac_md5_calculate_hmac(
	          key,
	          16,
	          data,
	          208,
	          hmac,
	          LIBHMAC_MD5_HASH_SIZE,
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

/* TODO add tests for key_size > block_size and libhmac_md5_context_initialize failing */

/* TODO add tests for key_size > block_size and libhmac_md5_context_update failing */

/* TODO add tests for key_size > block_size and libhmac_md5_context_finalize failing */

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
	 "libhmac_md5_calculate",
	 hmac_test_md5_calculate );

	HMAC_TEST_RUN(
	 "libhmac_md5_calculate_hmac",
	 hmac_test_md5_calculate_hmac );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

