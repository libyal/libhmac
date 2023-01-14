/*
 * Library SHA1 context type testing program
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
#include <file_stream.h>
#include <memory.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H )
#include <openssl/sha.h>

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
#include <openssl/evp.h>
#endif

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )
#define __USE_GNU
#include <dlfcn.h>
#undef __USE_GNU
#endif

#include "hmac_test_libcerror.h"
#include "hmac_test_libhmac.h"
#include "hmac_test_macros.h"
#include "hmac_test_memory.h"
#include "hmac_test_unused.h"

/* Make sure libhmac_sha1.h is included to define LIBHMAC_HAVE_SHA1_SUPPORT
 */
#include "../libhmac/libhmac_sha1.h"

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH )

static int (*hmac_test_real_SHA1_Init)(SHA1_CTX *)                                              = NULL;
static int (*hmac_test_real_SHA1_Update)(SHA1_CTX *, const void *, unsigned long)               = NULL;
static int (*hmac_test_real_SHA1_Final)(unsigned char *, SHA1_CTX *)                            = NULL;

int hmac_test_SHA1_Init_attempts_before_fail                                                   = -1;
int hmac_test_SHA1_Update_attempts_before_fail                                                 = -1;
int hmac_test_SHA1_Final_attempts_before_fail                                                  = -1;

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA1 )

static int (*hmac_test_real_EVP_DigestInit_ex)(EVP_MD_CTX *, const EVP_MD *, ENGINE *)         = NULL;
static int (*hmac_test_real_EVP_DigestUpdate)(EVP_MD_CTX *, const void *, size_t)              = NULL;
static int (*hmac_test_real_EVP_DigestFinal_ex)(EVP_MD_CTX *, unsigned char *, unsigned int *) = NULL;

int hmac_test_EVP_DigestInit_ex_attempts_before_fail                                           = -1;
int hmac_test_EVP_DigestUpdate_attempts_before_fail                                            = -1;
int hmac_test_EVP_DigestFinal_ex_attempts_before_fail                                          = -1;

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH ) */

#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH )

/* Custom SHA1_Init for testing error cases
 * Returns 1 if successful or 0 otherwise
 */
int SHA1_Init(
     SHA1_CTX *c )
{
	int result = 0;

	if( hmac_test_real_SHA1_Init == NULL )
	{
		hmac_test_real_SHA1_Init = dlsym(
		                            RTLD_NEXT,
		                            "SHA1_Init" );
	}
	if( hmac_test_SHA1_Init_attempts_before_fail == 0 )
	{
		hmac_test_SHA1_Init_attempts_before_fail = -1;

		return( 0 );
	}
	else if( hmac_test_SHA1_Init_attempts_before_fail > 0 )
	{
		hmac_test_SHA1_Init_attempts_before_fail--;
	}
	result = hmac_test_real_SHA1_Init(
	          c );

	return( result );
}

/* Custom SHA1_Update for testing error cases
 * Returns 1 if successful or 0 otherwise
 */
int SHA1_Update(
     SHA1_CTX *c,
     const void *data,
     unsigned long len )
{
	int result = 0;

	if( hmac_test_real_SHA1_Update == NULL )
	{
		hmac_test_real_SHA1_Update = dlsym(
		                              RTLD_NEXT,
		                              "SHA1_Update" );
	}
	if( hmac_test_SHA1_Update_attempts_before_fail == 0 )
	{
		hmac_test_SHA1_Update_attempts_before_fail = -1;

		return( 0 );
	}
	else if( hmac_test_SHA1_Update_attempts_before_fail > 0 )
	{
		hmac_test_SHA1_Update_attempts_before_fail--;
	}
	result = hmac_test_real_SHA1_Update(
	          c,
	          data,
	          len );

	return( result );
}

/* Custom SHA1_Final for testing error cases
 * Returns 1 if successful or 0 otherwise
 */
int SHA1_Final(
     unsigned char *md,
     SHA1_CTX *c )
{
	int result = 0;

	if( hmac_test_real_SHA1_Final == NULL )
	{
		hmac_test_real_SHA1_Final = dlsym(
		                             RTLD_NEXT,
		                             "SHA1_Final" );
	}
	if( hmac_test_SHA1_Final_attempts_before_fail == 0 )
	{
		hmac_test_SHA1_Final_attempts_before_fail = -1;

		return( 0 );
	}
	else if( hmac_test_SHA1_Final_attempts_before_fail > 0 )
	{
		hmac_test_SHA1_Final_attempts_before_fail--;
	}
	result = hmac_test_real_SHA1_Final(
	          md,
	          c );

	return( result );
}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA1 )

/* Custom EVP_DigestInit_ex for testing error cases
 * Returns 1 if successful or 0 otherwise
 */
int EVP_DigestInit_ex(
     EVP_MD_CTX *ctx,
     const EVP_MD *type,
     ENGINE *impl )
{
	int result = 0;

	if( hmac_test_real_EVP_DigestInit_ex == NULL )
	{
		hmac_test_real_EVP_DigestInit_ex = dlsym(
		                                    RTLD_NEXT,
		                                    "EVP_DigestInit_ex" );
	}
	if( hmac_test_EVP_DigestInit_ex_attempts_before_fail == 0 )
	{
		hmac_test_EVP_DigestInit_ex_attempts_before_fail = -1;

		return( 0 );
	}
	else if( hmac_test_EVP_DigestInit_ex_attempts_before_fail > 0 )
	{
		hmac_test_EVP_DigestInit_ex_attempts_before_fail--;
	}
	result = hmac_test_real_EVP_DigestInit_ex(
	          ctx,
	          type,
	          impl );

	return( result );
}

/* Custom EVP_DigestUpdate for testing error cases
 * Returns 1 if successful or 0 otherwise
 */
int EVP_DigestUpdate(
     EVP_MD_CTX *ctx,
     const void *d,
     size_t cnt )
{
	int result = 0;

	if( hmac_test_real_EVP_DigestUpdate == NULL )
	{
		hmac_test_real_EVP_DigestUpdate = dlsym(
		                                   RTLD_NEXT,
		                                   "EVP_DigestUpdate" );
	}
	if( hmac_test_EVP_DigestUpdate_attempts_before_fail == 0 )
	{
		hmac_test_EVP_DigestUpdate_attempts_before_fail = -1;

		return( 0 );
	}
	else if( hmac_test_EVP_DigestUpdate_attempts_before_fail > 0 )
	{
		hmac_test_EVP_DigestUpdate_attempts_before_fail--;
	}
	result = hmac_test_real_EVP_DigestUpdate(
	          ctx,
	          d,
	          cnt );

	return( result );
}

/* Custom EVP_DigestFinal_ex for testing error cases
 * Returns 1 if successful or 0 otherwise
 */
int EVP_DigestFinal_ex(
     EVP_MD_CTX *ctx,
     unsigned char *md,
     unsigned int *s )
{
	int result = 0;

	if( hmac_test_real_EVP_DigestFinal_ex == NULL )
	{
		hmac_test_real_EVP_DigestFinal_ex = dlsym(
		                                     RTLD_NEXT,
		                                     "EVP_DigestFinal_ex" );
	}
	if( hmac_test_EVP_DigestFinal_ex_attempts_before_fail == 0 )
	{
		hmac_test_EVP_DigestFinal_ex_attempts_before_fail = -1;

		return( 0 );
	}
	else if( hmac_test_EVP_DigestFinal_ex_attempts_before_fail > 0 )
	{
		hmac_test_EVP_DigestFinal_ex_attempts_before_fail--;
	}
	result = hmac_test_real_EVP_DigestFinal_ex(
	          ctx,
	          md,
	          s );

	return( result );
}

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH ) */

#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

/* Tests the libhmac_sha1_initialize function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_sha1_initialize(
     void )
{
	libcerror_error_t *error        = NULL;
	libhmac_sha1_context_t *context = NULL;
	int result                      = 0;

#if defined( HAVE_HMAC_TEST_MEMORY )
	int number_of_malloc_fail_tests = 1;
	int number_of_memset_fail_tests = 1;
	int test_number                 = 0;
#endif

	/* Test libhmac_sha1_initialize without entries
	 */
	result = libhmac_sha1_initialize(
	          &context,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	HMAC_TEST_ASSERT_IS_NOT_NULL(
	 "context",
	 context );

	HMAC_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libhmac_sha1_free(
	          &context,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	HMAC_TEST_ASSERT_IS_NULL(
	 "context",
	 context );

	HMAC_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libhmac_sha1_initialize(
	          NULL,
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

	context = (libhmac_sha1_context_t *) 0x12345678UL;

	result = libhmac_sha1_initialize(
	          &context,
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

	context = NULL;

#if defined( HAVE_HMAC_TEST_MEMORY )

	/* 1 fail in memory_allocate_structure
	 */
	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libhmac_sha1_initialize with malloc failing
		 */
		hmac_test_malloc_attempts_before_fail = test_number;

		result = libhmac_sha1_initialize(
		          &context,
		          &error );

		if( hmac_test_malloc_attempts_before_fail != -1 )
		{
			hmac_test_malloc_attempts_before_fail = -1;

			if( context != NULL )
			{
				libhmac_sha1_free(
				 &context,
				 NULL );
			}
		}
		else
		{
			HMAC_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			HMAC_TEST_ASSERT_IS_NULL(
			 "context",
			 context );

			HMAC_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
	/* 1 fail in memset after memory_allocate_structure
	 */
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test libhmac_sha1_initialize with memset failing
		 */
		hmac_test_memset_attempts_before_fail = test_number;

		result = libhmac_sha1_initialize(
		          &context,
		          &error );

		if( hmac_test_memset_attempts_before_fail != -1 )
		{
			hmac_test_memset_attempts_before_fail = -1;

			if( context != NULL )
			{
				libhmac_sha1_free(
				 &context,
				 NULL );
			}
		}
		else
		{
			HMAC_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			HMAC_TEST_ASSERT_IS_NULL(
			 "context",
			 context );

			HMAC_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( HAVE_HMAC_TEST_MEMORY ) */

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libhmac_sha1_initialize with SHA1_Init failing
	 */
	hmac_test_SHA1_Init_attempts_before_fail = 0;

	result = libhmac_sha1_initialize(
	          &context,
	          &error );

	if( hmac_test_SHA1_Init_attempts_before_fail != -1 )
	{
		hmac_test_SHA1_Init_attempts_before_fail = -1;

		if( context != NULL )
		{
			libhmac_sha1_free(
			 &context,
			 NULL );
		}
	}
	else
	{
		HMAC_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		HMAC_TEST_ASSERT_IS_NULL(
		 "context",
		 context );

		HMAC_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA1 )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libhmac_sha1_initialize with EVP_DigestInit_ex failing
	 */
	hmac_test_EVP_DigestInit_ex_attempts_before_fail = 0;

	result = libhmac_sha1_initialize(
	          &context,
	          &error );

	if( hmac_test_EVP_DigestInit_ex_attempts_before_fail != -1 )
	{
		hmac_test_EVP_DigestInit_ex_attempts_before_fail = -1;

		if( context != NULL )
		{
			libhmac_sha1_free(
			 &context,
			 NULL );
		}
	}
	else
	{
		HMAC_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		HMAC_TEST_ASSERT_IS_NULL(
		 "context",
		 context );

		HMAC_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#else
#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libhmac_sha1_initialize with memcpy failing
	 */
	hmac_test_memcpy_attempts_before_fail = 0;

	result = libhmac_sha1_initialize(
	          &context,
	          &error );

	if( hmac_test_memcpy_attempts_before_fail != -1 )
	{
		hmac_test_memcpy_attempts_before_fail = -1;

		if( context != NULL )
		{
			libhmac_sha1_free(
			 &context,
			 NULL );
		}
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		HMAC_TEST_ASSERT_IS_NULL(
		 "context",
		 context );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED ) */

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( context != NULL )
	{
		libhmac_sha1_free(
		 &context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libhmac_sha1_free function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_sha1_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libhmac_sha1_free(
	          NULL,
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

/* Tests the libhmac_sha1_update function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_sha1_update(
     void )
{
	uint8_t data[ 208 ];

	libcerror_error_t *error        = NULL;
	libhmac_sha1_context_t *context = NULL;
	size_t maximum_size             = 0;
	int result                      = 0;

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH )
#if ( SIZEOF_LONG < SIZEOF_SIZE_T )
	maximum_size = (size_t) ULONG_MAX;
#else
	maximum_size = (size_t) SSIZE_MAX;
#endif
#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA1 )
	maximum_size = (size_t) SSIZE_MAX;
#else
	maximum_size = (size_t) SSIZE_MAX;
#endif

	/* Initialize test
	 */
	result = libhmac_sha1_initialize(
	          &context,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	HMAC_TEST_ASSERT_IS_NOT_NULL(
	 "context",
	 context );

	HMAC_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libhmac_sha1_update(
	          context,
	          data,
	          208,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	HMAC_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libhmac_sha1_update(
	          context,
	          data,
	          0,
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
	result = libhmac_sha1_update(
	          NULL,
	          data,
	          208,
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

	result = libhmac_sha1_update(
	          context,
	          NULL,
	          208,
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

	if( maximum_size > 0 )
	{
		result = libhmac_sha1_update(
		          context,
		          data,
		          maximum_size + 1,
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
	}
#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libhmac_sha1_update with SHA1_Update failing
	 */
	hmac_test_SHA1_Update_attempts_before_fail = 0;

	result = libhmac_sha1_update(
	          context,
	          data,
	          208,
	          &error );

	if( hmac_test_SHA1_Update_attempts_before_fail != -1 )
	{
		hmac_test_SHA1_Update_attempts_before_fail = -1;
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
#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA1 )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libhmac_sha1_update with EVP_DigestUpdate failing
	 */
	hmac_test_EVP_DigestUpdate_attempts_before_fail = 0;

	result = libhmac_sha1_update(
	          context,
	          data,
	          208,
	          &error );

	if( hmac_test_EVP_DigestUpdate_attempts_before_fail != -1 )
	{
		hmac_test_EVP_DigestUpdate_attempts_before_fail = -1;
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
#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#else
#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libhmac_sha1_update with memcpy failing
	 */
	hmac_test_memcpy_attempts_before_fail = 0;

	result = libhmac_sha1_update(
	          context,
	          data,
	          208,
	          &error );

	if( hmac_test_memcpy_attempts_before_fail != -1 )
	{
		hmac_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Test libhmac_sha1_update with memcpy failing
	 */
	hmac_test_memcpy_attempts_before_fail = 1;

	result = libhmac_sha1_update(
	          context,
	          data,
	          208,
	          &error );

	if( hmac_test_memcpy_attempts_before_fail != -1 )
	{
		hmac_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED ) */
#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH ) */

	/* Clean up
	 */
	result = libhmac_sha1_free(
	          &context,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	HMAC_TEST_ASSERT_IS_NULL(
	 "context",
	 context );

	HMAC_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( context != NULL )
	{
		libhmac_sha1_free(
		 &context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libhmac_sha1_finalize function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_sha1_finalize(
     void )
{
	uint8_t hash[ LIBHMAC_SHA1_HASH_SIZE ];

	libcerror_error_t *error        = NULL;
	libhmac_sha1_context_t *context = NULL;
	size_t maximum_size             = 0;
	int result                      = 0;

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH )
	maximum_size = (size_t) SSIZE_MAX;
#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA1 )
	maximum_size = (size_t) UINT_MAX;
#else
	maximum_size = (size_t) SSIZE_MAX;
#endif

	/* Initialize test
	 */
	result = libhmac_sha1_initialize(
	          &context,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	HMAC_TEST_ASSERT_IS_NOT_NULL(
	 "context",
	 context );

	HMAC_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libhmac_sha1_finalize(
	          context,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
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
	result = libhmac_sha1_finalize(
	          NULL,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
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

	result = libhmac_sha1_finalize(
	          context,
	          NULL,
	          LIBHMAC_SHA1_HASH_SIZE,
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

	if( maximum_size > 0 )
	{
		result = libhmac_sha1_finalize(
		          context,
		          hash,
		          maximum_size + 1,
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
	}
	result = libhmac_sha1_finalize(
	          context,
	          hash,
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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libhmac_sha1_finalize with SHA1_Final failing
	 */
	hmac_test_SHA1_Final_attempts_before_fail = 0;

	result = libhmac_sha1_finalize(
	          context,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
	          &error );

	if( hmac_test_SHA1_Final_attempts_before_fail != -1 )
	{
		hmac_test_SHA1_Final_attempts_before_fail = -1;
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
#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA1 )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libhmac_sha1_finalize with EVP_DigestFinal_ex failing
	 */
	hmac_test_EVP_DigestFinal_ex_attempts_before_fail = 0;

	result = libhmac_sha1_finalize(
	          context,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
	          &error );

	if( hmac_test_EVP_DigestFinal_ex_attempts_before_fail != -1 )
	{
		hmac_test_EVP_DigestFinal_ex_attempts_before_fail = -1;
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
#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#else
#if defined( HAVE_HMAC_TEST_MEMORY )
#if defined( OPTIMIZATION_DISABLED )

	/* Test libhmac_sha1_finalize with memset of internal_context->block failing
	 */
	hmac_test_memset_attempts_before_fail = 0;

	result = libhmac_sha1_finalize(
	          context,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
	          &error );

	if( hmac_test_memset_attempts_before_fail != -1 )
	{
		hmac_test_memset_attempts_before_fail = -1;
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
#endif /* defined( OPTIMIZATION_DISABLED ) */

	/* Test libhmac_sha1_finalize with memset of internal_context failing
	 */
	hmac_test_memset_attempts_before_fail = 1;

	result = libhmac_sha1_finalize(
	          context,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
	          &error );

	if( hmac_test_memset_attempts_before_fail != -1 )
	{
		hmac_test_memset_attempts_before_fail = -1;
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
#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA_DIGEST_LENGTH ) */

	/* Clean up
	 */
	result = libhmac_sha1_free(
	          &context,
	          &error );

	HMAC_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	HMAC_TEST_ASSERT_IS_NULL(
	 "context",
	 context );

	HMAC_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( context != NULL )
	{
		libhmac_sha1_free(
		 &context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libhmac_sha1_calculate function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_sha1_calculate(
     void )
{
	uint8_t data[ 208 ];
	uint8_t hash[ LIBHMAC_SHA1_HASH_SIZE ];

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
	result = libhmac_sha1_calculate(
	          data,
	          208,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
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

	/* Test libhmac_sha1_calculate with malloc failing in libhmac_sha1_initialize
	 */
	hmac_test_malloc_attempts_before_fail = 0;

	result = libhmac_sha1_calculate(
	          data,
	          208,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
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

	/* Test libhmac_sha1_calculate with libhmac_sha1_update failing
	 */
	result = libhmac_sha1_calculate(
	          NULL,
	          208,
	          hash,
	          LIBHMAC_SHA1_HASH_SIZE,
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

	/* Test libhmac_sha1_calculate with libhmac_sha1_finalize failing
	 */
	result = libhmac_sha1_calculate(
	          data,
	          208,
	          NULL,
	          LIBHMAC_SHA1_HASH_SIZE,
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

/* Tests the libhmac_sha1_calculate_hmac function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_sha1_calculate_hmac(
     void )
{
	uint8_t data[ 208 ];
	uint8_t hmac[ LIBHMAC_SHA1_HASH_SIZE ];
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
	result = libhmac_sha1_calculate_hmac(
	          key,
	          16,
	          data,
	          208,
	          hmac,
	          LIBHMAC_SHA1_HASH_SIZE,
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
	result = libhmac_sha1_calculate_hmac(
	          NULL,
	          16,
	          data,
	          208,
	          hmac,
	          LIBHMAC_SHA1_HASH_SIZE,
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

	result = libhmac_sha1_calculate_hmac(
	          key,
	          (size_t) SSIZE_MAX + 1,
	          data,
	          208,
	          hmac,
	          LIBHMAC_SHA1_HASH_SIZE,
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

	result = libhmac_sha1_calculate_hmac(
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

	/* Test libhmac_sha1_calculate_hmac with malloc failing
	 */
	hmac_test_malloc_attempts_before_fail = 0;

	result = libhmac_sha1_calculate_hmac(
	          key,
	          16,
	          data,
	          208,
	          hmac,
	          LIBHMAC_SHA1_HASH_SIZE,
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

/* TODO add tests for key_size > block_size and libhmac_sha1_initialize failing */

/* TODO add tests for key_size > block_size and libhmac_sha1_update failing */

/* TODO add tests for key_size > block_size and libhmac_sha1_finalize failing */

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

#if !defined( LIBHMAC_HAVE_SHA1_SUPPORT )

	/* TODO add tests for libhmac_sha1_transform */

#endif /* !defined( LIBHMAC_HAVE_SHA1_SUPPORT ) */

	HMAC_TEST_RUN(
	 "libhmac_sha1_initialize",
	 hmac_test_sha1_initialize );

	HMAC_TEST_RUN(
	 "libhmac_sha1_free",
	 hmac_test_sha1_free );

	HMAC_TEST_RUN(
	 "libhmac_sha1_update",
	 hmac_test_sha1_update );

	HMAC_TEST_RUN(
	 "libhmac_sha1_finalize",
	 hmac_test_sha1_finalize );

	HMAC_TEST_RUN(
	 "libhmac_sha1_calculate",
	 hmac_test_sha1_calculate );

	HMAC_TEST_RUN(
	 "libhmac_sha1_calculate_hmac",
	 hmac_test_sha1_calculate_hmac );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

