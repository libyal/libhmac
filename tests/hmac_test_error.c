/*
 * Library error functions test program
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "hmac_test_libhmac.h"
#include "hmac_test_macros.h"
#include "hmac_test_unused.h"

/* Tests the libhmac_error_free function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_error_free(
     void )
{
	/* Test invocation of function only
	 */
	libhmac_error_free(
	 NULL );

	return( 1 );
}

/* Tests the libhmac_error_fprint function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_error_fprint(
     void )
{
	/* Test invocation of function only
	 */
	libhmac_error_fprint(
	 NULL,
	 NULL );

	return( 1 );
}

/* Tests the libhmac_error_sprint function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_error_sprint(
     void )
{
	/* Test invocation of function only
	 */
	libhmac_error_sprint(
	 NULL,
	 NULL,
	 0 );

	return( 1 );
}

/* Tests the libhmac_error_backtrace_fprint function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_error_backtrace_fprint(
     void )
{
	/* Test invocation of function only
	 */
	libhmac_error_backtrace_fprint(
	 NULL,
	 NULL );

	return( 1 );
}

/* Tests the libhmac_error_backtrace_sprint function
 * Returns 1 if successful or 0 if not
 */
int hmac_test_error_backtrace_sprint(
     void )
{
	/* Test invocation of function only
	 */
	libhmac_error_backtrace_sprint(
	 NULL,
	 NULL,
	 0 );

	return( 1 );
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
	 "libhmac_error_free",
	 hmac_test_error_free );

	HMAC_TEST_RUN(
	 "libhmac_error_fprint",
	 hmac_test_error_fprint );

	HMAC_TEST_RUN(
	 "libhmac_error_sprint",
	 hmac_test_error_sprint );

	HMAC_TEST_RUN(
	 "libhmac_error_backtrace_fprint",
	 hmac_test_error_backtrace_fprint );

	HMAC_TEST_RUN(
	 "libhmac_error_backtrace_sprint",
	 hmac_test_error_backtrace_sprint );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

