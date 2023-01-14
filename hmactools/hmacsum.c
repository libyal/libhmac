/*
 * hmacsum
 * Calculates a Hash-based Message Authentication Code (HMAC) of the data in a file
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

#include <stdio.h>

#if defined( HAVE_IO_H ) || defined( WINAPI )
#include <io.h>
#endif

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#if defined( HAVE_UNISTD_H )
#include <unistd.h>
#endif

#include "hmactools_getopt.h"
#include "hmactools_libcerror.h"
#include "hmactools_libclocale.h"
#include "hmactools_libcnotify.h"
#include "hmactools_libhmac.h"
#include "hmactools_output.h"
#include "hmactools_signal.h"
#include "hmactools_unused.h"
#include "sum_handle.h"

sum_handle_t *hmacsum_sum_handle = NULL;
int hmacsum_abort                = 0;

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use hmacsum to calculate a Hash-based Message Authentication Code (HMAC)\n"
	                 "of the data in a file.\n\n" );

	fprintf( stream, "Usage: hmacsum [ -d digest_type ] [ -p process_buffer_size ] [ -hvV ]\n"
	                 "               source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-d:     calculate digest (hash) types option: md5 (default), sha1,\n"
	                 "\t        sha224, sha256, sha512 (multiple types can be combined\n"
	                 "\t        with a ,)\n" );
	fprintf( stream, "\t-p:     specify the process buffer size (default is 32768 bytes)\n" );
	fprintf( stream, "\t-h:     shows this help\n" );
	fprintf( stream, "\t-v:     verbose output to stderr\n" );
	fprintf( stream, "\t-V:     print version\n" );
}

/* Signal handler for hmacsum
 */
void hmacsum_signal_handler(
      hmactools_signal_t signal HMACTOOLS_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error = NULL;
	static char *function    = "hmacsum_signal_handler";

	HMACTOOLS_UNREFERENCED_PARAMETER( signal )

	hmacsum_abort = 1;

	if( ( hmacsum_sum_handle != NULL )
	 && ( sum_handle_signal_abort(
	       hmacsum_sum_handle,
	       &error ) != 1 ) )
	{
		libcnotify_printf(
		 "%s: unable to signal sum handle to abort.\n",
		 function );

		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	/* Force stdin to close otherwise any function reading it will remain blocked
	 */
#if defined( WINAPI ) && !defined( __CYGWIN__ )
	if( _close(
	     0 ) != 0 )
#else
	if( close(
	     0 ) != 0 )
#endif
	{
		libcnotify_printf(
		 "%s: unable to close stdin.\n",
		 function );
	}
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] )
#else
int main( int argc, char * const argv[] )
#endif
{
	libcerror_error_t *error                       = NULL;
	system_character_t *option_digest_types        = NULL;
	system_character_t *option_process_buffer_size = NULL;
	system_character_t *program                    = _SYSTEM_STRING( "hmacsum" );
	system_character_t *source                     = NULL;
	system_integer_t option                        = 0;
	uint8_t verbose                                = 0;
	int result                                     = 0;

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 1 );

	if( libclocale_initialize(
	     "hmactools",
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize locale values.\n" );

		goto on_error;
	}
	if( hmactools_output_initialize(
	     _IONBF,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize output settings.\n" );

		goto on_error;
	}
	hmactools_output_version_fprint(
	 stdout,
	 program );

	while( ( option = hmactools_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "d:hp:vV" ) ) ) != (system_integer_t) -1 )
	{
		switch( option )
		{
			case (system_integer_t) '?':
			default:
				fprintf(
				 stderr,
				 "Invalid argument: %" PRIs_SYSTEM "\n",
				 argv[ optind - 1 ] );

				usage_fprint(
				 stdout );

				goto on_error;

			case (system_integer_t) 'd':
				option_digest_types = optarg;

				break;

			case (system_integer_t) 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case (system_integer_t) 'p':
				option_process_buffer_size = optarg;

				break;

			case (system_integer_t) 'v':
				verbose = 1;

				break;

			case (system_integer_t) 'V':
				hmactools_output_copyright_fprint(
				 stdout );

				return( EXIT_SUCCESS );
		}
	}
	if( optind == argc )
	{
		fprintf(
		 stderr,
		 "Missing soure file.\n" );

		usage_fprint(
		 stdout );

		goto on_error;
	}
	source = argv[ optind ];

	libcnotify_verbose_set(
	 verbose );

	if( sum_handle_initialize(
	     &hmacsum_sum_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create sum handle.\n" );

		goto on_error;
	}
	if( option_process_buffer_size != NULL )
	{
		result = sum_handle_set_process_buffer_size(
			  hmacsum_sum_handle,
			  option_process_buffer_size,
			  &error );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to set process buffer size.\n" );

			goto on_error;
		}
		else if( ( result == 0 )
		      || ( hmacsum_sum_handle->process_buffer_size > (size_t) SSIZE_MAX ) )
		{
			hmacsum_sum_handle->process_buffer_size = 32768;

			fprintf(
			 stderr,
			 "Unsupported process buffer size defaulting to: 32768.\n" );
		}
	}
	if( option_digest_types != NULL )
	{
		result = sum_handle_set_digest_types(
			  hmacsum_sum_handle,
			  option_digest_types,
			  &error );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to set digest types.\n" );

			goto on_error;
		}
	}
	if( hmactools_signal_attach(
	     hmacsum_signal_handler,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to attach signal handler.\n" );

		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	result = sum_handle_open_input(
	          hmacsum_sum_handle,
	          source,
	          &error );

	if( hmacsum_abort != 0 )
	{
		goto on_abort;
	}
	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open input.\n" );

		goto on_error;
	}
	result = sum_handle_process_input(
	          hmacsum_sum_handle,
	          &error );

	if( hmacsum_abort != 0 )
	{
		goto on_abort;
	}
	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to process input.\n" );

		goto on_error;
	}
	if( sum_handle_hash_values_fprint(
	    hmacsum_sum_handle,
	    stdout,
	    &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to print hash values.\n" );

		goto on_error;
	}
on_abort:
	if( sum_handle_close(
	     hmacsum_sum_handle,
	     &error ) != 0 )
	{
		fprintf(
		 stderr,
		 "Unable to close sum handle.\n" );

		goto on_error;
	}
	if( hmactools_signal_detach(
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to detach signal handler.\n" );

		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( sum_handle_free(
	     &hmacsum_sum_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free sum handle.\n" );

		goto on_error;
	}
	if( hmacsum_abort != 0 )
	{
		fprintf(
		 stdout,
		 "%" PRIs_SYSTEM ": ABORTED\n",
		 program );

		return( EXIT_FAILURE );
	}
	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( hmacsum_sum_handle != NULL )
	{
		sum_handle_free(
		 &hmacsum_sum_handle,
		 NULL );
	}
	return( EXIT_FAILURE );
}

