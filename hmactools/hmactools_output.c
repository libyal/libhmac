/*
 * Output functions
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
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>
#include <wide_string.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#if defined( HAVE_STRING_H ) || defined( WINAPI )
#include <string.h>
#endif

#include "hmactools_i18n.h"
#include "hmactools_libcerror.h"
#include "hmactools_libclocale.h"
#include "hmactools_libcnotify.h"
#include "hmactools_libhmac.h"
#include "hmactools_libuna.h"
#include "hmactools_output.h"

/* Initializes output settings
 * Returns 1 if successful or -1 on error
 */
int hmactools_output_initialize(
     int stdio_mode,
     libcerror_error_t **error )
{
	static char *function = "hmactools_output_initialize";

	if( ( stdio_mode != _IOFBF )
	 && ( stdio_mode != _IOLBF )
	 && ( stdio_mode != _IONBF ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported standard IO mode.",
		 function );

		return( -1 );
	}
#if !defined( __BORLANDC__ )
	if( setvbuf(
	     stdout,
	     NULL,
	     stdio_mode,
	     0 ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set IO mode of stdout.",
		 function );

		return( -1 );
	}
	if( setvbuf(
	     stderr,
	     NULL,
	     stdio_mode,
	     0 ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set IO mode of stderr.",
		 function );

		return( -1 );
	}
#endif /* !defined( __BORLANDC__ ) */

	return( 1 );
}

/* Prints the copyright information
 */
void hmactools_output_copyright_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	/* TRANSLATORS: This is a proper name.
	 */
	fprintf(
	 stream,
	 _( "Copyright (C) 2011-2023, %s.\n" ),
	 _( "Joachim Metz" ) );

	fprintf(
	 stream,
	 _( "This is free software; see the source for copying conditions. There is NO\n"
	    "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n" ) );

	/* TRANSLATORS: The placeholder indicates the bug-reporting address
	 * for this package.  Please add _another line_ saying
	 * "Report translation bugs to <...>\n" with the address for translation
	 * bugs (typically your translation team's web or email address).
	 */
	fprintf(
	 stream,
	 _( "Report bugs to <%s>.\n" ),
	 PACKAGE_BUGREPORT );
}

/* Prints the version information to a stream
 */
void hmactools_output_version_fprint(
      FILE *stream,
      const system_character_t *program )
{
	if( stream == NULL )
	{
		return;
	}
	if( program == NULL )
	{
		return;
	}
	fprintf(
	 stream,
	 "%" PRIs_SYSTEM " %s\n\n",
	 program,
	 LIBHMAC_VERSION_STRING );
}

/* Prints the detailed version information to a stream
 */
void hmactools_output_version_detailed_fprint(
      FILE *stream,
      const system_character_t *program )
{
	if( stream == NULL )
	{
		return;
	}
	if( program == NULL )
	{
		return;
	}
	fprintf(
	 stream,
	 "%" PRIs_SYSTEM " %s (libhmac %s",
	 program,
	 LIBHMAC_VERSION_STRING,
	 LIBHMAC_VERSION_STRING );

#if defined( HAVE_LIBUNA ) || defined( HAVE_LOCAL_LIBUNA )
	fprintf(
	 stream,
	 ", libuna %s",
	 LIBUNA_VERSION_STRING );
#endif

	fprintf(
	 stream,
	 ")\n\n" );
}

