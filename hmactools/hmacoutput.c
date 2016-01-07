/*
 * Output functions
 *
 * Copyright (C) 2011-2016, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <file_stream.h>
#include <memory.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#if defined( HAVE_STRING_H ) || defined( WINAPI )
#include <string.h>
#endif

#include "hmacoutput.h"
#include "hmactools_libcerror.h"
#include "hmactools_libclocale.h"
#include "hmactools_libcnotify.h"
#include "hmactools_libcstring.h"
#include "hmactools_libcsystem.h"
#include "hmactools_libhmac.h"
#include "hmactools_libuna.h"

/* Prints the executable version information
 */
void hmacoutput_copyright_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf(
	 stream,
	 "Copyright (C) 2011-2016, Joachim Metz <%s>.\n"
	 "This is free software; see the source for copying conditions. There is NO\n"
	 "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
	 PACKAGE_BUGREPORT );
}

/* Prints the version information to a stream
 */
void hmacoutput_version_fprint(
      FILE *stream,
      const libcstring_system_character_t *program )
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
	 "%" PRIs_LIBCSTRING_SYSTEM " %s\n\n",
	 program,
	 LIBHMAC_VERSION_STRING );
}

/* Prints the detailed version information to a stream
 */
void hmacoutput_version_detailed_fprint(
      FILE *stream,
      const libcstring_system_character_t *program )
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
	 "%" PRIs_LIBCSTRING_SYSTEM " %s (libhmac %s",
	 program,
	 LIBHMAC_VERSION_STRING,
	 LIBHMAC_VERSION_STRING );

	fprintf(
	 stream,
	 ", libcsystem %s",
	 LIBCSYSTEM_VERSION_STRING );

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

