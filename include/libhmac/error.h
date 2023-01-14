/*
 * The error code definitions for libhmac
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

#if !defined( _LIBHMAC_ERROR_H )
#define _LIBHMAC_ERROR_H

#include <libhmac/types.h>

/* External error type definition hides internal structure
 */
typedef intptr_t libhmac_error_t;

/* The error domains
 */
enum LIBHMAC_ERROR_DOMAINS
{
	LIBHMAC_ERROR_DOMAIN_ARGUMENTS			= (int) 'a',
	LIBHMAC_ERROR_DOMAIN_CONVERSION			= (int) 'c',
	LIBHMAC_ERROR_DOMAIN_COMPRESSION		= (int) 'C',
	LIBHMAC_ERROR_DOMAIN_IO				= (int) 'I',
	LIBHMAC_ERROR_DOMAIN_INPUT			= (int) 'i',
	LIBHMAC_ERROR_DOMAIN_MEMORY			= (int) 'm',
	LIBHMAC_ERROR_DOMAIN_OUTPUT			= (int) 'o',
	LIBHMAC_ERROR_DOMAIN_RUNTIME			= (int) 'r'
};

/* The argument error codes
 * to signify errors regarding arguments passed to a function
 */
enum LIBHMAC_ARGUMENT_ERROR
{
	LIBHMAC_ARGUMENT_ERROR_GENERIC			= 0,

	/* The argument contains an invalid value
	 */
	LIBHMAC_ARGUMENT_ERROR_INVALID_VALUE		= 1,

	/* The argument contains a value less than zero
	 */
	LIBHMAC_ARGUMENT_ERROR_VALUE_LESS_THAN_ZERO	= 2,

	/* The argument contains a value zero or less
	 */
	LIBHMAC_ARGUMENT_ERROR_VALUE_ZERO_OR_LESS	= 3,

	/* The argument contains a value that exceeds the maximum
	 * for the specific type
	 */
	LIBHMAC_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM	= 4,

	/* The argument contains a value that is too small
	 */
	LIBHMAC_ARGUMENT_ERROR_VALUE_TOO_SMALL		= 5,

	/* The argument contains a value that is too large
	 */
	LIBHMAC_ARGUMENT_ERROR_VALUE_TOO_LARGE		= 6,

	/* The argument contains a value that is out of bounds
	 */
	LIBHMAC_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS	= 7,

	/* The argument contains a value that is not supported
	 */
	LIBHMAC_ARGUMENT_ERROR_UNSUPPORTED_VALUE	= 8,

	/* The argument contains a value that conficts with another argument
	 */
	LIBHMAC_ARGUMENT_ERROR_CONFLICTING_VALUE	= 9
};

/* The conversion error codes
 * to signify errors regarding conversions
 */
enum LIBHMAC_CONVERSION_ERROR
{
	LIBHMAC_CONVERSION_ERROR_GENERIC		= 0,

	/* The conversion failed on the input
	 */
	LIBHMAC_CONVERSION_ERROR_INPUT_FAILED		= 1,

	/* The conversion failed on the output
	 */
	LIBHMAC_CONVERSION_ERROR_OUTPUT_FAILED		= 2
};

/* The compression error codes
 * to signify errors regarding compression
 */
enum LIBHMAC_COMPRESSION_ERROR
{
	LIBHMAC_COMPRESSION_ERROR_GENERIC		= 0,

	/* The compression failed
	 */
	LIBHMAC_COMPRESSION_ERROR_COMPRESS_FAILED	= 1,

	/* The decompression failed
	 */
	LIBHMAC_COMPRESSION_ERROR_DECOMPRESS_FAILED	= 2
};

/* The input/output error codes
 * to signify errors regarding input/output
 */
enum LIBHMAC_IO_ERROR
{
	LIBHMAC_IO_ERROR_GENERIC			= 0,

	/* The open failed
	 */
	LIBHMAC_IO_ERROR_OPEN_FAILED			= 1,

	/* The close failed
	 */
	LIBHMAC_IO_ERROR_CLOSE_FAILED			= 2,

	/* The seek failed
	 */
	LIBHMAC_IO_ERROR_SEEK_FAILED			= 3,

	/* The read failed
	 */
	LIBHMAC_IO_ERROR_READ_FAILED			= 4,

	/* The write failed
	 */
	LIBHMAC_IO_ERROR_WRITE_FAILED			= 5,

	/* Access denied
	 */
	LIBHMAC_IO_ERROR_ACCESS_DENIED			= 6,

	/* The resource is invalid i.e. a missing file
	 */
	LIBHMAC_IO_ERROR_INVALID_RESOURCE		= 7,

	/* The ioctl failed
	 */
	LIBHMAC_IO_ERROR_IOCTL_FAILED			= 8,

	/* The unlink failed
	 */
	LIBHMAC_IO_ERROR_UNLINK_FAILED			= 9
};

/* The input error codes
 * to signify errors regarding handing input data
 */
enum LIBHMAC_INPUT_ERROR
{
	LIBHMAC_INPUT_ERROR_GENERIC			= 0,

	/* The input contains invalid data
	 */
	LIBHMAC_INPUT_ERROR_INVALID_DATA		= 1,

	/* The input contains an unsupported signature
	 */
	LIBHMAC_INPUT_ERROR_SIGNATURE_MISMATCH		= 2,

	/* A checksum in the input did not match
	 */
	LIBHMAC_INPUT_ERROR_CHECKSUM_MISMATCH		= 3,

	/* A value in the input did not match a previously
	 * read value or calculated value
	 */
	LIBHMAC_INPUT_ERROR_VALUE_MISMATCH		= 4
};

/* The memory error codes
 * to signify errors regarding memory
 */
enum LIBHMAC_MEMORY_ERROR
{
	LIBHMAC_MEMORY_ERROR_GENERIC			= 0,

	/* There is insufficient memory available
	 */
	LIBHMAC_MEMORY_ERROR_INSUFFICIENT		= 1,

	/* The memory failed to be copied
	 */
	LIBHMAC_MEMORY_ERROR_COPY_FAILED		= 2,

	/* The memory failed to be set
	 */
	LIBHMAC_MEMORY_ERROR_SET_FAILED			= 3
};

/* The output error codes
 */
enum LIBHMAC_OUTPUT_ERROR
{
	LIBHMAC_OUTPUT_ERROR_GENERIC			= 0,

	/* There is insuficient space to write the output
	 */
	LIBHMAC_OUTPUT_ERROR_INSUFFICIENT_SPACE		= 1
};

/* The runtime error codes
 * to signify errors regarding runtime processing
 */
enum LIBHMAC_RUNTIME_ERROR
{
	LIBHMAC_RUNTIME_ERROR_GENERIC			= 0,

	/* The value is missing
	 */
	LIBHMAC_RUNTIME_ERROR_VALUE_MISSING		= 1,

	/* The value was already set
	 */
	LIBHMAC_RUNTIME_ERROR_VALUE_ALREADY_SET		= 2,

	/* The creation and/or initialization of an internal structure failed
	 */
	LIBHMAC_RUNTIME_ERROR_INITIALIZE_FAILED		= 3,

	/* The resize of an internal structure failed
	 */
	LIBHMAC_RUNTIME_ERROR_RESIZE_FAILED		= 4,

	/* The free and/or finalization of an internal structure failed
	 */
	LIBHMAC_RUNTIME_ERROR_FINALIZE_FAILED		= 5,

	/* The value could not be determined
	 */
	LIBHMAC_RUNTIME_ERROR_GET_FAILED		= 6,

	/* The value could not be set
	 */
	LIBHMAC_RUNTIME_ERROR_SET_FAILED		= 7,

	/* The value could not be appended/prepended
	 */
	LIBHMAC_RUNTIME_ERROR_APPEND_FAILED		= 8,

	/* The value could not be copied
	 */
	LIBHMAC_RUNTIME_ERROR_COPY_FAILED		= 9,

	/* The value could not be removed
	 */
	LIBHMAC_RUNTIME_ERROR_REMOVE_FAILED		= 10,

	/* The value could not be printed
	 */
	LIBHMAC_RUNTIME_ERROR_PRINT_FAILED		= 11,

	/* The value was out of bounds
	 */
	LIBHMAC_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS	= 12,

	/* The value exceeds the maximum for its specific type
	 */
	LIBHMAC_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM	= 13,

	/* The value is unsupported
	 */
	LIBHMAC_RUNTIME_ERROR_UNSUPPORTED_VALUE		= 14,

	/* An abort was requested
	 */
	LIBHMAC_RUNTIME_ERROR_ABORT_REQUESTED		= 15
};

#endif /* !defined( _LIBHMAC_ERROR_H ) */

