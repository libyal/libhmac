/*
 * Python definition of the libhmac SHA224 functions
 *
 * Copyright (C) 2010-2023, Joachim Metz <joachim.metz@gmail.com>
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pyhmac_error.h"
#include "pyhmac_libhmac.h"
#include "pyhmac_sha224.h"
#include "pyhmac_python.h"
#include "pyhmac_unused.h"

/* Calculates the SHA224 of the data
 * Returns 1 if successful or -1 on error
 */
PyObject *pyhmac_sha224_calculate(
           PyObject *self PYHMAC_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	uint8_t sha224_hash[ LIBHMAC_SHA224_HASH_SIZE ];

	PyObject *bytes_object      = NULL;
	libcerror_error_t *error    = NULL;
	const char *data            = NULL;
	static char *function       = "pyhmac_sha224_calculate";
	static char *keyword_list[] = { "data", NULL };
	Py_ssize_t data_size        = 0;
	int result                  = 0;

	PYHMAC_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "O",
	     keyword_list,
	     &bytes_object ) == 0 )
	{
		return( NULL );
	}
	PyErr_Clear();

#if PY_MAJOR_VERSION >= 3
	result = PyObject_IsInstance(
	          bytes_object,
	          (PyObject *) &PyBytes_Type );
#else
	result = PyObject_IsInstance(
	          bytes_object,
	          (PyObject *) &PyString_Type );
#endif
	if( result == -1 )
	{
		pyhmac_error_fetch_and_raise(
		 PyExc_RuntimeError,
		 "%s: unable to determine if object is of type bytes.",
		 function );

		return( NULL );
	}
	else if( result == 0 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported bytes object type",
		 function );

		return( NULL );
	}
	PyErr_Clear();

#if PY_MAJOR_VERSION >= 3
	data = PyBytes_AsString(
	        bytes_object );

	data_size = PyBytes_Size(
	             bytes_object );
#else
	data = PyString_AsString(
	        bytes_object );

	data_size = PyString_Size(
	             bytes_object );
#endif
	if( ( data_size < 0 )
	 || ( data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid data size value out of bounds.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libhmac_sha224_calculate(
	          (uint8_t *) data,
	          (size_t) data_size,
	          sha224_hash,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyhmac_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to calculate SHA224 from data.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

#if PY_MAJOR_VERSION >= 3
	bytes_object = PyBytes_FromStringAndSize(
	                (char *) sha224_hash,
	                LIBHMAC_SHA224_HASH_SIZE );
#else
	bytes_object = PyString_FromStringAndSize(
	                (char *) sha224_hash,
	                LIBHMAC_SHA224_HASH_SIZE );
#endif
	if( bytes_object == NULL )
	{
		PyErr_Format(
		 PyExc_IOError,
		 "%s: unable to convert SHA224 hash into bytes object.",
		 function );

		return( NULL );
	}
	return( bytes_object );
}

/* Calculates the SHA224 HMAC of the data
 * Returns 1 if successful or -1 on error
 */
PyObject *pyhmac_sha224_calculate_hmac(
           PyObject *self PYHMAC_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	uint8_t sha224_hmac[ LIBHMAC_SHA224_HASH_SIZE ];

	PyObject *bytes_object      = NULL;
	PyObject *string_object     = NULL;
	libcerror_error_t *error    = NULL;
	const char *data            = NULL;
	static char *function       = "pyhmac_sha224_calculate";
	char *key_data              = NULL;
	static char *keyword_list[] = { "key", "data", NULL };
	Py_ssize_t data_size        = 0;
        Py_ssize_t key_data_size    = 0;
	int result                  = 0;

	PYHMAC_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OO",
	     keyword_list,
	     &string_object,
	     &bytes_object ) == 0 )
	{
		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	key_data = PyBytes_AsString(
	            string_object );

	key_data_size = PyBytes_Size(
	                 string_object );
#else
	key_data = PyString_AsString(
	            string_object );

	key_data_size = PyString_Size(
	                 string_object );
#endif
	if( ( key_data_size < 0 )
	 || ( key_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument key data size value out of bounds.",
		 function );

		return( NULL );
	}
	PyErr_Clear();

#if PY_MAJOR_VERSION >= 3
	result = PyObject_IsInstance(
	          bytes_object,
	          (PyObject *) &PyBytes_Type );
#else
	result = PyObject_IsInstance(
	          bytes_object,
	          (PyObject *) &PyString_Type );
#endif
	if( result == -1 )
	{
		pyhmac_error_fetch_and_raise(
		 PyExc_RuntimeError,
		 "%s: unable to determine if object is of type bytes.",
		 function );

		return( NULL );
	}
	else if( result == 0 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported bytes object type",
		 function );

		return( NULL );
	}
	PyErr_Clear();

#if PY_MAJOR_VERSION >= 3
	data = PyBytes_AsString(
	        bytes_object );

	data_size = PyBytes_Size(
	             bytes_object );
#else
	data = PyString_AsString(
	        bytes_object );

	data_size = PyString_Size(
	             bytes_object );
#endif
	if( ( data_size < 0 )
	 || ( data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid data size value out of bounds.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libhmac_sha224_calculate_hmac(
	          (uint8_t *) key_data,
	          key_data_size,
	          (uint8_t *) data,
	          (size_t) data_size,
	          sha224_hmac,
	          LIBHMAC_SHA224_HASH_SIZE,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyhmac_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to calculate SHA224 HMAC from data.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

#if PY_MAJOR_VERSION >= 3
	bytes_object = PyBytes_FromStringAndSize(
	                (char *) sha224_hmac,
	                LIBHMAC_SHA224_HASH_SIZE );
#else
	bytes_object = PyString_FromStringAndSize(
	                (char *) sha224_hmac,
	                LIBHMAC_SHA224_HASH_SIZE );
#endif
	if( bytes_object == NULL )
	{
		PyErr_Format(
		 PyExc_IOError,
		 "%s: unable to convert SHA224 HMAC into bytes object.",
		 function );

		return( NULL );
	}
	return( bytes_object );
}

