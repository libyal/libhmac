/*
 * Python object wrapper of libhmac_sha512_context_t
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pyhmac_error.h"
#include "pyhmac_libhmac.h"
#include "pyhmac_libcerror.h"
#include "pyhmac_python.h"
#include "pyhmac_sha512_context.h"
#include "pyhmac_unused.h"

PyMethodDef pyhmac_sha512_context_object_methods[] = {

	{ "update",
	  (PyCFunction) pyhmac_sha512_context_update,
	  METH_VARARGS | METH_KEYWORDS,
	  "update(data) -> None\n"
	  "\n"
	  "Updates the SHA512 context." },

	{ "finalize",
	  (PyCFunction) pyhmac_sha512_context_finalize,
	  METH_NOARGS,
	  "finalize() -> Bytes\n"
	  "\n"
	  "Finalizes the SHA512 context." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

PyGetSetDef pyhmac_sha512_context_object_get_set_definitions[] = {

	/* Sentinel */
	{ NULL, NULL, NULL, NULL, NULL }
};

PyTypeObject pyhmac_sha512_context_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pyhmac.sha512_context",
	/* tp_basicsize */
	sizeof( pyhmac_sha512_context_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pyhmac_sha512_context_free,
	/* tp_print */
	0,
	/* tp_getattr */
	0,
	/* tp_setattr */
	0,
	/* tp_compare */
	0,
	/* tp_repr */
	0,
	/* tp_as_number */
	0,
	/* tp_as_sequence */
	0,
	/* tp_as_mapping */
	0,
	/* tp_hash */
	0,
	/* tp_call */
	0,
	/* tp_str */
	0,
	/* tp_getattro */
	0,
	/* tp_setattro */
	0,
	/* tp_as_buffer */
	0,
	/* tp_flags */
	Py_TPFLAGS_DEFAULT,
	/* tp_doc */
	"pyhmac sha512_context object (wraps libhmac_sha512_context_t)",
	/* tp_traverse */
	0,
	/* tp_clear */
	0,
	/* tp_richcompare */
	0,
	/* tp_weaklistoffset */
	0,
	/* tp_iter */
	0,
	/* tp_iternext */
	0,
	/* tp_methods */
	pyhmac_sha512_context_object_methods,
	/* tp_members */
	0,
	/* tp_getset */
	pyhmac_sha512_context_object_get_set_definitions,
	/* tp_base */
	0,
	/* tp_dict */
	0,
	/* tp_descr_get */
	0,
	/* tp_descr_set */
	0,
	/* tp_dictoffset */
	0,
	/* tp_init */
	(initproc) pyhmac_sha512_context_init,
	/* tp_alloc */
	0,
	/* tp_new */
	0,
	/* tp_free */
	0,
	/* tp_is_gc */
	0,
	/* tp_bases */
	NULL,
	/* tp_mro */
	NULL,
	/* tp_cache */
	NULL,
	/* tp_subclasses */
	NULL,
	/* tp_weaklist */
	NULL,
	/* tp_del */
	0
};

/* Creates a new SHA512 context object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pyhmac_sha512_context_new(
           void )
{
	pyhmac_sha512_context_t *pyhmac_sha512_context = NULL;
	static char *function                          = "pyhmac_sha512_context_new";

	pyhmac_sha512_context = PyObject_New(
	                         struct pyhmac_sha512_context,
	                         &pyhmac_sha512_context_type_object );

	if( pyhmac_sha512_context == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize SHA512 context.",
		 function );

		goto on_error;
	}
	if( pyhmac_sha512_context_init(
	     pyhmac_sha512_context ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize SHA512 context.",
		 function );

		goto on_error;
	}
	return( (PyObject *) pyhmac_sha512_context );

on_error:
	if( pyhmac_sha512_context != NULL )
	{
		Py_DecRef(
		 (PyObject *) pyhmac_sha512_context );
	}
	return( NULL );
}

/* Initializes a SHA512 context object
 * Returns 0 if successful or -1 on error
 */
int pyhmac_sha512_context_init(
     pyhmac_sha512_context_t *pyhmac_sha512_context )
{
	libcerror_error_t *error = NULL;
	static char *function    = "pyhmac_sha512_context_init";

	if( pyhmac_sha512_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid SHA512 context.",
		 function );

		return( -1 );
	}
	pyhmac_sha512_context->sha512_context = NULL;

	if( libhmac_sha512_initialize(
	     &( pyhmac_sha512_context->sha512_context ),
	     &error ) != 1 )
	{
		pyhmac_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to initialize SHA512 context.",
		 function );

		libcerror_error_free(
		 &error );

		return( -1 );
	}
	return( 0 );
}

/* Frees a SHA512 context object
 */
void pyhmac_sha512_context_free(
      pyhmac_sha512_context_t *pyhmac_sha512_context )
{
	struct _typeobject *ob_type = NULL;
	libcerror_error_t *error    = NULL;
	static char *function       = "pyhmac_sha512_context_free";
	int result                  = 0;

	if( pyhmac_sha512_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid SHA512 context.",
		 function );

		return;
	}
	if( pyhmac_sha512_context->sha512_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid SHA512 context - missing libhmac SHA512 context.",
		 function );

		return;
	}
	ob_type = Py_TYPE(
	           pyhmac_sha512_context );

	if( ob_type == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: missing ob_type.",
		 function );

		return;
	}
	if( ob_type->tp_free == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid ob_type - missing tp_free.",
		 function );

		return;
	}
	Py_BEGIN_ALLOW_THREADS

	result = libhmac_sha512_free(
	          &( pyhmac_sha512_context->sha512_context ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyhmac_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to free libhmac SHA512 context.",
		 function );

		libcerror_error_free(
		 &error );
	}
	ob_type->tp_free(
	 (PyObject*) pyhmac_sha512_context );
}

/* Updates the SHA512 context
 * Returns 1 if successful or -1 on error
 */
PyObject *pyhmac_sha512_context_update(
           pyhmac_sha512_context_t *pyhmac_sha512_context,
           PyObject *arguments,
           PyObject *keywords )
{
	PyObject *bytes_object      = NULL;
	libcerror_error_t *error    = NULL;
	const char *data            = NULL;
	static char *function       = "pyhmac_sha512_context_update";
	static char *keyword_list[] = { "data", NULL };
	Py_ssize_t data_size        = 0;
	int result                  = 0;

	if( pyhmac_sha512_context == NULL )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: invalid SHA512 context.",
		 function );

		return( NULL );
	}
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

	result = libhmac_sha512_update(
	          pyhmac_sha512_context->sha512_context,
	          (uint8_t *) data,
	          (size_t) data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyhmac_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to update SHA512 context from data.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

/* Finalize the SHA512 context
 * Returns 1 if successful or -1 on error
 */
PyObject *pyhmac_sha512_context_finalize(
           pyhmac_sha512_context_t *pyhmac_sha512_context,
           PyObject *arguments )
{
	uint8_t sha512_hash[ LIBHMAC_SHA512_HASH_SIZE ];

	PyObject *bytes_object   = NULL;
	libcerror_error_t *error = NULL;
	static char *function    = "pyhmac_sha512_context_finalize";
	int result               = 0;

	PYHMAC_UNREFERENCED_PARAMETER( arguments )

	if( pyhmac_sha512_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid SHA512 context.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libhmac_sha512_finalize(
	          pyhmac_sha512_context->sha512_context,
	          sha512_hash,
	          LIBHMAC_SHA512_HASH_SIZE,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyhmac_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to finalize SHA512 context.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	bytes_object = PyBytes_FromStringAndSize(
	                (char *) sha512_hash,
	                LIBHMAC_SHA512_HASH_SIZE );
#else
	bytes_object = PyString_FromStringAndSize(
	                (char *) sha512_hash,
	                LIBHMAC_SHA512_HASH_SIZE );
#endif
	if( bytes_object == NULL )
	{
		PyErr_Format(
		 PyExc_IOError,
		 "%s: unable to convert SHA512 hash into bytes object.",
		 function );

		return( NULL );
	}
	return( bytes_object );
}

