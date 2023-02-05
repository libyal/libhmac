/*
 * Python bindings module for libhmac (pyhmac)
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
#include <narrow_string.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pyhmac.h"
#include "pyhmac_libhmac.h"
#include "pyhmac_libcerror.h"
#include "pyhmac_python.h"
#include "pyhmac_unused.h"

/* The pyhmac module methods
 */
PyMethodDef pyhmac_module_methods[] = {
	{ "get_version",
	  (PyCFunction) pyhmac_get_version,
	  METH_NOARGS,
	  "get_version() -> String\n"
	  "\n"
	  "Retrieves the version." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

/* Retrieves the pyhmac/libhmac version
 * Returns a Python object if successful or NULL on error
 */
PyObject *pyhmac_get_version(
           PyObject *self PYHMAC_ATTRIBUTE_UNUSED,
           PyObject *arguments PYHMAC_ATTRIBUTE_UNUSED )
{
	const char *errors           = NULL;
	const char *version_string   = NULL;
	size_t version_string_length = 0;

	PYHMAC_UNREFERENCED_PARAMETER( self )
	PYHMAC_UNREFERENCED_PARAMETER( arguments )

	Py_BEGIN_ALLOW_THREADS

	version_string = libhmac_get_version();

	Py_END_ALLOW_THREADS

	version_string_length = narrow_string_length(
	                         version_string );

	/* Pass the string length to PyUnicode_DecodeUTF8
	 * otherwise it makes the end of string character is part
	 * of the string
	 */
	return( PyUnicode_DecodeUTF8(
	         version_string,
	         (Py_ssize_t) version_string_length,
	         errors ) );
}

#if PY_MAJOR_VERSION >= 3

/* The pyhmac module definition
 */
PyModuleDef pyhmac_module_definition = {
	PyModuleDef_HEAD_INIT,

	/* m_name */
	"pyhmac",
	/* m_doc */
	"Python libhmac module (pyhmac).",
	/* m_size */
	-1,
	/* m_methods */
	pyhmac_module_methods,
	/* m_reload */
	NULL,
	/* m_traverse */
	NULL,
	/* m_clear */
	NULL,
	/* m_free */
	NULL,
};

#endif /* PY_MAJOR_VERSION >= 3 */

/* Initializes the pyhmac module
 */
#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_pyhmac(
                void )
#else
PyMODINIT_FUNC initpyhmac(
                void )
#endif
{
	PyObject *module           = NULL;
	PyGILState_STATE gil_state = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	libhmac_notify_set_stream(
	 stderr,
	 NULL );
	libhmac_notify_set_verbose(
	 1 );
#endif

	/* Create the module
	 * This function must be called before grabbing the GIL
	 * otherwise the module will segfault on a version mismatch
	 */
#if PY_MAJOR_VERSION >= 3
	module = PyModule_Create(
	          &pyhmac_module_definition );
#else
	module = Py_InitModule3(
	          "pyhmac",
	          pyhmac_module_methods,
	          "Python libhmac module (pyhmac)." );
#endif
	if( module == NULL )
	{
#if PY_MAJOR_VERSION >= 3
		return( NULL );
#else
		return;
#endif
	}
#if PY_VERSION_HEX < 0x03070000
	PyEval_InitThreads();
#endif
	gil_state = PyGILState_Ensure();

/* TODO */

	PyGILState_Release(
	 gil_state );

#if PY_MAJOR_VERSION >= 3
	return( module );
#else
	return;
#endif

on_error:
	PyGILState_Release(
	 gil_state );

#if PY_MAJOR_VERSION >= 3
	return( NULL );
#else
	return;
#endif
}

