/*
 * Python object wrapper of libhmac_sha224_context_t
 *
 * Copyright (C) 2011-2024, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _PYHMAC_SHA224_CONTEXT_H )
#define _PYHMAC_SHA224_CONTEXT_H

#include <common.h>
#include <types.h>

#include "pyhmac_libhmac.h"
#include "pyhmac_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pyhmac_sha224_context pyhmac_sha224_context_t;

struct pyhmac_sha224_context
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The libhmac SHA224 context
	 */
	libhmac_sha224_context_t *sha224_context;
};

extern PyMethodDef pyhmac_sha224_context_object_methods[];
extern PyTypeObject pyhmac_sha224_context_type_object;

PyObject *pyhmac_sha224_context_new(
           void );

int pyhmac_sha224_context_init(
     pyhmac_sha224_context_t *pyhmac_sha224_context );

void pyhmac_sha224_context_free(
      pyhmac_sha224_context_t *pyhmac_sha224_context );

PyObject *pyhmac_sha224_context_update(
           pyhmac_sha224_context_t *pyhmac_sha224_context,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pyhmac_sha224_context_finalize(
           pyhmac_sha224_context_t *pyhmac_sha224_context,
           PyObject *arguments );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _PYHMAC_SHA224_CONTEXT_H ) */

