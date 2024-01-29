/*
 * Python definition of the libhmac SHA256 functions
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

#if !defined( _PYHMAC_SHA256_H )
#define _PYHMAC_SHA256_H

#include <common.h>
#include <types.h>

#include "pyhmac_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

PyObject *pyhmac_sha256_calculate(
           PyObject *self,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pyhmac_sha256_calculate_hmac(
           PyObject *self,
           PyObject *arguments,
           PyObject *keywords );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _PYHMAC_SHA256_H ) */

