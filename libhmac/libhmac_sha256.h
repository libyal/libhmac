/*
 * SHA-256 functions
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

#if !defined( _LIBHMAC_SHA256_H )
#define _LIBHMAC_SHA256_H

#include <common.h>
#include <types.h>

#include "libhmac_extern.h"
#include "libhmac_libcerror.h"
#include "libhmac_types.h"

#if defined( __cplusplus )
extern "C" {
#endif

LIBHMAC_EXTERN \
int libhmac_sha256_initialize(
     libhmac_sha256_context_t **context,
     libcerror_error_t **error );

LIBHMAC_EXTERN \
int libhmac_sha256_free(
     libhmac_sha256_context_t **context,
     libcerror_error_t **error );

LIBHMAC_EXTERN \
int libhmac_sha256_update(
     libhmac_sha256_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libcerror_error_t **error );

LIBHMAC_EXTERN \
int libhmac_sha256_finalize(
     libhmac_sha256_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libcerror_error_t **error );

LIBHMAC_EXTERN \
int libhmac_sha256_calculate(
     const uint8_t *buffer,
     size_t size,
     uint8_t *hash,
     size_t hash_size,
     libcerror_error_t **error );

LIBHMAC_EXTERN \
int libhmac_sha256_calculate_hmac(
     const uint8_t *key,
     size_t key_size,
     const uint8_t *buffer,
     size_t size,
     uint8_t *hmac,
     size_t hmac_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBHMAC_SHA256_H ) */

