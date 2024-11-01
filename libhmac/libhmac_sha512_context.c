/*
 * SHA-512 functions
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

#include <common.h>
#include <byte_stream.h>
#include <memory.h>
#include <types.h>

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H )
#include <openssl/sha.h>

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#include "libhmac_byte_stream.h"
#include "libhmac_definitions.h"
#include "libhmac_libcerror.h"
#include "libhmac_sha512_context.h"

#if !defined( LIBHMAC_HAVE_SHA512_SUPPORT )

/* FIPS 180-2 based SHA-512 functions
 */

/* The first 64-bits of the fractional parts of the square roots of the first 8 primes [ 2, 19 ]
 */
uint64_t libhmac_sha512_context_prime_square_roots[ 8 ] = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

/* The first 64-bits of the fractional parts of the cube roots of the first 80 primes [ 2, 409 ]
 */
uint64_t libhmac_sha512_context_prime_cube_roots[ 80 ] = {
	0x428a2f98d728ae22,  0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,  0xe9b5dba58189dbbc,
	0x3956c25bf348b538,  0x59f111f1b605d019, 0x923f82a4af194f9b,  0xab1c5ed5da6d8118,
	0xd807aa98a3030242,  0x12835b0145706fbe, 0x243185be4ee4b28c,  0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f,  0x80deb1fe3b1696b1, 0x9bdc06a725c71235,  0xc19bf174cf692694,
	0xe49b69c19ef14ad2,  0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5,  0x240ca1cc77ac9c65,
	0x2de92c6f592b0275,  0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4,  0x76f988da831153b5,
	0x983e5152ee66dfab,  0xa831c66d2db43210, 0xb00327c898fb213f,  0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2,  0xd5a79147930aa725, 0x06ca6351e003826f,  0x142929670a0e6e70,
	0x27b70a8546d22ffc,  0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,  0x53380d139d95b3df,
	0x650a73548baf63de,  0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,  0x92722c851482353b,
	0xa2bfe8a14cf10364,  0xa81a664bbc423001, 0xc24b8b70d0f89791,  0xc76c51a30654be30,
	0xd192e819d6ef5218,  0xd69906245565a910, 0xf40e35855771202a,  0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8,  0x1e376c085141ab53, 0x2748774cdf8eeb99,  0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63,  0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,  0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc,  0x78a5636f43172f60, 0x84c87814a1f0ab72,  0x8cc702081a6439ec,
	0x90befffa23631e28,  0xa4506cebde82bde9, 0xbef9a3f7b2c67915,  0xc67178f2e372532b,
	0xca273eceea26619c,  0xd186b8c721c0c207, 0xeada7dd6cde0eb1e,  0xf57d4f7fee6ed178,
	0x06f067aa72176fba,  0x0a637dc5a2c898a6, 0x113f9804bef90dae,  0x1b710b35131c471b,
	0x28db77f523047d84,  0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,  0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6,  0x597f299cfc657e2a, 0x5fcb6fab3ad6faec,  0x6c44198c4a475817
};

#define libhmac_sha512_context_transform_extend_64bit_value( values_64bit, value_64bit_index, s0, s1 ) \
	s0 = byte_stream_bit_rotate_right_64bit( values_64bit[ value_64bit_index - 15 ], 1 ) \
	   ^ byte_stream_bit_rotate_right_64bit( values_64bit[ value_64bit_index - 15 ], 8 ) \
	   ^ ( values_64bit[ value_64bit_index - 15 ] >> 7 ); \
	s1 = byte_stream_bit_rotate_right_64bit( values_64bit[ value_64bit_index - 2 ], 19 ) \
	   ^ byte_stream_bit_rotate_right_64bit( values_64bit[ value_64bit_index - 2 ], 61 ) \
	   ^ ( values_64bit[ value_64bit_index - 2 ] >> 6 ); \
\
	values_64bit[ value_64bit_index ] = values_64bit[ value_64bit_index - 16 ] \
	                                  + s0 \
	                                  + values_64bit[ value_64bit_index - 7 ] \
	                                  + s1

#define libhmac_sha512_context_transform_unfolded_extend_64bit_values( values_64bit, s0, s1 ) \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 16, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 17, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 18, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 19, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 20, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 21, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 22, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 23, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 24, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 25, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 26, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 27, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 28, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 29, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 30, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 31, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 32, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 33, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 34, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 35, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 36, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 37, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 38, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 39, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 40, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 41, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 42, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 43, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 44, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 45, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 46, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 47, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 48, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 49, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 50, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 51, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 52, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 53, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 54, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 55, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 56, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 57, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 58, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 59, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 60, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 61, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 62, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 63, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 64, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 65, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 66, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 67, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 68, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 69, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 70, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 71, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 72, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 73, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 74, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 75, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 76, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 77, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 78, s0, s1 ); \
	libhmac_sha512_context_transform_extend_64bit_value( values_64bit, 79, s0, s1 );

#define libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, value_64bit_index, hash_values, hash_value_index0, hash_value_index1, hash_value_index2, hash_value_index3, hash_value_index4, hash_value_index5, hash_value_index6, hash_value_index7, s0, s1, t1, t2 ) \
	s0 = byte_stream_bit_rotate_right_64bit( hash_values[ hash_value_index0 ], 28 ) \
	   ^ byte_stream_bit_rotate_right_64bit( hash_values[ hash_value_index0 ], 34 ) \
	   ^ byte_stream_bit_rotate_right_64bit( hash_values[ hash_value_index0 ], 39 ); \
	s1 = byte_stream_bit_rotate_right_64bit( hash_values[ hash_value_index4 ], 14 ) \
	   ^ byte_stream_bit_rotate_right_64bit( hash_values[ hash_value_index4 ], 18 ) \
	   ^ byte_stream_bit_rotate_right_64bit( hash_values[ hash_value_index4 ], 41 ); \
\
	t1  = hash_values[ hash_value_index7 ]; \
	t1 += s1; \
	t1 += ( hash_values[ hash_value_index4 ] & hash_values[ hash_value_index5 ] ) \
	    ^ ( ~( hash_values[ hash_value_index4 ] ) & hash_values[ hash_value_index6 ] ); \
	t1 += libhmac_sha512_context_prime_cube_roots[ value_64bit_index ]; \
	t1 += values_64bit[ value_64bit_index ]; \
	t2  = s0; \
	t2 += ( hash_values[ hash_value_index0 ] & hash_values[ hash_value_index1 ] ) \
	    ^ ( hash_values[ hash_value_index0 ] & hash_values[ hash_value_index2 ] ) \
	    ^ ( hash_values[ hash_value_index1 ] & hash_values[ hash_value_index2 ] ); \
\
	hash_values[ hash_value_index3 ] += t1; \
	hash_values[ hash_value_index7 ]  = t1 + t2;

#define libhmac_sha512_context_transform_unfolded_calculate_hash_values( values_64bit, hash_values, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 0, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 1, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 2, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 3, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 4, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 5, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 6, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 7, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 8, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 9, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 10, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 11, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 12, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 13, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 14, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 15, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 16, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 17, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 18, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 19, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 20, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 21, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 22, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 23, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 24, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 25, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 26, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 27, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 28, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 29, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 30, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 31, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 32, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 33, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 34, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 35, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 36, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 37, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 38, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 39, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 40, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 41, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 42, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 43, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 44, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 45, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 46, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 47, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 48, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 49, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 50, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 51, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 52, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 53, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 54, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 55, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 56, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 57, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 58, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 59, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 60, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 61, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 62, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 63, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 64, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 65, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 66, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 67, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 68, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 69, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 70, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 71, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 72, hash_values, 0, 1, 2, 3, 4, 5, 6, 7, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 73, hash_values, 7, 0, 1, 2, 3, 4, 5, 6, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 74, hash_values, 6, 7, 0, 1, 2, 3, 4, 5, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 75, hash_values, 5, 6, 7, 0, 1, 2, 3, 4, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 76, hash_values, 4, 5, 6, 7, 0, 1, 2, 3, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 77, hash_values, 3, 4, 5, 6, 7, 0, 1, 2, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 78, hash_values, 2, 3, 4, 5, 6, 7, 0, 1, s0, s1, t1, t2 ) \
	libhmac_sha512_context_transform_unfolded_calculate_hash_value( values_64bit, 79, hash_values, 1, 2, 3, 4, 5, 6, 7, 0, s0, s1, t1, t2 )

/* Calculates the SHA-512 of 128 byte sized blocks of data in a buffer
 * Returns the number of bytes used if successful or -1 on error
 */
ssize_t libhmac_sha512_context_transform(
         libhmac_internal_sha512_context_t *internal_context,
         const uint8_t *buffer,
         size_t size,
         libcerror_error_t **error )
{
	uint64_t hash_values[ 8 ];
	uint64_t values_64bit[ 80 ];

	static char *function     = "libhmac_sha512_context_transform";
	uint64_t s0               = 0;
	uint64_t s1               = 0;
	uint64_t t1               = 0;
	uint64_t t2               = 0;
	size_t buffer_offset      = 0;

#if !defined( LIBHMAC_UNFOLLED_LOOPS )
	uint8_t hash_values_index = 0;
	uint8_t value_64bit_index = 0;
#endif

	if( internal_context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid internal context.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	while( size >= LIBHMAC_SHA512_BLOCK_SIZE )
	{
		if( memory_copy(
		     hash_values,
		     internal_context->hash_values,
		     sizeof( uint64_t ) * 8 ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy hash values.",
			 function );

			goto on_error;
		}
#if defined( LIBHMAC_UNFOLLED_LOOPS )
		/* Break the block into 16 x 64-bit values
		 */
		libhmac_byte_stream_copy_to_16x_uint64_big_endian(
		 &( buffer[ buffer_offset ] ),
		 values_64bit );

		buffer_offset += LIBHMAC_SHA512_BLOCK_SIZE;

		/* Extend to 80 x 64-bit values
		 */
		libhmac_sha512_context_transform_unfolded_extend_64bit_values(
		 values_64bit,
		 s0,
		 s1 );

		/* Calculate the hash values for the 64-bit values
		 */
		libhmac_sha512_context_transform_unfolded_calculate_hash_values(
		 values_64bit,
		 hash_values,
		 s0,
		 s1,
		 t1,
		 t2 );

		/* Update the hash values in the context
		 */
		internal_context->hash_values[ 0 ] += hash_values[ 0 ];
		internal_context->hash_values[ 1 ] += hash_values[ 1 ];
		internal_context->hash_values[ 2 ] += hash_values[ 2 ];
		internal_context->hash_values[ 3 ] += hash_values[ 3 ];
		internal_context->hash_values[ 4 ] += hash_values[ 4 ];
		internal_context->hash_values[ 5 ] += hash_values[ 5 ];
		internal_context->hash_values[ 6 ] += hash_values[ 6 ];
		internal_context->hash_values[ 7 ] += hash_values[ 7 ];

#else
		/* Break the block into 16 x 64-bit values
		 */
		for( value_64bit_index = 0;
		     value_64bit_index < 16;
		     value_64bit_index++ )
		{
			byte_stream_copy_to_uint64_big_endian(
			 &( buffer[ buffer_offset ] ),
			 values_64bit[ value_64bit_index ] );

			buffer_offset += sizeof( uint64_t );
		}
		/* Extend to 80 x 64-bit values
		 */
		for( value_64bit_index = 16;
		     value_64bit_index < 80;
		     value_64bit_index++ )
		{
			libhmac_sha512_context_transform_extend_64bit_value(
			 values_64bit,
			 value_64bit_index,
			 s0,
			 s1 );
		}
		/* Calculate the hash values for the 64-bit values
		 */
		for( value_64bit_index = 0;
		     value_64bit_index < 80;
		     value_64bit_index++ )
		{
			s0 = byte_stream_bit_rotate_right_64bit( hash_values[ 0 ], 28 )
			   ^ byte_stream_bit_rotate_right_64bit( hash_values[ 0 ], 34 )
			   ^ byte_stream_bit_rotate_right_64bit( hash_values[ 0 ], 39 );
			s1 = byte_stream_bit_rotate_right_64bit( hash_values[ 4 ], 14 )
			   ^ byte_stream_bit_rotate_right_64bit( hash_values[ 4 ], 18 )
			   ^ byte_stream_bit_rotate_right_64bit( hash_values[ 4 ], 41 );

			t1  = hash_values[ 7 ];
			t1 += s1;
			t1 += ( hash_values[ 4 ] & hash_values[ 5 ] )
			    ^ ( ~( hash_values[ 4 ] ) & hash_values[ 6 ] );
			t1 += libhmac_sha512_context_prime_cube_roots[ value_64bit_index ];
			t1 += values_64bit[ value_64bit_index ];
			t2  = s0;
			t2 += ( hash_values[ 0 ] & hash_values[ 1 ] )
			    ^ ( hash_values[ 0 ] & hash_values[ 2 ] )
			    ^ ( hash_values[ 1 ] & hash_values[ 2 ] );

			hash_values[ 7 ] = hash_values[ 6 ];
			hash_values[ 6 ] = hash_values[ 5 ];
			hash_values[ 5 ] = hash_values[ 4 ];
			hash_values[ 4 ] = hash_values[ 3 ] + t1;
			hash_values[ 3 ] = hash_values[ 2 ];
			hash_values[ 2 ] = hash_values[ 1 ];
			hash_values[ 1 ] = hash_values[ 0 ];
			hash_values[ 0 ] = t1 + t2;
		}
		/* Update the hash values in the context
		 */
		for( hash_values_index = 0;
		     hash_values_index < 8;
		     hash_values_index++ )
		{
			internal_context->hash_values[ hash_values_index ] += hash_values[ hash_values_index ];
		}
#endif /* defined( LIBHMAC_UNFOLLED_LOOPS ) */

		size -= LIBHMAC_SHA512_BLOCK_SIZE;
	}
	/* Prevent sensitive data from leaking
	 */
	if( memory_set(
	     hash_values,
	     0,
	     sizeof( uint64_t ) * 8 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear hash values.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     values_64bit,
	     0,
	     sizeof( uint64_t ) * 80 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear 64-bit values.",
		 function );

		goto on_error;
	}
	return( (ssize_t) buffer_offset );

on_error:
	memory_set(
	 values_64bit,
	 0,
	 sizeof( uint64_t ) * 80 );

	memory_set(
	 hash_values,
	 0,
	 sizeof( uint64_t ) * 8 );

	return( -1 );
}

#endif /* !defined( LIBHMAC_HAVE_SHA512_SUPPORT ) */

/* Creates a SHA-512 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libhmac_sha512_context_initialize(
     libhmac_sha512_context_t **context,
     libcerror_error_t **error )
{
	libhmac_internal_sha512_context_t *internal_context = NULL;
	static char *function                               = "libhmac_sha512_context_initialize";

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA512 )
	const EVP_MD *evp_md_type                           = NULL;
#endif

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( *context != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid context value already set.",
		 function );

		return( -1 );
	}
	internal_context = memory_allocate_structure(
	                    libhmac_internal_sha512_context_t );

	if( internal_context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create context.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_context,
	     0,
	     sizeof( libhmac_internal_sha512_context_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear context.",
		 function );

		memory_free(
		 internal_context );

		return( -1 );
	}
#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA512_DIGEST_LENGTH )
	if( SHA512_Init(
	     &( internal_context->sha512_context ) ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize context.",
		 function );

		goto on_error;
	}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA512 )
#if defined( HAVE_EVP_MD_CTX_INIT )
	EVP_MD_CTX_init(
	 &( internal_context->internal_evp_md_context ) );

	internal_context->evp_md_context = &( internal_context->internal_evp_md_context );
#else
	internal_context->evp_md_context = EVP_MD_CTX_new();

	if( internal_context->evp_md_context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create EVP message digest context.",
		 function );

		goto on_error;
	}
#endif /* defined( HAVE_EVP_MD_CTX_INIT ) */

/* TODO use EVP_MD_fetch for EVP_DigestInit_ex2 */
	evp_md_type = EVP_sha512();

#if defined( HAVE_EVP_DIGESTINIT_EX2 )
	if( EVP_DigestInit_ex2(
	     internal_context->evp_md_context,
	     evp_md_type,
	     NULL ) != 1 )
#else
	if( EVP_DigestInit_ex(
	     internal_context->evp_md_context,
	     evp_md_type,
	     NULL ) != 1 )
#endif
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize context.",
		 function );

#if defined( HAVE_EVP_MD_CTX_CLEANUP )
		EVP_MD_CTX_cleanup(
		 &( internal_context->internal_evp_md_context ) );
		ERR_remove_thread_state(
		 NULL );
#else
		EVP_MD_CTX_free(
		 internal_context->evp_md_context );
#endif
		internal_context->evp_md_context = NULL;

		goto on_error;
	}
#else
	if( memory_copy(
	     internal_context->hash_values,
	     libhmac_sha512_context_prime_square_roots,
	     sizeof( uint64_t ) * 8 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy initial hash values.",
		 function );

		return( -1 );
	}
#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA512_DIGEST_LENGTH ) */

	*context = (libhmac_sha512_context_t *) internal_context;

	return( 1 );

on_error:
	if( internal_context != NULL )
	{
		memory_free(
		 internal_context );
	}
	return( -1 );
}

/* Frees a SHA-512 context
 * Returns 1 if successful or -1 on error
 */
int libhmac_sha512_context_free(
     libhmac_sha512_context_t **context,
     libcerror_error_t **error )
{
	libhmac_internal_sha512_context_t *internal_context = NULL;
	static char *function                               = "libhmac_sha512_context_free";

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( *context != NULL )
	{
		internal_context = (libhmac_internal_sha512_context_t *) *context;
		*context         = NULL;

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA512_DIGEST_LENGTH )
		/* No additional clean up necessary
		 */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA512 )
#if defined( HAVE_EVP_MD_CTX_CLEANUP )
		if( EVP_MD_CTX_cleanup(
		     &( internal_context->internal_evp_md_context ) ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to clean up EVP message digest context.",
			 function );
		}
		/* Make sure the error state is removed otherwise OpenSSL will leak memory
		 */
		ERR_remove_thread_state(
		 NULL );
#else
		EVP_MD_CTX_free(
		 internal_context->evp_md_context );

#endif /* defined( HAVE_EVP_MD_CTX_CLEANUP ) */

		internal_context->evp_md_context = NULL;
#else
		/* No additional clean up necessary
		 */
#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA512_DIGEST_LENGTH ) */

		memory_free(
		 internal_context );
	}
	return( 1 );
}

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA512_DIGEST_LENGTH )

/* Updates the SHA-512 context using OpenSSL
 * Returns 1 if successful or -1 on error
 */
int libhmac_sha512_context_update(
     libhmac_sha512_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libcerror_error_t **error )
{
	libhmac_internal_sha512_context_t *internal_context = NULL;
	static char *function                               = "libhmac_sha512_context_update";
	unsigned long safe_hash_size                        = 0;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libhmac_internal_sha512_context_t *) context;

	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
#if ( SIZEOF_LONG < SIZEOF_SIZE_T )
	if( size > (size_t) ULONG_MAX )
#else
	if( size > (size_t) SSIZE_MAX )
#endif
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( size == 0 )
	{
		return( 1 );
	}
	safe_hash_size = (unsigned long) size;

	if( SHA512_Update(
	     &( internal_context->sha512_context ),
	     (const void *) buffer,
	     size ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to update context.",
		 function );

		return( -1 );
	}
	return( 1 );
}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA512 )

/* Updates the SHA-512 context using OpenSSL EVP
 * Returns 1 if successful or -1 on error
 */
int libhmac_sha512_context_update(
     libhmac_sha512_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libcerror_error_t **error )
{
	libhmac_internal_sha512_context_t *internal_context = NULL;
	static char *function                               = "libhmac_sha512_context_update";

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libhmac_internal_sha512_context_t *) context;

	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( size == 0 )
	{
		return( 1 );
	}
	if( EVP_DigestUpdate(
	     internal_context->evp_md_context,
	     (const void *) buffer,
	     size ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to update context.",
		 function );

		return( -1 );
	}
	return( 1 );
}

#else

/* Updates the SHA-512 context using fallback implementation
 * Returns 1 if successful or -1 on error
 */
int libhmac_sha512_context_update(
     libhmac_sha512_context_t *context,
     const uint8_t *buffer,
     size_t size,
     libcerror_error_t **error )
{
	libhmac_internal_sha512_context_t *internal_context = NULL;
	static char *function                               = "libhmac_sha512_context_update";
	size_t buffer_offset                                = 0;
	size_t remaining_block_size                         = 0;
	ssize_t process_count                               = 0;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libhmac_internal_sha512_context_t *) context;

	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( size == 0 )
	{
		return( 1 );
	}
	if( internal_context->block_offset > 0 )
	{
		if( internal_context->block_offset >= LIBHMAC_SHA512_BLOCK_SIZE )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid context - block offset value out of bounds.",
			 function );

			return( -1 );
		}
		remaining_block_size = LIBHMAC_SHA512_BLOCK_SIZE - internal_context->block_offset;

		if( remaining_block_size > size )
		{
			remaining_block_size = size;
		}
		if( memory_copy(
		     &( internal_context->block[ internal_context->block_offset ] ),
		     buffer,
		     remaining_block_size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy data to context block.",
			 function );

			return( -1 );
		}
		internal_context->block_offset += remaining_block_size;

		if( internal_context->block_offset < LIBHMAC_SHA512_BLOCK_SIZE )
		{
			return( 1 );
		}
		buffer_offset += remaining_block_size;
		size          -= remaining_block_size;

		process_count = libhmac_sha512_context_transform(
		                 internal_context,
		                 internal_context->block,
		                 LIBHMAC_SHA512_BLOCK_SIZE,
		                 error );

		if( process_count == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to transform context block.",
			 function );

			return( -1 );
		}
		internal_context->hash_count  += process_count;
		internal_context->block_offset = 0;
	}
	if( size > 0 )
	{
		process_count = libhmac_sha512_context_transform(
		                 internal_context,
		                 &( buffer[ buffer_offset ] ),
		                 size,
		                 error );

		if( process_count == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to transform buffer.",
			 function );

			return( -1 );
		}
		internal_context->hash_count += process_count;

		buffer_offset += process_count;
		size          -= process_count;
	}
	if( size > 0 )
	{
		if( size >= LIBHMAC_SHA512_BLOCK_SIZE )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid size value out of bounds.",
			 function );

			return( -1 );
		}
		if( memory_copy(
		     internal_context->block,
		     &( buffer[ buffer_offset ] ),
		     size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy remaining data to context block.",
			 function );

			return( -1 );
		}
		internal_context->block_offset = size;
	}
	return( 1 );
}

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA512_DIGEST_LENGTH ) */

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA512_DIGEST_LENGTH )

/* Finalizes the SHA-512 context using OpenSSL
 * Returns 1 if successful or -1 on error
 */
int libhmac_sha512_context_finalize(
     libhmac_sha512_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libcerror_error_t **error )
{
	libhmac_internal_sha512_context_t *internal_context = NULL;
	static char *function                               = "libhmac_sha512_context_finalize";

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libhmac_internal_sha512_context_t *) context;

	if( hash == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid hash.",
		 function );

		return( -1 );
	}
	if( hash_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid hash size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( hash_size < (size_t) LIBHMAC_SHA512_HASH_SIZE )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid hash size value too small.",
		 function );

		return( -1 );
	}
	if( SHA512_Final(
	     hash,
	     &( internal_context->sha512_context ) ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to finalize context.",
		 function );

		return( -1 );
	}
	return( 1 );
}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_SHA512 )

/* Finalizes the SHA-512 context using OpenSSL EVP
 * Returns 1 if successful or -1 on error
 */
int libhmac_sha512_context_finalize(
     libhmac_sha512_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libcerror_error_t **error )
{
	libhmac_internal_sha512_context_t *internal_context = NULL;
	static char *function                               = "libhmac_sha512_context_finalize";
	unsigned int safe_hash_size                         = 0;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libhmac_internal_sha512_context_t *) context;

	if( hash == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid hash.",
		 function );

		return( -1 );
	}
	if( ( hash_size < (size_t) LIBHMAC_SHA512_HASH_SIZE )
	 || ( hash_size > (size_t) UINT_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid hash size value out of bounds.",
		 function );

		return( -1 );
	}
	safe_hash_size = (unsigned int) hash_size;

	if( EVP_DigestFinal_ex(
	     internal_context->evp_md_context,
	     (unsigned char *) hash,
	     &safe_hash_size ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to finalize context.",
		 function );

		return( -1 );
	}
	return( 1 );
}

#else

/* Finalizes the SHA-512 context using fallback implementation
 * Returns 1 if successful or -1 on error
 */
int libhmac_sha512_context_finalize(
     libhmac_sha512_context_t *context,
     uint8_t *hash,
     size_t hash_size,
     libcerror_error_t **error )
{
	libhmac_internal_sha512_context_t *internal_context = NULL;
	static char *function                               = "libhmac_sha512_context_finalize";
	size_t block_size                                   = 0;
	size_t number_of_blocks                             = 0;
	ssize_t process_count                               = 0;
	uint64_t bit_size                                   = 0;

#if !defined( LIBHMAC_UNFOLLED_LOOPS )
	size_t hash_index                                   = 0;
	int hash_values_index                               = 0;
#endif

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libhmac_internal_sha512_context_t *) context;

	if( hash == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid hash.",
		 function );

		return( -1 );
	}
	if( hash_size < (size_t) LIBHMAC_SHA512_HASH_SIZE )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid hash value too small.",
		 function );

		return( -1 );
	}
	if( hash_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid hash size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( hash_size < (size_t) LIBHMAC_SHA512_HASH_SIZE )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid hash size value too small.",
		 function );

		return( -1 );
	}
	/* Add padding with a size of 112 mod 128
	 */
	number_of_blocks = 1;

	if( internal_context->block_offset > 111 )
	{
		number_of_blocks += 1;
	}
	block_size = number_of_blocks * LIBHMAC_SHA512_BLOCK_SIZE;

	if( memory_set(
	     &( internal_context->block[ internal_context->block_offset ] ),
	     0,
	     block_size - internal_context->block_offset ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear context block.",
		 function );

		return( -1 );
	}
	/* The first byte of the padding contains 0x80
	 */
	internal_context->block[ internal_context->block_offset ] = 0x80;

	bit_size = ( internal_context->hash_count + internal_context->block_offset ) * 8;

	byte_stream_copy_from_uint64_big_endian(
	 &( internal_context->block[ block_size - 8 ] ),
	 bit_size );

	process_count = libhmac_sha512_context_transform(
	                 internal_context,
	                 internal_context->block,
	                 block_size,
	                 error );

	if( process_count == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to transform context block.",
		 function );

		return( -1 );
	}
#if !defined( LIBHMAC_UNFOLLED_LOOPS )
	for( hash_values_index = 0;
	     hash_values_index < 8;
	     hash_values_index++ )
	{
		byte_stream_copy_from_uint64_big_endian(
		 &( hash[ hash_index ] ),
		 internal_context->hash_values[ hash_values_index ] );

		hash_index += sizeof( uint64_t );
	}
#else
	byte_stream_copy_from_uint64_big_endian(
	 &( hash[ 0 ] ),
	 internal_context->hash_values[ 0 ] );

	byte_stream_copy_from_uint64_big_endian(
	 &( hash[ 8 ] ),
	 internal_context->hash_values[ 1 ] );

	byte_stream_copy_from_uint64_big_endian(
	 &( hash[ 16 ] ),
	 internal_context->hash_values[ 2 ] );

	byte_stream_copy_from_uint64_big_endian(
	 &( hash[ 24 ] ),
	 internal_context->hash_values[ 3 ] );

	byte_stream_copy_from_uint64_big_endian(
	 &( hash[ 32 ] ),
	 internal_context->hash_values[ 4 ] );

	byte_stream_copy_from_uint64_big_endian(
	 &( hash[ 40 ] ),
	 internal_context->hash_values[ 5 ] );

	byte_stream_copy_from_uint64_big_endian(
	 &( hash[ 48 ] ),
	 internal_context->hash_values[ 6 ] );

	byte_stream_copy_from_uint64_big_endian(
	 &( hash[ 56 ] ),
	 internal_context->hash_values[ 7 ] );

#endif /* !defined( LIBHMAC_UNFOLLED_LOOPS ) */

	/* Prevent sensitive data from leaking
	 */
	if( memory_set(
	     internal_context,
	     0,
	     sizeof( libhmac_internal_sha512_context_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear context.",
		 function );

		return( -1 );
	}
	return( 1 );
}

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_SHA_H ) && defined( SHA512_DIGEST_LENGTH ) */

