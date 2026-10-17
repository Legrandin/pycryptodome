/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef SSE2_UNALIGNED_H
#define SSE2_UNALIGNED_H

/*
 * Unaligned loads and stores of SSE2 registers, at any address p.
 * Include only in code compiled for SSE2 (or later, such as AVX2).
 *
 * The cast via void* avoids -Wcast-align: the intrinsics do not
 * require the alignment of __m128i.
 */

#include <emmintrin.h>

#define LOADU_128(p)        _mm_loadu_si128((const __m128i*)(const void*)(p))
#define STOREU_128(p, v)    _mm_storeu_si128((__m128i*)(void*)(p), (v))
#define LOADL_64(p)         _mm_loadl_epi64((const __m128i*)(const void*)(p))

#endif
