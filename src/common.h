/* ===================================================================
 *
 * Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "errors.h"

/*
 * Define STATIC as an empty string to turn certain static functions public
 */
#ifndef STATIC
#define STATIC static inline
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define _PASTE(x,y) x##y
#define _PASTE2(x,y) _PASTE(x,y)

#ifdef _MSC_VER

typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#ifndef UINT32_MAX
#define UINT32_MAX 0xFFFFFFFFUL
#endif

#define inline _inline
#define RESTRICT __restrict

#include <malloc.h>

#else /** Not MSC **/

#include <stdint.h>

#if __STDC_VERSION__ >= 199901L
#define RESTRICT restrict
#else
#ifdef __GNUC__
#define RESTRICT __restrict
#define inline __inline
#else
#define RESTRICT
#define inline
#endif
#endif

#endif

/** Force checking of assertions **/
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

/*
 * On Windows, distutils expects that a CPython module always exports the symbol init${MODNAME}
 */
#if defined(_MSC_VER) || defined(__MINGW32__)
#include <Python.h>
#if PY_MAJOR_VERSION >= 3
#define FAKE_INIT(x) PyMODINIT_FUNC _PASTE2(PyInit__,x) (void) { return NULL; }
#else
#define FAKE_INIT(x) PyMODINIT_FUNC _PASTE2(init_,x) (void) { return; }
#endif
#else
#define FAKE_INIT(x)
#endif

/*
 * On Windows, functions must be explicitly marked for export.
 */
#if defined(_MSC_VER) || defined(__MINGW32__)
#define EXPORT_SYM __declspec(dllexport)
#else
#define EXPORT_SYM
#endif

/*
 * Platform specific routine for aligned allocation
 */
#if defined(_MSC_VER) || defined(__MINGW32__)

static inline void* align_alloc(size_t size, unsigned boundary)
{
    return _aligned_malloc(size, boundary);
}

static inline void align_free(void *mem)
{
    if (mem) {
        _aligned_free(mem);
    }
}

#elif defined(HAVE_POSIX_MEMALIGN)

static inline void* align_alloc(size_t size, unsigned boundary)
{
    int result;
    void *new_mem;
    result = posix_memalign((void**)&new_mem, boundary, size);
    return result ? NULL : new_mem;
}

static inline void align_free(void *mem)
{
    free(mem);
}

#elif defined(HAVE_MEMALIGN)

#include <malloc.h>

static inline void* align_alloc(size_t size, unsigned boundary)
{
    return memalign(boundary, size);
}

static inline void align_free(void *mem)
{
    free(mem);
}

#else
#error No routines for aligned memory
#endif

/*
 * Endianness convesion
 */

static inline void u32to8_little(uint8_t *p, const uint32_t *w)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(p, w, 4);
#else
    p[0] = (uint8_t)*w;
    p[1] = (uint8_t)(*w >> 8);
    p[2] = (uint8_t)(*w >> 16);
    p[3] = (uint8_t)(*w >> 24);
#endif
}

static inline void u8to32_little(uint32_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(w, p, 4);
#else
    *w = (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
#endif
}

static inline void u32to8_big(uint8_t *p, const uint32_t *w)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(p, w, 4);
#else
    p[0] = (uint8_t)(*w >> 24);
    p[1] = (uint8_t)(*w >> 16);
    p[2] = (uint8_t)(*w >> 8);
    p[3] = (uint8_t)*w;
#endif
}

static inline void u8to32_big(uint32_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(w, p, 4);
#else
    *w = (uint32_t)p[3] | (uint32_t)p[2]<<8 | (uint32_t)p[1]<<16 | (uint32_t)p[0]<<24;
#endif
}

static inline uint32_t load_u8to32_little(const uint8_t *p)
{
    uint32_t w;

    u8to32_little(&w, p);
    return w;
}

static inline uint32_t load_u8to32_big(const uint8_t *p)
{
    uint32_t w;

    u8to32_big(&w, p);
    return w;
}

#define LOAD_U32_LITTLE(p) load_u8to32_little(p)
#define LOAD_U32_BIG(p) load_u8to32_big(p)

#define STORE_U32_LITTLE(p, w) u32to8_little((p), &(w))
#define STORE_U32_BIG(p, w) u32to8_big((p), &(w))

static inline void u64to8_little(uint8_t *p, const uint64_t *w)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(p, w, 8);
#else
    p[0] = (uint8_t)*w;
    p[1] = (uint8_t)(*w >> 8);
    p[2] = (uint8_t)(*w >> 16);
    p[3] = (uint8_t)(*w >> 24);
    p[4] = (uint8_t)(*w >> 32);
    p[5] = (uint8_t)(*w >> 40);
    p[6] = (uint8_t)(*w >> 48);
    p[7] = (uint8_t)(*w >> 56);
#endif
}

static inline void u8to64_little(uint64_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(w, p, 8);
#else
    *w = (uint64_t)p[0]       |
         (uint64_t)p[1] << 8  |
         (uint64_t)p[2] << 16 |
         (uint64_t)p[3] << 24 |
         (uint64_t)p[4] << 32 |
         (uint64_t)p[5] << 40 |
         (uint64_t)p[6] << 48 |
         (uint64_t)p[7] << 56;
#endif
}

static inline void u64to8_big(uint8_t *p, const uint64_t *w)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(p, w, 8);
#else
    p[0] = (uint8_t)(*w >> 56);
    p[1] = (uint8_t)(*w >> 48);
    p[2] = (uint8_t)(*w >> 40);
    p[3] = (uint8_t)(*w >> 32);
    p[4] = (uint8_t)(*w >> 24);
    p[5] = (uint8_t)(*w >> 16);
    p[6] = (uint8_t)(*w >> 8);
    p[7] = (uint8_t)*w;
#endif
}

static inline void u8to64_big(uint64_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(w, p, 8);
#else
    *w = (uint64_t)p[0] << 56 |
         (uint64_t)p[1] << 48 |
         (uint64_t)p[2] << 40 |
         (uint64_t)p[3] << 32 |
         (uint64_t)p[4] << 24 |
         (uint64_t)p[5] << 16 |
         (uint64_t)p[6] << 8  |
         (uint64_t)p[7];
#endif
}

static inline uint64_t load_u8to64_little(const uint8_t *p)
{
    uint64_t w;

    u8to64_little(&w, p);
    return w;
}

static inline uint64_t load_u8to64_big(const uint8_t *p)
{
    uint64_t w;

    u8to64_big(&w, p);
    return w;
}

#define LOAD_U64_LITTLE(p) load_u8to64_little(p)
#define LOAD_U64_BIG(p) load_u8to64_big(p)

#define STORE_U64_LITTLE(p, w) u64to8_little((p), &(w))
#define STORE_U64_BIG(p, w) u64to8_big((p), &(w))

#endif
