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

#define inline _inline
#define RESTRICT __restrict

#include <malloc.h>

#else /** Not MSC **/

#include <stdint.h>

#if __STDC_VERSION__ >= 199901L
#define RESTRICT restrict
#else
#define RESTRICT __restrict
#endif

#endif

#include <stdlib.h>
#include <string.h>

/** Force checking of assertions **/
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>


#include "errors.h"

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

#endif
