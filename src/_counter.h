/*
 *  _counter.h: Fast counter for use with CTR-mode ciphers
 *
 * =======================================================================
 * Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * =======================================================================
 */
#ifndef PCT__COUNTER_H
#define PCT__COUNTER_H

#include <stdint.h>
#include "Python.h"

typedef struct {
    PyObject_HEAD;
    PyStringObject *prefix;     /* Prefix (useful for a nonce) */
    PyStringObject *suffix;     /* Suffix (useful for a nonce) */
    uint8_t *val;       /* Buffer for our output string */
    uint32_t buf_size;  /* Size of the buffer */
    uint8_t *p;         /* Pointer to the part of the buffer that we're allowed to update */
    uint16_t nbytes;    /* The number of bytes that from .p that are part of the counter */
    void (*inc_func)(void *);   /* Pointer to the counter increment function */
} PCT_CounterObject;

#endif /* PCT__COUNTER_H */
