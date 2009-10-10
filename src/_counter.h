/*
 *  _counter.h: Fast counter for use with CTR-mode ciphers
 *
 * Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 */
#ifndef PCT__COUNTER_H
#define PCT__COUNTER_H

#include <stdint.h>
#include "Python.h"

typedef struct {
    PyObject_HEAD
    PyStringObject *prefix;     /* Prefix (useful for a nonce) */
    PyStringObject *suffix;     /* Suffix (useful for a nonce) */
    uint8_t *val;       /* Buffer for our output string */
    uint32_t buf_size;  /* Size of the buffer */
    uint8_t *p;         /* Pointer to the part of the buffer that we're allowed to update */
    uint16_t nbytes;    /* The number of bytes that from .p that are part of the counter */
    void (*inc_func)(void *);   /* Pointer to the counter increment function */
    int shortcut_disabled;  /* This gets set to a non-zero value when the shortcut mechanism is disabled */
} PCT_CounterObject;

#endif /* PCT__COUNTER_H */
