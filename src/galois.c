/*
 *  galois.c: arithmetic in Galois Fields
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

#include "pycrypto_common.h"
#include <stddef.h>
#include <assert.h>
#include <string.h>

/**
 * Big Endian to word conversions
 */
static uint32_t be_to_word(const uint8_t fb[4])
{
    uint32_t tmp;
    int i;
    tmp = 0;
    for (i=0; i<4; i++)
        tmp = tmp<<8 ^ *fb++;
    return tmp;
}

static void block_to_words(uint32_t w[4], const uint8_t block[16])
{
    int i;
    for (i=0; i<4; i++) {
        w[i] = be_to_word(&block[i*4]);
    }
}

/**
 *  Word to Big Endian conversions
 */
static void word_to_be(uint8_t fb[4], uint32_t w)
{
    int i;
    for (i=0; i<4; i++) {
        fb[3-i] = (uint8_t) w;
        w >>= 8;
    }
}

static void words_to_block(uint8_t block[16], const uint32_t w[4])
{
    int i;
    for (i=0; i<4; i++) {
        word_to_be(&block[i*4], w[i]);
    }
}

/**
 * Multiply to elements of GF(2**128) using the reducing polynomial
 * (x^128 + x^7 + x^2 + x + 1).
 */
static void gcm_mult(uint32_t z[4], const uint32_t x[4], const uint32_t y[4])
{
    uint32_t v[4];
    int i;

    /** z, v = 0, y **/
    for (i=0; i<4; i++) {
        z[i] = 0;
        v[i] = y[i];
    }
    for (i=0; i<128; i++) {
        uint32_t c;

        /** z ^= (x>>i&1)*v **/
        if ((x[i>>5] >> (~i&31)) & 1) {
            z[0] ^= v[0];
            z[1] ^= v[1];
            z[2] ^= v[2];
            z[3] ^= v[3];
        }
        /** v = (v&1)*0xE1000000000000000000000000000000L ^ (v>>1) **/
        c = v[3]&1 ? 0xE1000000 : 0;
        v[3] = v[3]>>1 | (v[2] << 31);
        v[2] = v[2]>>1 | (v[1] << 31);
        v[1] = v[1]>>1 | (v[0] << 31);
        v[0] = v[0]>>1 ^ c;
    }
}

/**
 * Compute the GHASH of a piece of an arbitrary data given an
 * arbitrary Y_0, as specified in NIST SP 800 38D.
 *
 * \param y_out      The resulting GHASH (16 bytes).
 * \param block_data Pointer to the data to hash.
 * \param len        Length of the data to hash (multiple of 16).
 * \param y_in       The initial Y (Y_0, 16 bytes).
 * \param h          The hash key (16 bytes).
 */
static void ghash(
        uint8_t y_out[16],
        const uint8_t block_data[],
        int len,
        const uint8_t y_in[16],
        const uint8_t h[16]
        )
{
    int i, j;
    uint32_t result[4], hw[4], x[4];

    block_to_words(result, y_in);
    block_to_words(hw, h);
    for (i=0; i<len; i+=16) {
        for (j=0; j<4; j++) {
            x[j] = result[j] ^ be_to_word(&block_data[i+j*4]);
        }
        gcm_mult(result, hw, x);
    }
    words_to_block(y_out, result);
}

static char ghash__doc__[] =
"_ghash(data:str, y:str, h:str) -> str\n"
"\n"
"Return a GHASH.\n";

static PyObject *
ghash_function(PyObject *self, PyObject *args)
{
    PyObject *data, *y, *h;
    PyObject *retval = NULL;
    Py_ssize_t len_data, len_y, len_h;

    if (!PyArg_ParseTuple(args, "SSS", &data, &y, &h)) {
        goto out;
    }

    len_data = PyBytes_GET_SIZE(data);
    len_y = PyBytes_GET_SIZE(y);
    len_h = PyBytes_GET_SIZE(h);

    if (len_data%16!=0) {
        PyErr_SetString(PyExc_ValueError, "Length of data must be a multiple of 16 bytes.");
        goto out;
    }

    if (len_y!=16) {
        PyErr_SetString(PyExc_ValueError, "Length of y must be 16 bytes.");
        goto out;
    }

    if (len_h!=16) {
        PyErr_SetString(PyExc_ValueError, "Length of h must be 16 bytes.");
        goto out;
    }

    /* Create return string */
    retval = PyBytes_FromStringAndSize(NULL, 16);
    if (!retval) {
        goto out;
    }

#define PyBytes_Buffer(a)   (uint8_t*)PyBytes_AS_STRING(a)

    ghash(  PyBytes_Buffer(retval), PyBytes_Buffer(data), len_data,
            PyBytes_Buffer(y), PyBytes_Buffer(h));

#undef PyBytes_Buffer

out:
    return retval;
}

/*
 * Module-level method table and module initialization function
 */

static PyMethodDef galois_methods[] = {
    {"_ghash", ghash_function, METH_VARARGS, ghash__doc__},
    {NULL, NULL, 0, NULL}   /* end-of-list sentinel value */
};

#ifdef IS_PY3K

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"galois",
	NULL,
	-1,
	galois_methods,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC
PyInit_galois(void)
{
    PyObject *m;

    /* Initialize the module */
    m = PyModule_Create(&moduledef);
    if (m == NULL)
       return NULL;
    return m;
}

#else

PyMODINIT_FUNC
initgalois(void)
{
    PyObject *m;

    /* Initialize the module */
    m = Py_InitModule("galois", galois_methods);
    if (m == NULL)
        return;
}

#endif
