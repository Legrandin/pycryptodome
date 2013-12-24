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

/** Type for tables containing the expanded hash key **/
typedef uint64_t t_key_tables[16][256][2];

typedef uint64_t t_v_tables[128][2];

/**
 * Big Endian to word conversions
 */
static uint64_t be_to_word(const uint8_t fb[8])
{
    uint64_t tmp;
    int i;
    tmp = 0;
    for (i=0; i<8; i++)
        tmp = tmp<<8 ^ *fb++;
    return tmp;
}

/**
 *  Word to Big Endian conversions
 */
static void word_to_be(uint8_t fb[8], uint64_t w)
{
    int i;
    for (i=0; i<8; i++) {
        fb[7-i] = (uint8_t) w;
        w >>= 8;
    }
}

/**
 * Compute H*x^i for i=0..127. Store the results in a new
 * vector indexed by i.
 */
static const t_v_tables* make_v_tables(const uint8_t y[16])
{
    t_v_tables *tables;
    uint64_t *cur;
    int i;

    tables = (t_v_tables*) calloc(128*2, sizeof(uint64_t));
    if (!tables) {
        return NULL;
    }

    cur = &((*tables)[0][0]);

    cur[0] = be_to_word(&y[0]);
    cur[1] = be_to_word(&y[8]);

    for (i=1; i<128; i++) {
        uint64_t c;
        uint64_t *next;

        next = &((*tables)[i][0]);

        /** v = (v&1)*0xE1000000000000000000000000000000L ^ (v>>1) **/
        c = cur[1]&1 ? 0xE100000000000000 : 0;
        next[1] = cur[1]>>1 | cur[0]<<63;
        next[0] = cur[0]>>1 ^ c;

        cur = next;
    }

    return (const t_v_tables*)tables;
}

/**
 * Multiply to elements of GF(2**128) using the reducing polynomial
 * (x^128 + x^7 + x^2 + x + 1).
 */
static void gcm_mult(uint8_t out[16], const uint8_t x[16], const uint8_t y[16])
{
    uint64_t z[2], v[2];
    int i;

    /** z, v = 0, y **/
    z[0] = z[1] = 0;
    v[0] = be_to_word(&y[0]);
    v[1] = be_to_word(&y[8]);

    for (i=0; i<16; i++) {
        uint8_t j;

        for (j=0x80; j>0; j>>=1) {
            uint64_t c;

            /** z ^= (x>>i&1)*v **/
            if (x[i] & j) {

                z[0] ^= v[0];
                z[1] ^= v[1];
            }
            /** v = (v&1)*0xE1000000000000000000000000000000L ^ (v>>1) **/
            c = v[1]&1 ? 0xE100000000000000 : 0;
            v[1] = v[1]>>1 | (v[0] << 63);
            v[0] = v[0]>>1 ^ c;
        }
    }
    word_to_be(out, z[0]);
    word_to_be(out+8, z[1]);
}

/**
 * Multiply two elements of GF(2**128) using the reducing polynomial
 * (x^128 + x^7 + x^2 + x + 1).
 *
 * The first element has been expanded into H tables.
 */
static void gcm_mult2(uint8_t out[16], const t_key_tables *key_tables, const uint8_t x[16])
{
    int i;
    uint64_t z[2];

    z[0] = z[1] = 0;
    for (i=0; i<16; i++) {
        z[0] ^= (*key_tables)[i][x[i]][0];
        z[1] ^= (*key_tables)[i][x[i]][1];
    }
    word_to_be(out,   z[0]);
    word_to_be(out+8, z[1]);
}

/**
 * Multiply two elements of GF(2**128) using the reducing polynomial
 * (x^128 + x^7 + x^2 + x + 1).
 *
 * In first element, only the byte at position 'pos' is non-zero at has
 * value 'x'.
 *
 * The second element, is expanded in V tables (128 elements, one per
 * each bit position).
 */
static void gcm_mult3(uint64_t out[2], uint8_t x, uint8_t pos, const t_v_tables *v_tables)
{
    uint64_t z[2];
    int j;
    const uint64_t (*v)[2];

    /** z, v = 0, y **/
    z[0] = z[1] = 0;

    v = &((*v_tables)[pos*8]);
    for (j=0x80; j!=0; j>>=1, v++) {
        if (x & j) {
            z[0] ^= (*v)[0];
            z[1] ^= (*v)[1];
        }
    }
    out[0] = z[0];
    out[1] = z[1];
}

/**
 * Expand a hash key into a set of tables that will speed
 * up GHASH.
 *
 * \param tables    Pointer to allocated memory that will hold
 *                  the tables.
 * \param h         The hash key.
 */
static int ghash_expand(t_key_tables *key_tables, const uint8_t h[16])
{
    int i;
    const t_v_tables *v_tables;

    v_tables = make_v_tables(h);
    if (v_tables==NULL) {
        return -1;
    }

    for (i=0; i<16; i++) {
        int j;

        for (j=0; j<256; j++) {
            /** Z = H*j*P^{8i} **/
            gcm_mult3(&((*key_tables)[i][j][0]), j, i, v_tables);
        }
    }

    free(v_tables);
    return 0;
}

/**
 * Compute the GHASH of a piece of an arbitrary data given an
 * arbitrary Y_0, as specified in NIST SP 800 38D.
 *
 * \param y_out             The resulting GHASH (16 bytes).
 * \param block_data        Pointer to the data to hash.
 * \param len               Length of the data to hash (multiple of 16).
 * \param y_in              The initial Y (Y_0, 16 bytes).
 * \param key_tables        The hash key, possibly expanded to 16*256*16 bytes.
 * \param key_tables_len    The length of the data pointed by key_table.
 */
static void ghash(
        uint8_t y_out[16],
        const uint8_t block_data[],
        int len,
        const uint8_t y_in[16],
        const void *key_tables,
        int key_tables_len
        )
{
    int i, j;
    uint8_t x[16];
    const t_key_tables *key_tables_64 = NULL;
    const uint8_t (*key)[16] = NULL;

    switch (key_tables_len) {
        case sizeof(t_key_tables):
            {
                key_tables_64 = (const t_key_tables*) key_tables;
                break;
            }
        case 16:
            {
                key = (const uint8_t (*)[16]) key_tables;
                break;
            }
        default:
            return;
    }

    memcpy(y_out, y_in, 16);

    if (key_tables_64) {
        for (i=0; i<len; i+=16) {
            for (j=0; j<16; j++) {
                x[j] = y_out[j] ^ block_data[i+j];
            }
            gcm_mult2(y_out, key_tables_64, x);
        }
    } else {
        for (i=0; i<len; i+=16) {
            for (j=0; j<16; j++) {
                x[j] = y_out[j] ^ block_data[i+j];
            }
            gcm_mult(y_out, *key, x);
        }
    }
}

static char ghash_expand__doc__[] =
"_ghash_expand(h:str) -> str\n"
"\n"
"Return an expanded hash key for GHASH.\n";

static PyObject *
ghash_expand_function(PyObject *self, PyObject *args)
{
    PyObject *h;
    PyObject *retval = NULL;
    Py_ssize_t len_h;
    int err;

    if (!PyArg_ParseTuple(args, "S", &h)) {
        goto out;
    }

    len_h = PyBytes_GET_SIZE(h);

    if (len_h!=16) {
        PyErr_SetString(PyExc_ValueError, "Length of h must be 16 bytes.");
        goto out;
    }

    /* Create return string */
    retval = PyBytes_FromStringAndSize(NULL, sizeof(t_key_tables));
    if (!retval) {
        goto out;
    }

    Py_BEGIN_ALLOW_THREADS;

    err = ghash_expand(
            (t_key_tables*)PyBytes_AS_STRING(retval),
            (uint8_t*)PyBytes_AS_STRING(h)
            );

    Py_END_ALLOW_THREADS;

    if (err!=0) {
        Py_DECREF(retval);
        retval = NULL;
    }

out:
    return retval;
}


static char ghash__doc__[] =
"_ghash(data:str, y:str, exp_h:str) -> str\n"
"\n"
"Return a GHASH.\n";

static PyObject *
ghash_function(PyObject *self, PyObject *args)
{
    PyObject *data, *y, *exp_h;
    PyObject *retval = NULL;
    Py_ssize_t len_data, len_y, len_exp_h;

    if (!PyArg_ParseTuple(args, "SSS", &data, &y, &exp_h)) {
        goto out;
    }

    len_data = PyBytes_GET_SIZE(data);
    len_y = PyBytes_GET_SIZE(y);
    len_exp_h = PyBytes_GET_SIZE(exp_h);

    if (len_data%16!=0) {
        PyErr_SetString(PyExc_ValueError, "Length of data must be a multiple of 16 bytes.");
        goto out;
    }

    if (len_y!=16) {
        PyErr_SetString(PyExc_ValueError, "Length of y must be 16 bytes.");
        goto out;
    }

    if (len_exp_h!=sizeof(t_key_tables) && len_exp_h!=16) {
        PyErr_SetString(PyExc_ValueError, "Length of expanded key is incorrect.");
        goto out;
    }

    /* Create return string */
    retval = PyBytes_FromStringAndSize(NULL, 16);
    if (!retval) {
        goto out;
    }

    Py_BEGIN_ALLOW_THREADS;

#define PyBytes_Buffer(a)   (uint8_t*)PyBytes_AS_STRING(a)

    ghash(  PyBytes_Buffer(retval), PyBytes_Buffer(data), len_data,
            PyBytes_Buffer(y),
            PyBytes_Buffer(exp_h), len_exp_h );

#undef PyBytes_Buffer

     Py_END_ALLOW_THREADS;

out:
    return retval;
}

/*
 * Module-level method table and module initialization function
 */

static PyMethodDef galois_methods[] = {
    {"_ghash_expand", ghash_expand_function, METH_VARARGS, ghash_expand__doc__},
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
