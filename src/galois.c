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

#define ALIGNMENT 32

/**
 * A V table is a 4096 bytes table that will contain the expanded
 * GHASH key (H). It is used to speed up the GF(128) multiplication Z = X*H.
 *
 * The table contains 128 entries, one for each bit of X.
 * Each entry takes 32 bytes and can fit into the cache line of a modern
 * processor. If we assume that access to memory mapped to the same
 * cache line is somewhat constant, we can make GHASH robust again
 * cache timing attacks.
 */
typedef uint64_t t_v_tables[128][2][2];

/**
 * To ensure that the V table is aligned to a 32-byte memory boundary,
 * we allocate a larger piece of memory and carve the V table from there.
 */
typedef struct {
    uint8_t buffer[sizeof(t_v_tables)+ALIGNMENT];
    int offset;
} t_exp_key;

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
 * Create a V table. V[i] is the value H*x^i (i=0..127).
 * \param h         The 16 byte GHASH key
 * \param tables    A pointer to an allocated V table
 */
static void make_v_tables(const uint8_t h[16], t_v_tables *tables)
{
    uint64_t (*cur)[2];
    int i;

    memset(tables, 0, sizeof(t_v_tables));

    cur = &((*tables)[0][1]);

    (*cur)[0] = be_to_word(&h[0]);
    (*cur)[1] = be_to_word(&h[8]);

    for (i=1; i<128; i++) {
        uint64_t c;
        uint64_t (*next)[2];

        next = &((*tables)[i][1]);

        /** v = (v&1)*0xE1000000000000000000000000000000L ^ (v>>1) **/
        c = (*cur)[1]&1 ? 0xE100000000000000 : 0;
        (*next)[1] = (*cur)[1]>>1 | (*cur)[0]<<63;
        (*next)[0] = (*cur)[0]>>1 ^ c;

        cur = next;
    }
}

/**
 * Multiply two elements of GF(2**128) using the reducing polynomial
 * (x^128 + x^7 + x^2 + x + 1).
 *
 * \param   out         The 16 byte buffer that will receive the result
 * \param   key_tables  One factor, expanded into a V table
 * \param   x           The other factor (16 bytes)
 */
static void gcm_mult2(uint8_t out[16], const t_v_tables *key_tables, const uint8_t x[16])
{
    int i, bit_scan_128;
    uint64_t z[2];

    z[0] = z[1] = 0;
    bit_scan_128 = 0;
    for (i=0; i<16; i++) {
        uint8_t xi;
        int j;

        xi = x[i];
        for (j=0; j<8; j++) {
            int bit;

            bit = xi>>7 & 1; /** Constant time */
            z[0] ^= (*key_tables)[bit_scan_128][bit][0];
            z[1] ^= (*key_tables)[bit_scan_128][bit][1];

            xi <<= 1;
            bit_scan_128++;
        }
    }
    
    word_to_be(out,   z[0]);
    word_to_be(out+8, z[1]);
}


/**
 * Compute the GHASH of a piece of data given an arbitrary Y_0,
 * as specified in NIST SP 800 38D.
 *
 * \param y_out      The resulting GHASH (16 bytes).
 * \param block_data Pointer to the data to hash.
 * \param len        Length of the data to hash (multiple of 16).
 * \param y_in       The initial Y (Y_0, 16 bytes).
 * \param key_tables The expanded hash key (16*256*16 bytes).
 */
static void ghash(
        uint8_t y_out[16],
        const uint8_t block_data[],
        int len,
        const uint8_t y_in[16],
        const t_v_tables *key_tables
        )
{
    int i;

    memcpy(y_out, y_in, 16);
    for (i=0; i<len; i+=16) {
        int j;
        uint8_t x[16];

        for (j=0; j<16; j++) {
            x[j] = y_out[j] ^ block_data[i+j];
        }
        gcm_mult2(y_out, key_tables, x);
    }
}

static void realign_v_tables(t_exp_key *exp_key)
{
    int new_offset;
    
    new_offset = ALIGNMENT - ((uintptr_t)exp_key->buffer & (ALIGNMENT-1));
    if (new_offset != exp_key->offset) {
        memmove(exp_key->buffer+new_offset,
                exp_key->buffer+exp_key->offset,
                sizeof(t_v_tables));
        exp_key->offset = new_offset;
    }
}

static char ghash_expand__doc__[] =
"ghash_expand(h:str) -> str\n"
"\n"
"Return an expanded GHASH key.\n";

/**
 * Expand the AES key into a Python (byte) string object.
 */ 
static PyObject *
ghash_expand_function(PyObject *self, PyObject *args)
{
    PyObject *h;
    PyObject *retval = NULL;
    Py_ssize_t len_h;
    t_exp_key *exp_key;

    if (!PyArg_ParseTuple(args, "S", &h)) {
        goto out;
    }

    len_h = PyBytes_GET_SIZE(h);

    if (len_h!=16) {
        PyErr_SetString(PyExc_ValueError, "Length of h must be 16 bytes.");
        goto out;
    }

    exp_key = calloc(1, sizeof(t_exp_key));
    if (!exp_key) {
        goto out;
    }

    Py_BEGIN_ALLOW_THREADS;
    
    exp_key->offset = ALIGNMENT - ((uintptr_t)exp_key->buffer & (ALIGNMENT-1));
    make_v_tables((uint8_t*)PyBytes_AS_STRING(h),
            (t_v_tables*)(exp_key->buffer + exp_key->offset));
    
    Py_END_ALLOW_THREADS;

    retval = PyBytes_FromStringAndSize((const char*)exp_key, sizeof *exp_key);
    free(exp_key);

out:
    return retval;
}


static char ghash__doc__[] =
"ghash(data:str, y:str, exp_key:str) -> str\n"
"\n"
"Return a GHASH.\n";

static PyObject *
ghash_function(PyObject *self, PyObject *args)
{
    PyObject *data, *y, *exp_key_serial;
    PyObject *retval = NULL;
    Py_ssize_t len_data, len_y, len_exp_key_serial;
    const t_v_tables *v_tables;
    t_exp_key *exp_key;

    if (!PyArg_ParseTuple(args, "SSS", &data, &y, &exp_key_serial)) {
        goto out;
    }

    len_data = PyBytes_GET_SIZE(data);
    len_y = PyBytes_GET_SIZE(y);
    len_exp_key_serial = PyBytes_GET_SIZE(exp_key_serial);

    if (len_data%16!=0) {
        PyErr_SetString(PyExc_ValueError, "Length of data must be a multiple of 16 bytes.");
        goto out;
    }

    if (len_y!=16) {
        PyErr_SetString(PyExc_ValueError, "Length of y must be 16 bytes.");
        goto out;
    }

    if (len_exp_key_serial!=sizeof(t_exp_key)) {
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

    exp_key = (t_exp_key *)PyBytes_AS_STRING(exp_key_serial);
    realign_v_tables(exp_key);
    v_tables = (const t_v_tables*)(exp_key->buffer + exp_key->offset);
    ghash(  PyBytes_Buffer(retval), PyBytes_Buffer(data), len_data,
            PyBytes_Buffer(y), v_tables);

#undef PyBytes_Buffer

     Py_END_ALLOW_THREADS;

out:
    return retval;
}

/*
 * Module-level method table and module initialization function
 */

static PyMethodDef galois_methods[] = {
    {"ghash_expand", ghash_expand_function, METH_VARARGS, ghash_expand__doc__},
    {"ghash", ghash_function, METH_VARARGS, ghash__doc__},
    {NULL, NULL, 0, NULL}   /* end-of-list sentinel value */
};

#ifdef IS_PY3K

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"_galois",
	"Arithmetic in Galois Fields",
	-1,
	galois_methods,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC
PyInit__galois(void)
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
init_galois(void)
{
    PyObject *m;

    /* Initialize the module */
    m = Py_InitModule("_galois", galois_methods);
    if (m == NULL)
        return;
}

#endif
