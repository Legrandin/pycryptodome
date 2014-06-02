/*
 *  cpuid.c: check CPU capabilities
 *
 * Written in 2013 by Sebastian Ramacher <sebastian@ramacher.at>
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
#include "pycrypto_compat.h"

#if defined HAVE_CPUID_H
#include <cpuid.h>
#elif defined HAVE_INTRIN_H
#include <intrin.h>
#endif

/*
 * The have_aes_ni Python function
 */

static char have_aes_ni__doc__[] =
"have_aes_ni() -> bool\n"
"\n"
"Return whether AES-NI instructions are available.\n";

static PyObject *
have_aes_ni(PyObject *self, PyObject *args)
{
    uint32_t info[4];

    memset(info, 0, sizeof info);
    
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    /* Call cpuid to retrieve x86 Processor Info and Feature bits.
     * info[2] is ecx. If bit 25 is set, the CPU supports the
     * AES-NI extension. */
#if defined HAVE_CPUID_H
    __get_cpuid(1, info, info+1, info+2, info+3);
#elif defined HAVE_INTRIN_H
    __cpuidex(info, 1, 0);
#endif

    if (info[2] & ((int)1<<25)) {
        Py_INCREF(Py_True);
        return Py_True;
    }
    
    Py_INCREF(Py_False);
    return Py_False;
}

/*
 * Module-level method table and module initialization function
 */

static PyMethodDef cpuid_methods[] = {
    {"have_aes_ni", have_aes_ni, METH_VARARGS, have_aes_ni__doc__},
    {NULL, NULL, 0, NULL}   /* end-of-list sentinel value */
};

#ifdef IS_PY3K
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"cpuid",
	NULL,
	-1,
	cpuid_methods,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

PyMODINIT_FUNC
#ifdef IS_PY3K
PyInit_cpuid(void)
#else
initcpuid(void)
#endif
{
    /* Initialize the module */
#ifdef IS_PY3K
    return PyModule_Create(&moduledef);
#else
    Py_InitModule("cpuid", cpuid_methods);
#endif
}

/* vim:set ts=4 sw=4 sts=4 expandtab: */
