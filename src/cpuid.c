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
#include "Python.h"
#include <stdint.h>
#include "config.h"

#ifdef HAVE_CPUID_H
#include <cpuid.h>

/* it's bit_AES with gcc */
#ifndef bit_AES
/* but some versions of clang provide bit_AESNI instead */
#ifdef bit_AESNI
#define bit_AES bit_AESNI
/* and others do not provide any define at all */
#else
#define bit_AES 0x02000000
#endif
#endif

#endif

#include "pycrypto_compat.h"

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
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

#ifndef HAVE_CPUID_H
    Py_INCREF(Py_False);
    return Py_False;
#else
    uint32_t eax, ebx, ecx, edx;
    /* call cpuid to check if AES-NI instructions are available */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & bit_AES) {
            Py_INCREF(Py_True);
            return Py_True;
        }
    }
    Py_INCREF(Py_False);
    return Py_False;
#endif
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
