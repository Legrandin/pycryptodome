/* -*- C -*- */
/*
 * Uses Windows CryptoAPI CryptGenRandom to get random bytes
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.  This software is provided "as is" without
 * warranty of fitness for use or suitability for any purpose, express
 * or implied. Use at your own risk or not at all. 
 *
 */

/* Author: Mark Moraes */

#include "Python.h"

#ifdef MS_WIN32

#define _WIN32_WINNT 0x400
#define WINSOCK

#include <windows.h>
#include <wincrypt.h>

static char winrandom__doc__[] =
"winrandom(nbytes, [provider], [provtype]): Returns nbytes of random data\n\
from Windows CryptGenRandom, a cryptographically strong pseudo-random\n\
generator using OS-gathered entropy.\n\
Provider is a string that specifies the Cryptographic Service Provider\n\
to use, default is the default OS CSP.\n\
provtype is an integer specifying the provider type to use, default\n\
is 1 (PROV_RSA_FULL)";

static PyObject *
winrandom(PyObject *self, PyObject *args, PyObject *kwdict)
{
	HCRYPTPROV hcp = 0;
	int n, nbytes;
	PyObject *res;
	char *buf;
	char *provname = NULL;
	int provtype = PROV_RSA_FULL;
	static char *kwlist[] = { "nbytes", "provider", "provtype", NULL};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "i|si", kwlist,
					 &n, &provname, &provtype)) {
		return NULL;
	}
	/* Just in case char != BYTE */
	nbytes = (n * sizeof(char)) / sizeof(BYTE);
	if (nbytes <= 0) {
		PyErr_SetString(PyExc_ValueError, "nbytes must be positive number");
		return NULL;
	}
	if ((buf = (char *) PyMem_Malloc(nbytes)) == NULL)
	    return PyErr_NoMemory();

	if (! CryptAcquireContext(&hcp, NULL, (LPCTSTR) provname,
				  (DWORD) provtype, 0)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptAcquireContext for provider \"%s\" type %i failed, error 0x%x",
			     provname? provname : "(null)", provtype,
			     GetLastError());
		PyMem_Free(buf);
		return NULL;
	} else if (! CryptGenRandom(hcp, (DWORD) nbytes, (BYTE *) buf)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptGenRandom failed, error %i",
			     GetLastError());
		PyMem_Free(buf);
		(void) CryptReleaseContext(hcp, 0);
		return NULL;
	}
	if (! CryptReleaseContext(hcp, 0)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptReleaseContext failed, error %i",
			     GetLastError());
		return NULL;
	}
	res = PyString_FromStringAndSize(buf, n);
	PyMem_Free(buf);
	return res;
}

static PyMethodDef WRMethods[] = {
        {"winrandom", (PyCFunction) winrandom, METH_VARARGS|METH_KEYWORDS,
	 winrandom__doc__},
	{NULL,      NULL}        /* Sentinel */
};


void
initwinrandom()
{
	(void) Py_InitModule("winrandom", WRMethods);
}

#endif /* MS_WIN32 */
