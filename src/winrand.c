/* -*- C -*- */
/*
 * Uses Windows CryptoAPI CryptGenRandom to get random bytes.
 * The "new" method returns an object, whose "get_bytes" method
 * can be called repeatedly to get random bytes, seeded by the
 * OS.  See the description in the comment at the end.
 * 
 * If you have the Intel Security Driver header files (icsp4ms.h)
 * for their hardware random number generator in the 810 and 820 chipsets,
 * then define HAVE_INTEL_RNG.
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

#ifdef HAVE_INTEL_RNG
# include "icsp4ms.h"
#else
# define PROV_INTEL_SEC 22
# define INTEL_DEF_PROV "Intel Hardware Cryptographic Service Provider"
#endif

/* To-Do: store provider name and type for print/repr? */
typedef struct
{
    PyObject_HEAD
    HCRYPTPROV hcp;
} WRobject;

staticforward PyTypeObject WRtype;

#define is_WRobject(v) ((v)->ob_type == &WRtype)

static void
WRdealloc(PyObject *ptr)
{		
	WRobject *o = (WRobject *)ptr;

	if (! is_WRobject(ptr)) {
		PyErr_Format(PyExc_TypeError,
		    "WinRandom trying to dealloc non-WinRandom object");
		return;
	}
	if (! CryptReleaseContext(o->hcp, 0)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptReleaseContext failed, error 0x%x",
			     GetLastError());
		return;
	}
	/* Overwrite the contents of the object */
	o->hcp = 0;
	PyObject_Del(ptr);
}

static char winrandom__doc__[] =
"new([provider], [provtype]): Returns an object handle to Windows\n\
CryptoAPI that can be used to access a cryptographically strong\n\
pseudo-random generator that uses OS-gathered entropy.\n\
Provider is a string that specifies the Cryptographic Service Provider\n\
to use, default is the default OS CSP.\n\
provtype is an integer specifying the provider type to use, default\n\
is 1 (PROV_RSA_FULL)";

static char WR_get_bytes__doc__[] =
"get_bytes(nbytes, [userdata]]): Returns nbytes of random data\n\
from Windows CryptGenRandom.\n\
userdata is a string with any additional entropic data that the\n\
user wishes to provide.";

static WRobject *
winrandom_new(PyObject *self, PyObject *args, PyObject *kwdict)
{
	HCRYPTPROV hcp = 0;
	WRobject *res;
	char *provname = NULL;
	int provtype = PROV_RSA_FULL;
	static char *kwlist[] = { "provider", "provtype", NULL};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "|si", kwlist,
					 &provname, &provtype)) {
		return NULL;
	}
	if (! CryptAcquireContext(&hcp, NULL, (LPCTSTR) provname,
				  (DWORD) provtype, 0)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptAcquireContext for provider \"%s\" type %i failed, error 0x%x",
			     provname? provname : "(null)", provtype,
			     GetLastError());
		return NULL;
	}
	res = PyObject_New(WRobject, &WRtype);
	res->hcp = hcp;
	return res;
}

static PyObject *
WR_get_bytes(WRobject *self, PyObject *args)
{
	HCRYPTPROV hcp = 0;
	int n, nbytes, len = 0;
	PyObject *res;
	char *buf, *str = NULL;
	
	if (! is_WRobject(self)) {
		PyErr_Format(PyExc_TypeError,
		    "WinRandom trying to get_bytes with non-WinRandom object");
		return NULL;
	}
	if (!PyArg_ParseTuple(args, "i|s#", &n, &str, &len)) {
		return NULL;
	}
	if (n <= 0) {
		PyErr_SetString(PyExc_ValueError, "nbytes must be positive number");
		return NULL;
	}
	/* Just in case char != BYTE, or userdata > desired result */
	nbytes = (((n > len) ? n : len) * sizeof(char)) / sizeof(BYTE) + 1;
	if ((buf = (char *) PyMem_Malloc(nbytes)) == NULL)
	    return PyErr_NoMemory();
	if (len > 0)
		memcpy(buf, str, len);
	/*
	 * if userdata > desired result, we end up getting
	 * more bytes than we really needed to return.  No
	 * easy way to avoid that: we prefer that
	 * CryptGenRandom does the distillation of userdata
	 * down to entropy, rather than trying to do it
	 * ourselves.  Since the extra bytes presumably come
	 * from an RC4 stream, they should be relatively
	 * cheap.
	 */
	if (! CryptGenRandom(self->hcp, (DWORD) nbytes, (BYTE *) buf)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptGenRandom failed, error 0x%x",
			     GetLastError());
		PyMem_Free(buf);
		return NULL;
	}
	res = PyString_FromStringAndSize(buf, n);
	PyMem_Free(buf);
	return res;
}

/* WinRandom object methods */

static PyMethodDef WRmethods[] =
{
	{"get_bytes", (PyCFunction) WR_get_bytes, METH_VARARGS,
		WR_get_bytes__doc__},
	{NULL, NULL}			/* sentinel */
};

/* winrandom module methods */

static PyMethodDef WR_mod_methods[] = {
        {"new", (PyCFunction) winrandom_new, METH_VARARGS|METH_KEYWORDS,
		winrandom__doc__},
	{NULL,      NULL}        /* Sentinel */
};


static PyObject *
WRgetattr(PyObject *s, char *name)
{
	WRobject *self = (WRobject*)s;
	if (! is_WRobject(self)) {
		PyErr_Format(PyExc_TypeError,
		    "WinRandom trying to getattr with non-WinRandom object");
		return NULL;
	}
	if (strcmp(name, "hcp") == 0)
		return PyInt_FromLong((long) self->hcp);
	return Py_FindMethod(WRmethods, (PyObject *) self, name);
}

static PyTypeObject WRtype =
{
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"winrandom.WinRandom",	/*tp_name*/
	sizeof(WRobject),	/*tp_size*/
	0,			/*tp_itemsize*/
	/* methods */
	WRdealloc,		/*tp_dealloc*/
	0,			/*tp_print*/
	WRgetattr,		/*tp_getattr*/
};

void
initwinrandom()
{
	PyObject *m;
	WRtype.ob_type = &PyType_Type;
	m = Py_InitModule("winrandom", WR_mod_methods);

	/* define Windows CSP Provider Types */
#ifdef PROV_RSA_FULL
	PyModule_AddIntConstant(m, "PROV_RSA_FULL", PROV_RSA_FULL);
#endif
#ifdef PROV_RSA_SIG
	PyModule_AddIntConstant(m, "PROV_RSA_SIG", PROV_RSA_SIG);
#endif
#ifdef PROV_DSS
	PyModule_AddIntConstant(m, "PROV_DSS", PROV_DSS);
#endif
#ifdef PROV_FORTEZZA
	PyModule_AddIntConstant(m, "PROV_FORTEZZA", PROV_FORTEZZA);
#endif
#ifdef PROV_MS_EXCHANGE
	PyModule_AddIntConstant(m, "PROV_MS_EXCHANGE", PROV_MS_EXCHANGE);
#endif
#ifdef PROV_SSL
	PyModule_AddIntConstant(m, "PROV_SSL", PROV_SSL);
#endif
#ifdef PROV_RSA_SCHANNEL
	PyModule_AddIntConstant(m, "PROV_RSA_SCHANNEL", PROV_RSA_SCHANNEL);
#endif
#ifdef PROV_DSS_DH
	PyModule_AddIntConstant(m, "PROV_DSS_DH", PROV_DSS_DH);
#endif
#ifdef PROV_EC_ECDSA_SIG
	PyModule_AddIntConstant(m, "PROV_EC_ECDSA_SIG", PROV_EC_ECDSA_SIG);
#endif
#ifdef PROV_EC_ECNRA_SIG
	PyModule_AddIntConstant(m, "PROV_EC_ECNRA_SIG", PROV_EC_ECNRA_SIG);
#endif
#ifdef PROV_EC_ECDSA_FULL
	PyModule_AddIntConstant(m, "PROV_EC_ECDSA_FULL", PROV_EC_ECDSA_FULL);
#endif
#ifdef PROV_EC_ECNRA_FULL
	PyModule_AddIntConstant(m, "PROV_EC_ECNRA_FULL", PROV_EC_ECNRA_FULL);
#endif
#ifdef PROV_SPYRUS_LYNKS
	PyModule_AddIntConstant(m, "PROV_SPYRUS_LYNKS", PROV_SPYRUS_LYNKS);
#endif
#ifdef PROV_INTEL_SEC
	PyModule_AddIntConstant(m, "PROV_INTEL_SEC", PROV_INTEL_SEC);
#endif

	/* Define Windows CSP Provider Names */
#ifdef MS_DEF_PROV
	PyModule_AddStringConstant(m, "MS_DEF_PROV", MS_DEF_PROV);
#endif
#ifdef MS_ENHANCED_PROV
	PyModule_AddStringConstant(m, "MS_ENHANCED_PROV", MS_ENHANCED_PROV);
#endif
#ifdef MS_DEF_RSA_SIG_PROV
	PyModule_AddStringConstant(m, "MS_DEF_RSA_SIG_PROV",
				   MS_DEF_RSA_SIG_PROV);
#endif
#ifdef MS_DEF_RSA_SCHANNEL_PROV
	PyModule_AddStringConstant(m, "MS_DEF_RSA_SCHANNEL_PROV",
				   MS_DEF_RSA_SCHANNEL_PROV);
#endif
#ifdef MS_ENHANCED_RSA_SCHANNEL_PROV
	PyModule_AddStringConstant(m, "MS_ENHANCED_RSA_SCHANNEL_PROV",
				   MS_ENHANCED_RSA_SCHANNEL_PROV);
#endif
#ifdef MS_DEF_DSS_PROV
	PyModule_AddStringConstant(m, "MS_DEF_DSS_PROV", MS_DEF_DSS_PROV);
#endif
#ifdef MS_DEF_DSS_DH_PROV
	PyModule_AddStringConstant(m, "MS_DEF_DSS_DH_PROV",
				   MS_DEF_DSS_DH_PROV);
#endif
#ifdef INTEL_DEF_PROV
	PyModule_AddStringConstant(m, "INTEL_DEF_PROV", INTEL_DEF_PROV);
#endif

	if (PyErr_Occurred())
		Py_FatalError("can't initialize module winrandom");
}

/*

CryptGenRandom usage is described in
http://msdn.microsoft.com/library/en-us/security/security/cryptgenrandom.asp
and many associated pages on Windows Cryptographic Service
Providers, which say:

	With Microsoft CSPs, CryptGenRandom uses the same
	random number generator used by other security
	components. This allows numerous processes to
	contribute to a system-wide seed. CryptoAPI stores
	an intermediate random seed with every user. To form
	the seed for the random number generator, a calling
	application supplies bits it might havefor instance,
	mouse or keyboard timing inputthat are then added to
	both the stored seed and various system data and
	user data such as the process ID and thread ID, the
	system clock, the system time, the system counter,
	memory status, free disk clusters, the hashed user
	environment block. This result is SHA-1 hashed, and
	the output is used to seed an RC4 stream, which is
	then used as the random stream and used to update
	the stored seed.

The only other detailed description I've found of the
sources of randomness for CryptGenRandom is this excerpt
from a posting
http://www.der-keiler.de/Newsgroups/comp.security.ssh/2002-06/0169.html

From: Jon McClelland (dowot69@hotmail.com) 
Date: 06/12/02 
... 
 
Windows, call a function such as CryptGenRandom, which has two of 
the properties of a good random number generator, unpredictability and 
even value distribution. This function, declared in Wincrypt.h, is 
available on just about every Windows platform, including Windows 95 
with Internet Explorer 3.02 or later, Windows 98, Windows Me, Windows 
CE v3, Windows NT 4, Windows 2000, and Windows XP. 
 
CryptGenRandom gets its randomness, also known as entropy, from many 
sources in Windows 2000, including the following: 
The current process ID (GetCurrentProcessID). 
The current thread ID (GetCurrentThreadID). 
The ticks since boot (GetTickCount). 
The current time (GetLocalTime). 
Various high-precision performance counters (QueryPerformanceCounter). 
A Message Digest 4 (MD4) hash of the user's environment block, which 
includes username, computer name, and search path. 
 
High-precision internal CPU counters, such as RDTSC, RDMSR, RDPMC (x86 
only-more information about these counters is at 
developer.intel.com/software/idap/resources/technical_collateral/pentiumii/RDTSCPM1.HTM 
<http://developer.intel.com>). 
 
Low-level system information, such as idle time, kernel time, 
interrupt times, commit limit, page read count, cache read count, 
nonpaged pool allocations, alignment fixup count, operating system 
lookaside information. 
 
Such information is added to a buffer, which is hashed using MD4 and 
used as the key to modify a buffer, using RC4, provided by the user. 
(Refer to the CryptGenRandom documentation in the Platform SDK for 
more information about the user-provided buffer.) Hence, if the user 
provides additional data in the buffer, this is used as an element in 
the witches brew to generate the random data. The result is a 
cryptographically random number generator. 
Also, note that if you plan to sell your software to the United States 
federal government, you'll need to use FIPS 140-1-approved algorithms. 
The default versions of CryptGenRandom in Microsoft Windows CE v3, 
Windows 95, Windows 98, Windows Me, Windows 2000, and Windows XP are 
FIPS-approved. Obviously FIPS-140 compliance is necessary but not 
sufficient to provide a properly secure source of random data. 
 
*/

#endif /* MS_WIN32 */
