
/*
 *  _rsa.c: C implementation of the RSA algorithm.
 *
 * Part of the Python Cryptography Toolkit
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */

#include <stdio.h>
#include <string.h>
#include <Python.h>
#include <longintrepr.h>				/* for conversions */
#include <gmp.h>

PyObject *_rsa_module;
PyObject *_rsa_dict;

void
longObjToMPZ (mpz_t m, PyLongObject * p)
{
	int size, i;
	mpz_t temp, temp2;
	mpz_init (temp);
	mpz_init (temp2);
	if (p->ob_size > 0)
		size = p->ob_size;
	else
		size = -p->ob_size;
	for (i = 0; i < size; i++)
		{
			mpz_set_ui (temp, p->ob_digit[i]);
			mpz_mul_2exp (temp2, temp, SHIFT * i);
			mpz_add (m, m, temp2);
		}
	mpz_clear (temp);
	mpz_clear (temp2);
}

PyObject *
mpzToLongObj (mpz_t m)
{
	/* borrowed from gmpy */
	int size = (mpz_sizeinbase (m, 2) + SHIFT - 1) / SHIFT;
	int i;
	mpz_t temp;
	PyLongObject *l = _PyLong_New (size);
	if (!l)
		return NULL;
	mpz_init_set (temp, m);
	for (i = 0; i < size; i++)
		{
			l->ob_digit[i] = (digit) (mpz_get_ui (temp) & MASK);
			mpz_fdiv_q_2exp (temp, temp, SHIFT);
		}
	i = size;
	while ((i > 0) && (l->ob_digit[i - 1] == 0))
		i--;
	l->ob_size = i;
	mpz_clear (temp);
	return (PyObject *) l;
}

PyObject *rsaKey_new (PyObject *, PyObject *);

static PyMethodDef _rsa__methods__[] = {
	{"construct", rsaKey_new, METH_VARARGS},
	{NULL, NULL}
};

typedef struct
{
	PyObject_HEAD mpz_t n;
	mpz_t e;
	mpz_t d;
	mpz_t p;
	mpz_t q;
}
rsaKey;

static int
rsaEncrypt (rsaKey * key, mpz_t v)
{
	if (mpz_cmp (v, key->n) >= 0)
		{
			return 1;
		}
	mpz_powm (v, v, key->e, key->n);
	return 0;
}

static int
rsaDecrypt (rsaKey * key, mpz_t v)
{
	if (mpz_cmp (v, key->n) >= 0)
		{
			return 1;
		}
	if (mpz_size (key->d) == 0)
		{
			return 2;
		}
	mpz_powm (v, v, key->d, key->n);
	return 0;
}

static void rsaKey_dealloc (rsaKey *);
static PyObject *rsaKey_getattr (rsaKey *, char *);
static PyObject *rsaKey__encrypt (rsaKey *, PyObject *);
static PyObject *rsaKey__decrypt (rsaKey *, PyObject *);
static PyObject *rsaKey__verify (rsaKey *, PyObject *);
static PyObject *rsaKey_size (rsaKey *, PyObject *);
static PyObject *rsaKey_hasprivate (rsaKey *, PyObject *);

PyObject *rsaError;							/* raised on errors */

static PyTypeObject rsaKeyType = {
	PyObject_HEAD_INIT (NULL) 0,
	"rsaKey",
	sizeof (rsaKey),
	0,
	(destructor) rsaKey_dealloc,	/* dealloc */
	0,														/* print */
	(getattrfunc) rsaKey_getattr,	/* getattr */
	0,														/* setattr */
	0,														/* compare */
	0,														/* repr */
	0,														/* as_number */
	0,														/* as_sequence */
	0,														/* as_mapping */
	0,														/* hash */
	0,														/* call */
};

static PyMethodDef rsaKey__methods__[] = {
	{"_encrypt", (PyCFunction) rsaKey__encrypt, METH_VARARGS,
	 "Encrypt the given long."},
	{"_decrypt", (PyCFunction) rsaKey__decrypt, METH_VARARGS,
	 "Decrypt the given long."},
	{"_sign", (PyCFunction) rsaKey__decrypt, METH_VARARGS,
	 "Sign the given long."},
	{"_verify", (PyCFunction) rsaKey__verify, METH_VARARGS,
	 "Verify that the signature is valid."},
	{"size", (PyCFunction) rsaKey_size, METH_VARARGS,
	 "Return the number of bits that this key can handle."},
	{"hasprivate", (PyCFunction) rsaKey_hasprivate, METH_VARARGS,
	 "Return 1 or 0 if this key does/doesn't have a private key."},
	{NULL, NULL, 0, NULL}
};

PyObject *
rsaKey_new (PyObject * self, PyObject * args)
{
	PyLongObject *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
	rsaKey *key;
	key = PyObject_New (rsaKey, &rsaKeyType);
	mpz_init (key->n);
	mpz_init (key->e);
	mpz_init (key->d);
	mpz_init (key->p);
	mpz_init (key->q);
	PyArg_ParseTuple (args, "O!O!|O!O!O!", &PyLong_Type, &n,
										&PyLong_Type, &e,
										&PyLong_Type, &d, &PyLong_Type, &p, &PyLong_Type, &q);
	longObjToMPZ (key->n, n);
	longObjToMPZ (key->e, e);
	if (!d)
		{
			return (PyObject *) key;
		}
	longObjToMPZ (key->d, d);
	if (p)
		{
			if (q)
				{
					longObjToMPZ (key->p, p);
					longObjToMPZ (key->q, q);
				}
		}
	/*Py_XDECREF(n);
	   Py_XDECREF(e);
	   Py_XDECREF(d);
	   Py_XDECREF(p);
	   Py_XDECREF(q); */
	return (PyObject *) key;
}

static void
rsaKey_dealloc (rsaKey * key)
{
	mpz_clear (key->n);
	mpz_clear (key->e);
	mpz_clear (key->d);
	mpz_clear (key->p);
	mpz_clear (key->q);
	PyObject_Del (key);
}

static PyObject *
rsaKey_getattr (rsaKey * key, char *attr)
{
	if (strcmp (attr, "n") == 0)
		return mpzToLongObj (key->n);
	else if (strcmp (attr, "e") == 0)
		return mpzToLongObj (key->e);
	else if (strcmp (attr, "d") == 0)
		{
			if (mpz_size (key->d) == 0)
				{
					PyErr_SetString (PyExc_AttributeError,
													 "rsaKey instance has no attribute 'd'");
					return NULL;
				}
			return mpzToLongObj (key->d);
		}
	else if (strcmp (attr, "p") == 0)
		{
			if (mpz_size (key->p) == 0)
				{
					PyErr_SetString (PyExc_AttributeError,
													 "rsaKey instance has no attribute 'p'");
					return NULL;
				}
			return mpzToLongObj (key->p);
		}
	else if (strcmp (attr, "q") == 0)
		{
			if (mpz_size (key->q) == 0)
				{
					PyErr_SetString (PyExc_AttributeError,
													 "rsaKey instance has no attribute 'q'");
					return NULL;
				}
			return mpzToLongObj (key->q);
		}
	else
		{
			return Py_FindMethod (rsaKey__methods__, (PyObject *) key, attr);
		}
}

PyObject *
rsaKey__encrypt (rsaKey * key, PyObject * args)
{
	PyObject *l, *r;
	mpz_t v;
	int result;
	if (!(PyArg_ParseTuple (args, "O!", &PyLong_Type, &l)))
		{
			return NULL;
		}
	mpz_init (v);
	longObjToMPZ (v, (PyLongObject *) l);
	result = rsaEncrypt (key, v);
	if (result == 1)
		{
			PyErr_SetString (rsaError, "Plaintext too large");
			return NULL;
		}
	r = (PyObject *) mpzToLongObj (v);
	mpz_clear (v);
	return Py_BuildValue ("N", r);
}

PyObject *
rsaKey__decrypt (rsaKey * key, PyObject * args)
{
	PyObject *l, *r;
	mpz_t v;
	int result;
	if (!(PyArg_ParseTuple (args, "O!", &PyLong_Type, &l)))
		{
			return NULL;
		}
	mpz_init (v);
	longObjToMPZ (v, (PyLongObject *) l);
	result = rsaDecrypt (key, v);
	if (result == 1)
		{
			PyErr_SetString (rsaError, "Ciphertext too large");
			return NULL;
		}
	else if (result == 2)
		{
			PyErr_SetString (rsaError, "Private key not available in this object");
			return NULL;
		}
	r = mpzToLongObj (v);
	mpz_clear (v);
	return Py_BuildValue ("N", r);
}

PyObject *
rsaKey__verify (rsaKey * key, PyObject * args)
{
	PyObject *l, *lsig;
	mpz_t v, vsig;
	if (!
			(PyArg_ParseTuple
			 (args, "O!O!", &PyLong_Type, &l, &PyLong_Type, &lsig)))
		{
			return NULL;
		}
	mpz_init (v);
	mpz_init (vsig);
	longObjToMPZ (v, (PyLongObject *) l);
	longObjToMPZ (vsig, (PyLongObject *) lsig);
	rsaEncrypt (key, vsig);
	if (mpz_cmp (v, vsig) == 0)
		return Py_BuildValue ("i", 1);
	else
		return Py_BuildValue ("i", 0);
}

PyObject *
rsaKey_size (rsaKey * key, PyObject * args)
{
	if (!PyArg_ParseTuple (args, ""))
		return NULL;
	return Py_BuildValue ("i", mpz_sizeinbase (key->n, 2) - 1);
}

PyObject *
rsaKey_hasprivate (rsaKey * key, PyObject * args)
{
	if (!PyArg_ParseTuple (args, ""))
		return NULL;
	if (mpz_size (key->d) == 0)
		return Py_BuildValue ("i", 0);
	else
		return Py_BuildValue ("i", 1);
}


void
init_rsa (void)
{
	rsaKeyType.ob_type = &PyType_Type;
	_rsa_module = Py_InitModule ("_rsa", _rsa__methods__);
	_rsa_dict = PyModule_GetDict (_rsa_module);
	rsaError = PyErr_NewException ("_rsa.error", NULL, NULL);
	PyDict_SetItemString (_rsa_dict, "error", rsaError);
}
