
/*
 *  _dsa.c: C implementation of the DSA algorithm.
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

PyObject *_dsa_module;
PyObject *_dsa_dict;

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
		{
			return NULL;
		}
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

PyObject *dsaKey_new (PyObject *, PyObject *);

static PyMethodDef _dsa__methods__[] = {
	{"construct", dsaKey_new, METH_VARARGS},
	{NULL, NULL}
};

typedef struct
{
	PyObject_HEAD mpz_t y;
	mpz_t g;
	mpz_t p;
	mpz_t q;
	mpz_t x;
}
dsaKey;

static int
dsaSign (dsaKey * key, mpz_t m, mpz_t k, mpz_t r, mpz_t s)
{
	mpz_t temp;
	if (mpz_cmp_ui (k, 2) < 0 || mpz_cmp (k, key->q) >= 0)
		{
			return 1;
		}
	mpz_init (temp);
	mpz_powm (r, key->g, k, key->p);
	mpz_mod (r, r, key->q);
	mpz_invert (s, k, key->q);
	mpz_mul (temp, key->x, r);
	mpz_add (temp, m, temp);
	mpz_mul (s, s, temp);
	mpz_mod (s, s, key->q);
	mpz_clear (temp);
	return 0;
}

static int
dsaVerify (dsaKey * key, mpz_t m, mpz_t r, mpz_t s)
{
	int result;
	mpz_t u1, u2, v1, v2, w;
	if (mpz_cmp_ui (r, 0) <= 0 || mpz_cmp (r, key->q) >= 0 ||
			mpz_cmp_ui (s, 0) <= 0 || mpz_cmp (s, key->q) >= 0)
		return 0;
	mpz_init (u1);
	mpz_init (u2);
	mpz_init (v1);
	mpz_init (v2);
	mpz_init (w);
	mpz_invert (w, s, key->q);
	mpz_mul (u1, m, w);
	mpz_mod (u1, u1, key->q);
	mpz_mul (u2, r, w);
	mpz_mod (u2, u2, key->q);
	mpz_powm (v1, key->g, u1, key->p);
	mpz_powm (v2, key->y, u2, key->p);
	mpz_mul (w, v1, v2);
	mpz_mod (w, w, key->p);
	mpz_mod (w, w, key->q);
	if (mpz_cmp (r, w) == 0)
		result = 1;
	else
		result = 0;
	mpz_clear (u1);
	mpz_clear (u2);
	mpz_clear (v1);
	mpz_clear (v2);
	mpz_clear (w);
	return result;
}

static void dsaKey_dealloc (dsaKey *);
static PyObject *dsaKey_getattr (dsaKey *, char *);
static PyObject *dsaKey__sign (dsaKey *, PyObject *);
static PyObject *dsaKey__verify (dsaKey *, PyObject *);
static PyObject *dsaKey_size (dsaKey *, PyObject *);
static PyObject *dsaKey_hasprivate (dsaKey *, PyObject *);

PyObject *dsaError;							/* raised on errors */

static PyTypeObject dsaKeyType = {
	PyObject_HEAD_INIT (NULL) 0,
	"dsaKey",
	sizeof (dsaKey),
	0,
	(destructor) dsaKey_dealloc,	/* dealloc */
	0,														/* print */
	(getattrfunc) dsaKey_getattr,	/* getattr */
	0,														/* setattr */
	0,														/* compare */
	0,														/* repr */
	0,														/* as_number */
	0,														/* as_sequence */
	0,														/* as_mapping */
	0,														/* hash */
	0,														/* call */
};

static PyMethodDef dsaKey__methods__[] = {
	{"_sign", (PyCFunction) dsaKey__sign, METH_VARARGS, "Sign the given long."},
	{"_verify", (PyCFunction) dsaKey__verify, METH_VARARGS,
	 "Verify that the signature is valid."},
	{"size", (PyCFunction) dsaKey_size, METH_VARARGS,
	 "Return the number of bits that this key can handle."},
	{"hasprivate", (PyCFunction) dsaKey_hasprivate, METH_VARARGS,
	 "Return 1 or 0 if this key does/doesn't have a private key."},
	{NULL, NULL, 0, NULL}
};

PyObject *
dsaKey_new (PyObject * self, PyObject * args)
{
	PyLongObject *y = NULL, *g = NULL, *p = NULL, *q = NULL, *x = NULL;
	dsaKey *key;
	key = PyObject_New (dsaKey, &dsaKeyType);
	mpz_init (key->y);
	mpz_init (key->g);
	mpz_init (key->p);
	mpz_init (key->q);
	mpz_init (key->x);
	PyArg_ParseTuple (args, "O!O!O!O!|O!", &PyLong_Type, &y,
										&PyLong_Type, &g,
										&PyLong_Type, &p, &PyLong_Type, &q, &PyLong_Type, &x);
	longObjToMPZ (key->y, y);
	longObjToMPZ (key->g, g);
	longObjToMPZ (key->p, p);
	longObjToMPZ (key->q, q);
	if (x)
		{
			longObjToMPZ (key->x, x);
		}
	/*Py_XDECREF(n);
	   Py_XDECREF(e);
	   Py_XDECREF(d);
	   Py_XDECREF(p);
	   Py_XDECREF(q); */
	return (PyObject *) key;
}

static void
dsaKey_dealloc (dsaKey * key)
{
	mpz_clear (key->y);
	mpz_clear (key->g);
	mpz_clear (key->p);
	mpz_clear (key->q);
	mpz_clear (key->x);
	PyObject_Del (key);
}

static PyObject *
dsaKey_getattr (dsaKey * key, char *attr)
{
	if (strcmp (attr, "y") == 0)
		return mpzToLongObj (key->y);
	else if (strcmp (attr, "g") == 0)
		return mpzToLongObj (key->g);
	else if (strcmp (attr, "p") == 0)
		return mpzToLongObj (key->p);
	else if (strcmp (attr, "q") == 0)
		return mpzToLongObj (key->q);
	else if (strcmp (attr, "x") == 0)
		{
			if (mpz_size (key->x) == 0)
				{
					PyErr_SetString (PyExc_AttributeError,
													 "rsaKey instance has no attribute 'x'");
					return NULL;
				}
			return mpzToLongObj (key->x);
		}
	else
		{
			return Py_FindMethod (dsaKey__methods__, (PyObject *) key, attr);
		}
}

PyObject *
dsaKey__sign (dsaKey * key, PyObject * args)
{
	PyObject *lm, *lk, *lr, *ls;
	mpz_t m, k, r, s;
	int result;
	if (!(PyArg_ParseTuple (args, "O!O!", &PyLong_Type, &lm,
													&PyLong_Type, &lk)))
		{
			return NULL;
		}
	mpz_init (m);
	mpz_init (k);
	mpz_init (r);
	mpz_init (s);
	longObjToMPZ (m, (PyLongObject *) lm);
	longObjToMPZ (k, (PyLongObject *) lk);
	result = dsaSign (key, m, k, r, s);
	if (result == 1)
		{
			PyErr_SetString (dsaError, "K not between 2 and q");
			return NULL;
		}
	lr = mpzToLongObj (r);
	ls = mpzToLongObj (s);
	mpz_clear (m);
	mpz_clear (k);
	mpz_clear (r);
	mpz_clear (s);
	return Py_BuildValue ("(NN)", lr, ls);
}

PyObject *
dsaKey__verify (dsaKey * key, PyObject * args)
{
	PyObject *lm, *lr, *ls;
	mpz_t m, r, s;
	int result;
	if (!(PyArg_ParseTuple (args, "O!O!O!", &PyLong_Type, &lm,
													&PyLong_Type, &lr, &PyLong_Type, &ls)))
		{
			return NULL;
		}
	mpz_init (m);
	mpz_init (r);
	mpz_init (s);
	longObjToMPZ (m, (PyLongObject *) lm);
	longObjToMPZ (r, (PyLongObject *) lr);
	longObjToMPZ (s, (PyLongObject *) ls);
	result = dsaVerify (key, m, r, s);
	mpz_clear (m);
	mpz_clear (r);
	mpz_clear (s);
	return Py_BuildValue ("i", result);
}

PyObject *
dsaKey_size (dsaKey * key, PyObject * args)
{
	if (!PyArg_ParseTuple (args, ""))
		return NULL;
	return Py_BuildValue ("i", mpz_sizeinbase (key->p, 2) - 1);
}

PyObject *
dsaKey_hasprivate (dsaKey * key, PyObject * args)
{
	if (!PyArg_ParseTuple (args, ""))
		return NULL;
	if (mpz_size (key->x) == 0)
		return Py_BuildValue ("i", 0);
	else
		return Py_BuildValue ("i", 1);
}


void
init_dsa (void)
{
	dsaKeyType.ob_type = &PyType_Type;
	_dsa_module = Py_InitModule ("_dsa", _dsa__methods__);
	_dsa_dict = PyModule_GetDict (_dsa_module);
	dsaError = PyErr_NewException ("_dsa.error", NULL, NULL);
	PyDict_SetItemString (_dsa_dict, "error", dsaError);
}
