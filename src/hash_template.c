/*
 *  hash_template.c : Generic framework for hash function extension modules
 *
 * Written by Andrew Kuchling and others
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
  
/* Basic object type */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef _HAVE_STDC_HEADERS
#include <string.h>
#endif

#define _STR(x) #x
#define _XSTR(x) _STR(x)
#define _PASTE(x,y) x##y
#define _PASTE2(x,y) _PASTE(x,y)
#define _MODULE_NAME _PASTE2(init,MODULE_NAME)
#define _MODULE_STRING _XSTR(MODULE_NAME)

typedef struct {
	PyObject_HEAD
	hash_state st;
} ALGobject;

staticforward PyTypeObject ALGtype;

#define is_ALGobject(v) ((v)->ob_type == &ALGtype)

static ALGobject *
newALGobject(void)
{
	ALGobject *new;

	new = PyObject_New(ALGobject, &ALGtype);
	return new;
}

/* Internal methods for a hashing object */

static void
ALG_dealloc(PyObject *ptr)
{
	ALGobject *self = (ALGobject *)ptr;

	/* Overwrite the contents of the object */
	memset((char*)&(self->st), 0, sizeof(hash_state));
	PyObject_Del(ptr);
}


/* External methods for a hashing object */

static char ALG_copy__doc__[] = 
"copy(): Return a copy of the hashing object.";

static PyObject *
ALG_copy(ALGobject *self, PyObject *args)
{
	ALGobject *newobj;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}
	
	if ( (newobj = newALGobject())==NULL)
		return NULL;

	hash_copy(&(self->st), &(newobj->st));
	return((PyObject *)newobj); 
}

static char ALG_digest__doc__[] = 
"digest(): Return the digest value as a string of binary data.";

static PyObject *
ALG_digest(ALGobject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	return (PyObject *)hash_digest(&(self->st));
}

static char ALG_hexdigest__doc__[] = 
"hexdigest(): Return the digest value as a string of hexadecimal digits.";

static PyObject *
ALG_hexdigest(ALGobject *self, PyObject *args)
{
	PyObject *value, *retval;
	unsigned char *raw_digest, *hex_digest;
	int i, j, size;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	/* Get the raw (binary) digest value */
	value = (PyObject *)hash_digest(&(self->st));
	size = PyString_Size(value);
	raw_digest = (unsigned char *) PyString_AsString(value);

	/* Create a new string */
	retval = PyString_FromStringAndSize(NULL, size * 2 );
	hex_digest = (unsigned char *) PyString_AsString(retval);

	/* Make hex version of the digest */
	for(i=j=0; i<size; i++)	
	{
		char c;
		c = raw_digest[i] / 16; c = (c>9) ? c+'a'-10 : c + '0';
		hex_digest[j++] = c;
		c = raw_digest[i] % 16; c = (c>9) ? c+'a'-10 : c + '0';
		hex_digest[j++] = c;
	}	
	Py_DECREF(value);
	return retval;
}

static char ALG_update__doc__[] = 
"update(string): Update this hashing object's state with the provided string.";

static PyObject *
ALG_update(ALGobject *self, PyObject *args)
{
	unsigned char *cp;
	int len;

	if (!PyArg_ParseTuple(args, "s#", &cp, &len))
		return NULL;

	hash_update(&(self->st), cp, len);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef ALG_methods[] = {
	{"copy", (PyCFunction)ALG_copy, METH_VARARGS, ALG_copy__doc__},
	{"digest", (PyCFunction)ALG_digest, METH_VARARGS, ALG_digest__doc__},
	{"hexdigest", (PyCFunction)ALG_hexdigest, METH_VARARGS, 
	 ALG_hexdigest__doc__},
	{"update", (PyCFunction)ALG_update, METH_VARARGS, ALG_update__doc__},
	{NULL,			NULL}		/* sentinel */
};

static PyObject *
ALG_getattr(PyObject *self, char *name)
{
	if (strcmp(name, "digest_size")==0)
		return PyInt_FromLong(DIGEST_SIZE);
	
	return Py_FindMethod(ALG_methods, self, name);
}

static PyTypeObject ALGtype = {
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	_MODULE_STRING,			/*tp_name*/
	sizeof(ALGobject),	/*tp_size*/
	0,			/*tp_itemsize*/
	/* methods */
	ALG_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	ALG_getattr, /*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
        0,			/*tp_as_number*/
};


/* The single module-level function: new() */

static char ALG_new__doc__[] =
"new([string]): Return a new " _MODULE_STRING 
" hashing object.  An optional string "
"argument may be provided; if present, this string will be "
"automatically hashed into the initial state of the object."; 

static PyObject *
ALG_new(PyObject *self, PyObject *args)
{
        ALGobject *new;
	unsigned char *cp = NULL;
	int len;
	
	if ((new = newALGobject()) == NULL)
		return NULL;

	if (!PyArg_ParseTuple(args, "|s#",
			      &cp, &len)) {
	        Py_DECREF(new);
		return NULL;
	}

        hash_init(&(new->st));

	if (PyErr_Occurred()) {
		Py_DECREF(new); 
		return NULL;
	}
	if (cp)
		hash_update(&(new->st), cp, len);

	return (PyObject *)new;
}


/* List of functions exported by this module */

static struct PyMethodDef ALG_functions[] = {
	{"new", (PyCFunction)ALG_new, METH_VARARGS, ALG_new__doc__},
	{NULL,			NULL}		 /* Sentinel */
};


/* Initialize this module. */

#if PYTHON_API_VERSION < 1011
#define PyModule_AddIntConstant(m,n,v) {PyObject *o=PyInt_FromLong(v); \
           if (o!=NULL) \
             {PyDict_SetItemString(PyModule_GetDict(m),n,o); Py_DECREF(o);}}
#endif

void
_MODULE_NAME (void)
{
	PyObject *m;

	ALGtype.ob_type = &PyType_Type;
	m = Py_InitModule("Crypto.Hash." _MODULE_STRING, ALG_functions);

	/* Add some symbolic constants to the module */
	PyModule_AddIntConstant(m, "digest_size", DIGEST_SIZE);

	/* Check for errors */
	if (PyErr_Occurred())
		Py_FatalError("can't initialize module " 
                              _MODULE_STRING);
}
