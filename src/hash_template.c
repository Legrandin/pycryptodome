/*
 *  hash.in : Generic framework for hash function extension modules
 *
 * Part of the Python Cryptography Toolkit, version 1.1
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.  This software is provided "as is" without
 * warranty of fitness for use or suitability for any purpose, express
 * or implied. Use at your own risk or not at all. 
 *
 */
  
/* Basic object type */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef _HAVE_STDC_HEADERS
#include <string.h>
#endif

#define Py_USE_NEW_NAMES
#include "Python.h"
#include "modsupport.h"

/* Endianness testing and definitions */
#define TestEndianness(variable) {int i=1; variable=PCT_BIG_ENDIAN;\
	if (*((char*)&i)==1) variable=PCT_LITTLE_ENDIAN;}

#define PCT_LITTLE_ENDIAN 1
#define PCT_BIG_ENDIAN 0

/* This is where the actual code for the hash function will go */

#define PCTObject_HEAD PyObject_HEAD
#define PCT_Str(x) #x
/* GetKeywordArg has been abandoned for PyArg_ParseTupleAndKeywords */
#define GetKeywordArg(name, default) {\
	PyObject *arg; \
			       if (kwdict==NULL || \
				   (( arg=PyDict_GetItemString(kwdict, PCT_Str(name)))==NULL )) {new->name = default;} else { \
																      if (!PyInt_Check(arg)) \
					   { \
						     PyErr_SetString(PyExc_TypeError, "Keyword argument must have integer value"); \
																	   Py_DECREF(new); \
																				   return NULL; \
																							} \
																								  new->name = PyInt_AsLong(arg); \
																													 } \
																														   }

@@IMPLEMENTATION@@ 	

staticforward PyTypeObject @@ALGORITHM@@type;

#define is_@@ALGORITHM@@object(v) ((v)->ob_type == &@@ALGORITHM@@type)

static @@ALGORITHM@@object *
new@@ALGORITHM@@object()
{
	@@ALGORITHM@@object *new;

	new = PyObject_NEW(@@ALGORITHM@@object, &@@ALGORITHM@@type);
	return new;
}

/* Internal methods for a hashing object */

static void
@@ALGORITHM@@_dealloc(ptr)
	PyObject *ptr;
{
	@@ALGORITHM@@object *@@ALGORITHM@@ptr=(@@ALGORITHM@@object *)ptr;
	PyMem_DEL(@@ALGORITHM@@ptr);
}


/* External methods for a hashing object */

static char @@ALGORITHM@@_copy__doc__[] = 
"Return a copy of the hashing object.";

static PyObject *
@@ALGORITHM@@_copy(self, args)
	@@ALGORITHM@@object *self;
	PyObject *args;
{
	@@ALGORITHM@@object *newobj;

	if ( (newobj = new@@ALGORITHM@@object())==NULL)
		return(NULL);

	if (!PyArg_NoArgs(args))
	{Py_DECREF(newobj); return(NULL);}
	
	@@ALGORITHM@@copy(self, newobj);
	return((PyObject *)newobj); 
}

static char @@ALGORITHM@@_digest__doc__[] = 
"Return the digest value as a string of binary data.";

static PyObject *
@@ALGORITHM@@_digest(self, args)
	@@ALGORITHM@@object *self;
	PyObject *args;
{

	if (!PyArg_NoArgs(args))
		return NULL;

	return (PyObject *)@@ALGORITHM@@digest(self);
}

static char @@ALGORITHM@@_hexdigest__doc__[] = 
"Return the digest value as a string of hexadecimal digits.";

static PyObject *
@@ALGORITHM@@_hexdigest(self, args)
	@@ALGORITHM@@object *self;
	PyObject *args;
{
	PyObject *value, *retval;
	unsigned char *raw_digest, *hex_digest;
	int i, j, size;

	if (!PyArg_NoArgs(args))
		return NULL;

	/* Get the raw (binary) digest value */
	value = (PyObject *)@@ALGORITHM@@digest(self);
	size = PyString_Size(value);
	raw_digest = PyString_AsString(value);

	/* Create a new string */
	retval = PyString_FromStringAndSize(NULL, size * 2 );
	hex_digest = PyString_AsString(retval);

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

static char @@ALGORITHM@@_update__doc__[] = 
"Update this hashing object's state with the provided string.";

static PyObject *
@@ALGORITHM@@_update(self, args)
	@@ALGORITHM@@object *self;
	PyObject *args;
{
	unsigned char *cp;
	int len;

	if (!PyArg_Parse(args, "s#", &cp, &len))
		return NULL;

	@@ALGORITHM@@update(self, cp, len);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef @@ALGORITHM@@_methods[] = {
	{"copy",		(PyCFunction)@@ALGORITHM@@_copy, 0, @@ALGORITHM@@_copy__doc__},
	{"digest",		(PyCFunction)@@ALGORITHM@@_digest, 0, @@ALGORITHM@@_digest__doc__},
	{"hexdigest",		(PyCFunction)@@ALGORITHM@@_hexdigest, 0, @@ALGORITHM@@_hexdigest__doc__},
	{"update",		(PyCFunction)@@ALGORITHM@@_update, 0, @@ALGORITHM@@_update__doc__},
	{NULL,			NULL}		/* sentinel */
};

static PyObject *
@@ALGORITHM@@_getattr(self, name)
	@@ALGORITHM@@object *self;
	char *name;
{
	if (strcmp(name, "blocksize")==0)
		return PyInt_FromLong(1);
	if (strcmp(name, "digestsize")==0)
		return PyInt_FromLong(@@DIGESTSIZE@@);
	
	return Py_FindMethod(@@ALGORITHM@@_methods, (PyObject *)self, name);
}

static PyTypeObject @@ALGORITHM@@type = {
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"@@ALGORITHM@@",			/*tp_name*/
	sizeof(@@ALGORITHM@@object),	/*tp_size*/
	0,			/*tp_itemsize*/
	/* methods */
	@@ALGORITHM@@_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	@@ALGORITHM@@_getattr, /*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
        0,			/*tp_as_number*/
};


/* The single module-level function: new() */

static char @@ALGORITHM@@_new__doc__[] =
 "Return a new @@ALGORITHM@@ hashing object.  An optional string "
 "argument may be provided; if present, this string will be "
 " automatically hashed."; 

static char *kwlist[] = {"string", @@KEYWORDLIST@@ 
			 NULL};

static PyObject *
@@ALGORITHM@@_new(self, args, kwdict)
	PyObject *self;
	PyObject *args;
	PyObject *kwdict;
{
	@@ALGORITHM@@object *new;
	unsigned char *cp = NULL;
	int len;
	
	if ((new = new@@ALGORITHM@@object()) == NULL)
		return NULL;

	@@KEYWORDDEFAULTS@@

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "|s#"  @@KEYWORDFMT@@, kwlist,
					 &cp, &len @@KEYWORDPTRS@@)) {
	        Py_DECREF(new);
		return NULL;
	}

        @@ALGORITHM@@init(new);

	if (PyErr_Occurred()) {Py_DECREF(new); return NULL;}
	if (cp)
		@@ALGORITHM@@update(new, cp, len);

	return (PyObject *)new;
}


/* List of functions exported by this module */

static struct PyMethodDef @@ALGORITHM@@_functions[] = {
	{"new",			(PyCFunction)@@ALGORITHM@@_new, METH_VARARGS|METH_KEYWORDS, @@ALGORITHM@@_new__doc__},
	{"@@MODNAME@@",		(PyCFunction)@@ALGORITHM@@_new, METH_VARARGS|METH_KEYWORDS, @@ALGORITHM@@_new__doc__},
	{NULL,			NULL}		 /* Sentinel */
};


/* Initialize this module. */

#define insint(n,v) {PyObject *o=PyInt_FromLong(v); if (o!=NULL) {PyDict_SetItemString(d,n,o); Py_DECREF(o);}}

void
init@@MODNAME@@()
{
	PyObject *d, *m;

	@@ALGORITHM@@type.ob_type = &PyType_Type;
	m = Py_InitModule("@@MODNAME@@", @@ALGORITHM@@_functions);

	/* Add some symbolic constants to the module */
	d = PyModule_GetDict(m);
	insint("blocksize", 1);  /* For future use, in case some hash
				    functions require an integral number of
				    blocks */ 
	insint("digestsize", @@DIGESTSIZE@@);

	/* Check for errors */
	if (PyErr_Occurred())
		Py_FatalError("can't initialize module @@MODNAME@@");
}


