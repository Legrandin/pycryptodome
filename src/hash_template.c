/*
 *  hash_template.c : Generic framework for hash function extension modules
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

/*#include "modsupport.h"*/

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

	new = PyObject_NEW(ALGobject, &ALGtype);
	return new;
}

/* Internal methods for a hashing object */

static void
ALG_dealloc(PyObject *ptr)
{
	ALGobject *ALGptr=(ALGobject *)ptr;
	PyMem_DEL(ALGptr);
}


/* External methods for a hashing object */

static char ALG_copy__doc__[] = 
"Return a copy of the hashing object.";

static PyObject *
ALG_copy(ALGobject *self, PyObject *args)
{
	ALGobject *newobj;

	if ( (newobj = newALGobject())==NULL)
		return(NULL);

	if (!PyArg_NoArgs(args))
	{Py_DECREF(newobj); return(NULL);}
	
	hash_copy(&(self->st), &(newobj->st));
	return((PyObject *)newobj); 
}

static char ALG_digest__doc__[] = 
"Return the digest value as a string of binary data.";

static PyObject *
ALG_digest(ALGobject *self, PyObject *args)
{

	if (!PyArg_NoArgs(args))
		return NULL;

	return (PyObject *)hash_digest(&(self->st));
}

static char ALG_hexdigest__doc__[] = 
"Return the digest value as a string of hexadecimal digits.";

static PyObject *
ALG_hexdigest(ALGobject *self, PyObject *args)
{
	PyObject *value, *retval;
	unsigned char *raw_digest, *hex_digest;
	int i, j, size;

	if (!PyArg_NoArgs(args))
		return NULL;

	/* Get the raw (binary) digest value */
	value = (PyObject *)hash_digest(&(self->st));
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

static char ALG_update__doc__[] = 
"Update this hashing object's state with the provided string.";

static PyObject *
ALG_update(self, args)
	ALGobject *self;
	PyObject *args;
{
	unsigned char *cp;
	int len;

	if (!PyArg_Parse(args, "s#", &cp, &len))
		return NULL;

	hash_update(&(self->st), cp, len);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef ALG_methods[] = {
	{"copy",		(PyCFunction)ALG_copy, 0, ALG_copy__doc__},
	{"digest",		(PyCFunction)ALG_digest, 0, ALG_digest__doc__},
	{"hexdigest",		(PyCFunction)ALG_hexdigest, 0, ALG_hexdigest__doc__},
	{"update",		(PyCFunction)ALG_update, 0, ALG_update__doc__},
	{NULL,			NULL}		/* sentinel */
};

static PyObject *
ALG_getattr(self, name)
	ALGobject *self;
	char *name;
{
	if (strcmp(name, "digest_size")==0)
		return PyInt_FromLong(DIGEST_SIZE);
	
	return Py_FindMethod(ALG_methods, (PyObject *)self, name);
}

static PyTypeObject ALGtype = {
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"ALG",			/*tp_name*/
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
 "Return a new ALG hashing object.  An optional string "
 "argument may be provided; if present, this string will be "
 " automatically hashed."; 

static PyObject *
ALG_new(self, args)
	PyObject *self;
	PyObject *args;
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

	if (PyErr_Occurred()) {Py_DECREF(new); return NULL;}
	if (cp)
		hash_update(&(new->st), cp, len);

	return (PyObject *)new;
}


/* List of functions exported by this module */

static struct PyMethodDef ALG_functions[] = {
	{"new",			(PyCFunction)ALG_new, METH_VARARGS, 
	 ALG_new__doc__},
	{NULL,			NULL}		 /* Sentinel */
};


/* Initialize this module. */

#define insint(n,v) {PyObject *o=PyInt_FromLong(v); if (o!=NULL) {PyDict_SetItemString(d,n,o); Py_DECREF(o);}}

#define _STR(x) #x
#define _PASTE(x,y) x##y
#define _PASTE2(x,y) _PASTE(x,y)
#define _MODULE_NAME _PASTE2(init,MODULE_NAME)
#define _MODULE_STRING _STR(MODULE_NAME)

void
_MODULE_NAME ()
{
	PyObject *d, *m;

	ALGtype.ob_type = &PyType_Type;
	m = Py_InitModule("Crypto.Hash.MD4", ALG_functions);

	/* Add some symbolic constants to the module */
	d = PyModule_GetDict(m);
	insint("digest_size", DIGEST_SIZE);

	/* Check for errors */
	if (PyErr_Occurred())
		Py_FatalError("can't initialize module " 
                              _MODULE_STRING);
}


