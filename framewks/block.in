/* -*- C -*- */
/*
 *  block.in : Generic framework for block encryption algorithms
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _HAVE_STDC_HEADERS
#include <string.h>
#endif

#include "Python.h"
#include "modsupport.h" 

#ifdef __GNUC__
#define inline __inline__
#else
#define inline
#endif


 /* Cipher operation modes */

#define MODE_ECB 0
#define MODE_CFB 1
#define MODE_CBC 2
#define MODE_OFB 3
#define MODE_PGP 4

       /* Endianness testing and definitions */
#define TestEndianness(variable) {int i=1; variable=PCT_BIG_ENDIAN;\
                                  if (*((char*)&i)==1) variable=PCT_LITTLE_ENDIAN;}

#define PCT_LITTLE_ENDIAN 1
#define PCT_BIG_ENDIAN 0

        /*
	 *
	 * Python interface
	 *
	 */

#define PCTObject_HEAD PyObject_HEAD int cipherMode, count; \
                 unsigned char IV[@@BLOCKSIZE@@], oldCipher[@@BLOCKSIZE@@];

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

#define is_@@ALGORITHM@@object(v)		((v)->ob_type == &@@ALGORITHM@@type)

static @@ALGORITHM@@object *
 new@@ALGORITHM@@object()
{
 @@ALGORITHM@@object * new;
 new = PyObject_NEW(@@ALGORITHM@@object, &@@ALGORITHM@@type);
 new->cipherMode = MODE_ECB;
 return new;
}

static void
@@ALGORITHM@@dealloc(ptr)
PyObject *ptr;
{		/* Overwrite the contents of the object, just in case... */
 int i;
 @@ALGORITHM@@object *self=(@@ALGORITHM@@object *)ptr;

 for (i = 0; i < sizeof(@@ALGORITHM@@object); i++)
  *((char *) self + i) = '\0';
 PyMem_DEL(self);
}


static char @@ALGORITHM@@new__doc__[] = 
"Return a new @@ALGORITHM@@ encryption object.";

static char *kwlist[] = {"key", "mode", "IV", @@KEYWORDLIST@@ 
			 NULL};

static @@ALGORITHM@@object *
@@ALGORITHM@@new(self, args, kwdict)
     PyObject *self;		/* Not used */
     PyObject *args;
     PyObject *kwdict;
{
 unsigned char *key, *IV;

 @@ALGORITHM@@object * new;
 int i, keylen, IVlen=0, mode=MODE_ECB;

 new = new@@ALGORITHM@@object();
 /* Set default values */
 @@KEYWORDDEFAULTS@@
 if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#|is#" @@KEYWORDFMT@@, kwlist,
		       &key, &keylen, &mode, &IV, &IVlen @@KEYWORDPTRS@@))
   {
     Py_XDECREF(new);
     return NULL;
   }

 if (@@KEYSIZE@@!=0 && keylen!=@@KEYSIZE@@)
   {
    PyErr_SetString(PyExc_ValueError, "@@ALGORITHM@@ key must be "
		    "@@KEYSIZE@@ bytes long");
    return (NULL);
   }
 if (@@KEYSIZE@@==0 && keylen==0)
   {
    PyErr_SetString(PyExc_ValueError, "@@ALGORITHM@@ key cannot be "
		    "the null string (0 bytes long)");
    return (NULL);
   }
 if (IVlen != @@BLOCKSIZE@@ && IVlen != 0)
   {
    PyErr_SetString(PyExc_ValueError, "@@ALGORITHM@@ IV must be "
		    "@@BLOCKSIZE@@ bytes long");
    return (NULL);
   }
 if (mode<MODE_ECB || mode>MODE_PGP) 
   {
     PyErr_SetString(PyExc_ValueError, "Unknown cipher feedback mode");
    return (NULL);
   }
 @@ALGORITHM@@init(new, key, keylen);
 if (PyErr_Occurred())
   {
     Py_DECREF(new);
     return(NULL);
   }
 for (i = 0; i < @@BLOCKSIZE@@; i++)
   {
    new->IV[i] = 0;
    new->oldCipher[i]=0;
   }
 for (i = 0; i < IVlen; i++)
   {
    new->IV[i] = IV[i];
   }
 new->cipherMode = mode;
 new->count=8;
 return new;
}

static char @@ALGORITHM@@_Encrypt__doc__[] =
"Decrypt the provided string of binary data.";

static PyObject *
@@ALGORITHM@@_Encrypt(self, args)
@@ALGORITHM@@object * self;
     PyObject *args;
{
  char *buffer, *str;
  char temp[@@BLOCKSIZE@@];
  int i, j, len;
  PyObject *result;
  
  if (!PyArg_Parse(args, "s#", &str, &len))
    return (NULL);
  if (len==0)			/* Handle empty string */
    {
      return PyString_FromStringAndSize(NULL, 0);
    }
  if ( (len % @@BLOCKSIZE@@) !=0 && self->cipherMode!=MODE_CFB
      && self->cipherMode!=MODE_PGP)
    {
      PyErr_SetString(PyExc_ValueError, "Strings for @@ALGORITHM@@ "
		      "must be a multiple of @@BLOCKSIZE@@ in length");
      return(NULL);
    }
  buffer=malloc(len);
  if (buffer==NULL) 
    {
      PyErr_SetString(PyExc_MemoryError, "No memory available in "
		      "@@ALGORITHM@@ encrypt");
      return(NULL);
    }
  switch(self->cipherMode)
    {
    case(MODE_ECB):      
      for(i=0; i<len; i+=@@BLOCKSIZE@@) 
	{
	  memcpy(buffer+i, str+i, @@BLOCKSIZE@@);
	  @@ALGORITHM@@encrypt(self, buffer+i);
	}
      break;
    case(MODE_CBC):      
      for(i=0; i<len; i+=@@BLOCKSIZE@@) 
	{
	  for(j=0; j<@@BLOCKSIZE@@; j++)
	    {
	      temp[j]=str[i+j]^self->IV[j];
	    }
	  @@ALGORITHM@@encrypt(self, temp);
	  memcpy(buffer+i, temp, @@BLOCKSIZE@@);
	  memcpy(self->IV, temp, @@BLOCKSIZE@@);
	}
      break;
    case(MODE_CFB):      
      for(i=0; i<len; i++) 
	{
	  @@ALGORITHM@@encrypt(self, self->IV);
	  buffer[i]=str[i]^self->IV[0];
	  memmove(self->IV, self->IV+1, @@BLOCKSIZE@@-1);
	  self->IV[@@BLOCKSIZE@@-1]=buffer[i];
	}
      break;
    case(MODE_PGP):
      if (len<=@@BLOCKSIZE@@-self->count) 
	{			/* If less than one block, XOR it in */
	  for(i=0; i<len; i++) 
	      buffer[i] = self->IV[self->count+i] ^= str[i];
	  self->count += len;
	}
      else 
	{
	  int j;
	  for(i=0; i<@@BLOCKSIZE@@-self->count; i++) 
	      buffer[i] = self->IV[self->count+i] ^= str[i];
	  self->count=0;
	  for(; i<len-@@BLOCKSIZE@@; i+=@@BLOCKSIZE@@) 
	    {
	      memcpy(self->oldCipher, self->IV, @@BLOCKSIZE@@);
	      @@ALGORITHM@@encrypt(self, self->IV);
	      for(j=0; j<@@BLOCKSIZE@@; j++)
		buffer[i+j] = self->IV[j] ^= str[i+j];
	    }
	  /* Do the remaining 1 to BLOCKSIZE bytes */
          memcpy(self->oldCipher, self->IV, @@BLOCKSIZE@@);
	  @@ALGORITHM@@encrypt(self, self->IV);
	  self->count=len-i;
	  for(j=0; j<len-i; j++) 
	    {
	      buffer[i+j] = self->IV[j] ^= str[i+j];
	    }
	}
      break;
    default:
      PyErr_SetString(PyExc_SystemError, "Unknown ciphertext feedback mode; "
		      "this shouldn't happen");
      return(NULL);
    }
  result=PyString_FromStringAndSize(buffer, len);
  free(buffer);
  return(result);
}

static char @@ALGORITHM@@_Decrypt__doc__[] =
"Decrypt the provided string of binary data.";


static PyObject *
@@ALGORITHM@@_Decrypt(self, args)
@@ALGORITHM@@object * self;
     PyObject *args;
{
  char *buffer, *str;
  char temp[@@BLOCKSIZE@@];
  int i, j, len;
  PyObject *result;
  
  if (!PyArg_Parse(args, "s#", &str, &len))
    return (NULL);
  if (len==0)			/* Handle empty string */
    {
      return PyString_FromStringAndSize(NULL, 0);
    }
  if ( (len % @@BLOCKSIZE@@) !=0 && self->cipherMode!=MODE_CFB
      && self->cipherMode!=MODE_PGP) 
    {
      PyErr_SetString(PyExc_ValueError, "Strings for @@ALGORITHM@@ "
		      "must be a multiple of @@BLOCKSIZE@@ in length");
      return(NULL);
    }
  buffer=malloc(len);
  if (buffer==NULL) 
    {
      PyErr_SetString(PyExc_MemoryError, "No memory available in "
		      "@@ALGORITHM@@ decrypt");
      return(NULL);
    }
  switch(self->cipherMode)
    {
    case(MODE_ECB):      
      for(i=0; i<len; i+=@@BLOCKSIZE@@) 
	{
	  memcpy(buffer+i, str+i, @@BLOCKSIZE@@);
	  @@ALGORITHM@@decrypt(self, buffer+i);
	}
      break;
    case(MODE_CBC):      
      for(i=0; i<len; i+=@@BLOCKSIZE@@) 
	{
          memcpy(self->oldCipher, self->IV, @@BLOCKSIZE@@);
	  memcpy(temp, str+i, @@BLOCKSIZE@@);
	  @@ALGORITHM@@decrypt(self, temp);
	  for(j=0; j<@@BLOCKSIZE@@; j++) 
	    {
	      buffer[i+j]=temp[j]^self->IV[j];
	      self->IV[j]=str[i+j];
	    }
	}
      break;
    case(MODE_CFB):      
      for(i=0; i<len; i++) 
	{
	  @@ALGORITHM@@encrypt(self, self->IV);
	  buffer[i]=str[i]^self->IV[0];
	  memmove(self->IV, self->IV+1, @@BLOCKSIZE@@-1);
	  self->IV[@@BLOCKSIZE@@-1]=str[i];
	}
      break;
    case(MODE_PGP):
      if (len<=@@BLOCKSIZE@@-self->count) 
	{			/* If less than one block, XOR it in */
	  unsigned char t;
	  for(i=0; i<len; i++)
	    {
	      t=self->IV[self->count+i];
	      buffer[i] = t ^ (self->IV[self->count+i] = str[i]);
	    }
	  self->count += len;
	}
      else 
	{
	  int j;
	  unsigned char t;
	  for(i=0; i<@@BLOCKSIZE@@-self->count; i++) 
	    {
	      t=self->IV[self->count+i];
	      buffer[i] = t ^ (self->IV[self->count+i] = str[i]);
	    }
	  self->count=0;
	  for(; i<len-@@BLOCKSIZE@@; i+=@@BLOCKSIZE@@) 
	    {
	      memcpy(self->oldCipher, self->IV, @@BLOCKSIZE@@);
	      @@ALGORITHM@@encrypt(self, self->IV);
	      for(j=0; j<@@BLOCKSIZE@@; j++)
		{
		  t=self->IV[j];
		  buffer[i+j] = t ^ (self->IV[j] = str[i+j]);
		}
	    }
	  /* Do the remaining 1 to BLOCKSIZE bytes */
          memcpy(self->oldCipher, self->IV, @@BLOCKSIZE@@);
	  @@ALGORITHM@@encrypt(self, self->IV);
	  self->count=len-i;
	  for(j=0; j<len-i; j++) 
	    {
	      t=self->IV[j];
	      buffer[i+j] = t ^ (self->IV[j] = str[i+j]);
	    }
	}
      break;
    default:
      PyErr_SetString(PyExc_SystemError, "Unknown ciphertext feedback mode; "
		      "this shouldn't happen");
      return(NULL);
    }
  result=PyString_FromStringAndSize(buffer, len);
  free(buffer);
  return(result);
}

static char @@ALGORITHM@@_Sync__doc__[] =
"For objects using the PGP feedback mode, this method modifies the IV, "
"synchronizing it with the preceding ciphertext.";

static PyObject *
@@ALGORITHM@@_Sync(self, args)
@@ALGORITHM@@object * self;
     PyObject *args;
{
  if (self->cipherMode!=MODE_PGP) 
    {
      PyErr_SetString(PyExc_SystemError, "sync() operation not defined for "
   	         "this feedback mode");
      return(NULL);
    }

  if (self->count!=8) 
    {
      memmove(self->IV+@@BLOCKSIZE@@-self->count, self->IV, self->count);
      memcpy(self->IV, self->oldCipher+self->count, @@BLOCKSIZE@@-self->count);
      self->count=8;
    }
  Py_INCREF(Py_None);
  return Py_None;
}

#if 0
void PrintState(self, msg)
     @@ALGORITHM@@object *self;
     char * msg;
{
  int count;
  
  printf("%sing: %i IV ", msg, (int)self->count);
  for(count=0; count<8; count++) printf("%i ", self->IV[count]);
  printf("\noldCipher:");
  for(count=0; count<8; count++) printf("%i ", self->oldCipher[count]);
  printf("\n");
}
#endif


/* @@ALGORITHM@@ object methods */

static PyMethodDef @@ALGORITHM@@methods[] =
{
 {"encrypt", (PyCFunction) @@ALGORITHM@@_Encrypt, 0, @@ALGORITHM@@_Encrypt__doc__},
 {"decrypt", (PyCFunction) @@ALGORITHM@@_Decrypt, 0, @@ALGORITHM@@_Decrypt__doc__},
 {"sync", (PyCFunction) @@ALGORITHM@@_Sync, 0, @@ALGORITHM@@_Sync__doc__},
 {NULL, NULL}			/* sentinel */
};


static int
@@ALGORITHM@@setattr(ptr, name, v)
     PyObject *ptr;
     char *name;
     PyObject *v;
{
  @@ALGORITHM@@object *self=(@@ALGORITHM@@object *)ptr;
  if (strcmp(name, "IV") != 0) 
    {
      PyErr_SetString(PyExc_AttributeError,
		      "non-existent block cipher object attribute");
      return -1;
    }
  if (v==NULL)
    {
      PyErr_SetString(PyExc_AttributeError,
		      "Can't delete IV attribute of block cipher object");
      return -1;
    }
  if (!PyString_Check(v))
    {
      PyErr_SetString(PyExc_TypeError,
		      "IV attribute of block cipher object must be string");
      return -1;
    }
  if (PyString_Size(v)!=@@BLOCKSIZE@@) 
    {
      PyErr_SetString(PyExc_ValueError, "@@ALGORITHM@@ IV must be "
		      "@@BLOCKSIZE@@ bytes long");
      return -1;
    }
  memcpy(self->IV, PyString_AsString(v), @@BLOCKSIZE@@);
  return (0);
}

static PyObject *
@@ALGORITHM@@getattr(s, name)
     PyObject *s;
     char *name;
{
  @@ALGORITHM@@object *self = (@@ALGORITHM@@object*)s;
  if (strcmp(name, "IV") == 0) 
    {
      return(PyString_FromStringAndSize(self->IV, @@BLOCKSIZE@@));
    }
  if (strcmp(name, "mode") == 0)
     {
       return(PyInt_FromLong((long)(self->cipherMode)));
     }
  if (strcmp(name, "blocksize") == 0)
     {
       return PyInt_FromLong(@@BLOCKSIZE@@);
     }
  if (strcmp(name, "keysize") == 0)
     {
       return PyInt_FromLong(@@KEYSIZE@@);
     }
 return Py_FindMethod(@@ALGORITHM@@methods, (PyObject *) self, name);
}

/* List of functions defined in the module */

static struct PyMethodDef modulemethods[] =
{
 {"new", (PyCFunction) @@ALGORITHM@@new, METH_VARARGS|METH_KEYWORDS, @@ALGORITHM@@new__doc__},
 {NULL, NULL}			/* sentinel */
};

static PyTypeObject @@ALGORITHM@@type =
{
 PyObject_HEAD_INIT(NULL)
 0,				/*ob_size*/
 "@@ALGORITHM@@",		/*tp_name*/
 sizeof(@@ALGORITHM@@object),	/*tp_size*/
 0,				/*tp_itemsize*/
 /* methods */
 @@ALGORITHM@@dealloc,	/*tp_dealloc*/
 0,				/*tp_print*/
 @@ALGORITHM@@getattr,	/*tp_getattr*/
 @@ALGORITHM@@setattr,    /*tp_setattr*/
 0,			/*tp_compare*/
 (reprfunc) 0,			/*tp_repr*/
 0,				/*tp_as_number*/
};

/* Initialization function for the module (*must* be called initxx) */

#define insint(n,v) {PyObject *o=PyInt_FromLong(v); if (o!=NULL) {PyDict_SetItemString(d,n,o); Py_DECREF(o);}}

void
init@@MODNAME@@()
{
 PyObject *m, *d, *x;

 @@ALGORITHM@@type.ob_type = &PyType_Type;

 /* Create the module and add the functions */
 m = Py_InitModule("@@MODNAME@@", modulemethods);

 /* Add some symbolic constants to the module */
 d = PyModule_GetDict(m);
 x = PyString_FromString("@@MODNAME@@.error");
 PyDict_SetItemString(d, "error", x);

 insint("ECB", MODE_ECB);
 insint("CFB", MODE_CFB);
 insint("CBC", MODE_CBC);
 insint("PGP", MODE_PGP);
 insint("blocksize", @@BLOCKSIZE@@);
 insint("keysize", @@KEYSIZE@@);

 /* Check for errors */
 if (PyErr_Occurred())
  Py_FatalError("can't initialize module @@MODNAME@@");
}

