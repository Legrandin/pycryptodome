
/*Rename cipherMode -> mode*/

/* -*- C -*- */
/*
 *  block_template.c : Generic framework for block encryption algorithms
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

#define MODE_ECB 1
#define MODE_CBC 2
#define MODE_CFB 3
#define MODE_PGP 4
#define MODE_OFB 5
#define MODE_CTR 6

        /*
	 *
	 * Python interface
	 *
	 */

typedef struct 
{
  PyObject_HEAD 
  int cipherMode, count, segment_size;
  unsigned char IV[BLOCK_SIZE], oldCipher[BLOCK_SIZE];
  PyObject *counter;
  block_state st;
} ALGobject;

staticforward PyTypeObject ALGtype;

#define is_ALGobject(v)		((v)->ob_type == &ALGtype)

static ALGobject *
newALGobject(void)
{
 ALGobject * new;
 new = PyObject_NEW(ALGobject, &ALGtype);
 new->cipherMode = MODE_ECB;
 return new;
}

static void
ALGdealloc(PyObject *ptr)
{		/* Overwrite the contents of the object, just in case... */
 int i;
 ALGobject *self=(ALGobject *)ptr;

 for (i = 0; i < sizeof(ALGobject); i++)
   *((char *) self + i) = '\0';
 PyMem_DEL(self);
}


static char ALGnew__doc__[] = 
"Return a new ALG encryption object.";

static char *kwlist[] = {"key", "mode", "IV", "counter", "segment_size",
			 NULL};

static ALGobject *
ALGnew(PyObject *self, PyObject *args, PyObject *kwdict)
{
 unsigned char *key, *IV;

 ALGobject * new;
 int i, keylen, IVlen=0, mode=MODE_ECB, segment_size=0;
 
 PyObject *counter = NULL;

 new = newALGobject();
 /* Set default values */
 if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#|is#Oi", kwlist,
				  &key, &keylen, &mode, &IV, &IVlen,
				  &counter, &segment_size
				  ))
   {
     Py_XDECREF(new);
     return NULL;
   }

 if (KEY_SIZE!=0 && keylen!=KEY_SIZE)
   {
    PyErr_SetString(PyExc_ValueError, "Key must be "
		    "key_size bytes long");
    return (NULL);
   }
 if (KEY_SIZE==0 && keylen==0)
   {
    PyErr_SetString(PyExc_ValueError, "Key cannot be "
		    "the null string (0 bytes long)");
    return (NULL);
   }
 if (IVlen != BLOCK_SIZE && IVlen != 0)
   {
    PyErr_SetString(PyExc_ValueError, "IV must be "
		    "BLOCK_SIZE bytes long");
    return (NULL);
   }
 if (mode<MODE_ECB || mode>MODE_CTR) 
   {
     PyErr_SetString(PyExc_ValueError, "Unknown cipher feedback mode");
     return (NULL);
   }

 /* Mode-specific checks */
 if (mode == MODE_CFB) {
   if (segment_size == 0) segment_size = BLOCK_SIZE*8;
   if (segment_size < 1 || segment_size > BLOCK_SIZE*8) {
     PyErr_SetString(PyExc_ValueError, "segment_size must be between "
		     "1 and 8*block_size");
   }
   new->segment_size = segment_size;
 }

 if (mode == MODE_CTR) {
   if (!PyCallable_Check(counter)) {
     PyErr_SetString(PyExc_ValueError, 
		     "'counter' parameter must be a callable object");
   }
   else {
     new->counter = counter;
   }
 } else {
   if (counter != NULL) {
     PyErr_SetString(PyExc_ValueError, 
		     "'counter' parameter only useful with CTR mode");
   }
 }

 block_init(&(new->st), key, keylen);
 if (PyErr_Occurred())
   {
     Py_DECREF(new);
     return(NULL);
   }
 for (i = 0; i < BLOCK_SIZE; i++)
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

static char ALG_Encrypt__doc__[] =
"Decrypt the provided string of binary data.";

static PyObject *
ALG_Encrypt(ALGobject *self, PyObject *args)
{
  char *buffer, *str;
  char temp[BLOCK_SIZE];
  int i, j, len;
  PyObject *result;
  
  if (!PyArg_Parse(args, "s#", &str, &len))
    return (NULL);
  if (len==0)			/* Handle empty string */
    {
      return PyString_FromStringAndSize(NULL, 0);
    }
  if ( (len % BLOCK_SIZE) !=0 && self->cipherMode!=MODE_CFB
      && self->cipherMode!=MODE_PGP)
    {
      PyErr_SetString(PyExc_ValueError, "Strings for ALG "
		      "must be a multiple of BLOCK_SIZE in length");
      return(NULL);
    }
  buffer=malloc(len);
  if (buffer==NULL) 
    {
      PyErr_SetString(PyExc_MemoryError, "No memory available in "
		      "ALG encrypt");
      return(NULL);
    }
  switch(self->cipherMode)
    {
    case(MODE_ECB):      
      for(i=0; i<len; i+=BLOCK_SIZE) 
	{
	  memcpy(buffer+i, str+i, BLOCK_SIZE);
	  block_encrypt(&(self->st), buffer+i);
	}
      break;
    case(MODE_CBC):      
      for(i=0; i<len; i+=BLOCK_SIZE) 
	{
	  for(j=0; j<BLOCK_SIZE; j++)
	    {
	      temp[j]=str[i+j]^self->IV[j];
	    }
	  block_encrypt(&(self->st), temp);
	  memcpy(buffer+i, temp, BLOCK_SIZE);
	  memcpy(self->IV, temp, BLOCK_SIZE);
	}
      break;
    case(MODE_CFB):      
      for(i=0; i<len; i++) 
	{
	  block_encrypt(&(self->st), self->IV);
	  buffer[i]=str[i]^self->IV[0];
	  memmove(self->IV, self->IV+1, BLOCK_SIZE-1);
	  self->IV[BLOCK_SIZE-1]=buffer[i];
	}
      break;
    case(MODE_PGP):
      if (len<=BLOCK_SIZE-self->count) 
	{			/* If less than one block, XOR it in */
	  for(i=0; i<len; i++) 
	      buffer[i] = self->IV[self->count+i] ^= str[i];
	  self->count += len;
	}
      else 
	{
	  int j;
	  for(i=0; i<BLOCK_SIZE-self->count; i++) 
	      buffer[i] = self->IV[self->count+i] ^= str[i];
	  self->count=0;
	  for(; i<len-BLOCK_SIZE; i+=BLOCK_SIZE) 
	    {
	      memcpy(self->oldCipher, self->IV, BLOCK_SIZE);
	      block_encrypt(&(self->st), self->IV);
	      for(j=0; j<BLOCK_SIZE; j++)
		buffer[i+j] = self->IV[j] ^= str[i+j];
	    }
	  /* Do the remaining 1 to BLOCK_SIZE bytes */
          memcpy(self->oldCipher, self->IV, BLOCK_SIZE);
	  block_encrypt(&(self->st), self->IV);
	  self->count=len-i;
	  for(j=0; j<len-i; j++) 
	    {
	      buffer[i+j] = self->IV[j] ^= str[i+j];
	    }
	}
      break;
    case(MODE_OFB):
      break;
    case(MODE_CTR):
      for(i=0; i<len; i+=BLOCK_SIZE) 
	{
          PyObject *ctr = PyObject_Call(self->counter, PyTuple_New(0), NULL);
	  if (ctr == NULL) return NULL;
	  if (!PyString_Check(ctr))
	    {
	      PyErr_SetString(PyExc_TypeError, 
			      "CTR counter function didn't return a string");
	      Py_DECREF(ctr);
	      return NULL;
	    }
	  if (PyString_Size(ctr) != BLOCK_SIZE) {
	      PyErr_SetString(PyExc_TypeError, 
			      "CTR counter function returned string of incorrect length");
	      Py_DECREF(ctr);
	      return NULL;
	  }
	  memcpy(temp, PyString_AsString, BLOCK_SIZE);
	  Py_DECREF(ctr);
	  block_encrypt(&(self->st), temp);
	  for(j=0; j<BLOCK_SIZE; j++)
	    {
	      buffer[i+j] = str[i+j]^temp[j];
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

static char ALG_Decrypt__doc__[] =
"Decrypt the provided string of binary data.";


static PyObject *
ALG_Decrypt(ALGobject *self, PyObject *args)
{
  char *buffer, *str;
  char temp[BLOCK_SIZE];
  int i, j, len;
  PyObject *result;
  
  if (!PyArg_Parse(args, "s#", &str, &len))
    return (NULL);
  if (len==0)			/* Handle empty string */
    {
      return PyString_FromStringAndSize(NULL, 0);
    }
  if ( (len % BLOCK_SIZE) !=0 && self->cipherMode!=MODE_CFB
      && self->cipherMode!=MODE_PGP) 
    {
      PyErr_SetString(PyExc_ValueError, "Strings for ALG "
		      "must be a multiple of BLOCK_SIZE in length");
      return(NULL);
    }
  buffer=malloc(len);
  if (buffer==NULL) 
    {
      PyErr_SetString(PyExc_MemoryError, "No memory available in "
		      "ALG decrypt");
      return(NULL);
    }
  switch(self->cipherMode)
    {
    case(MODE_ECB):      
      for(i=0; i<len; i+=BLOCK_SIZE) 
	{
	  memcpy(buffer+i, str+i, BLOCK_SIZE);
	  block_decrypt(&(self->st), buffer+i);
	}
      break;
    case(MODE_CBC):      
      for(i=0; i<len; i+=BLOCK_SIZE) 
	{
          memcpy(self->oldCipher, self->IV, BLOCK_SIZE);
	  memcpy(temp, str+i, BLOCK_SIZE);
	  block_decrypt(&(self->st), temp);
	  for(j=0; j<BLOCK_SIZE; j++) 
	    {
	      buffer[i+j]=temp[j]^self->IV[j];
	      self->IV[j]=str[i+j];
	    }
	}
      break;
    case(MODE_CFB):      
      for(i=0; i<len; i++) 
	{
	  block_encrypt(&(self->st), self->IV);
	  buffer[i]=str[i]^self->IV[0];
	  memmove(self->IV, self->IV+1, BLOCK_SIZE-1);
	  self->IV[BLOCK_SIZE-1]=str[i];
	}
      break;
    case(MODE_PGP):
      if (len<=BLOCK_SIZE-self->count) 
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
	  for(i=0; i<BLOCK_SIZE-self->count; i++) 
	    {
	      t=self->IV[self->count+i];
	      buffer[i] = t ^ (self->IV[self->count+i] = str[i]);
	    }
	  self->count=0;
	  for(; i<len-BLOCK_SIZE; i+=BLOCK_SIZE) 
	    {
	      memcpy(self->oldCipher, self->IV, BLOCK_SIZE);
	      block_encrypt(&(self->st), self->IV);
	      for(j=0; j<BLOCK_SIZE; j++)
		{
		  t=self->IV[j];
		  buffer[i+j] = t ^ (self->IV[j] = str[i+j]);
		}
	    }
	  /* Do the remaining 1 to BLOCK_SIZE bytes */
          memcpy(self->oldCipher, self->IV, BLOCK_SIZE);
	  block_encrypt(&(self->st), self->IV);
	  self->count=len-i;
	  for(j=0; j<len-i; j++) 
	    {
	      t=self->IV[j];
	      buffer[i+j] = t ^ (self->IV[j] = str[i+j]);
	    }
	}
      break;
    case (MODE_OFB):
      break;
    case (MODE_CTR):
      for(i=0; i<len; i+=BLOCK_SIZE) 
	{
          PyObject *ctr = PyObject_Call(self->counter, PyTuple_New(0), NULL);
	  if (ctr == NULL) return NULL;
	  if (!PyString_Check(ctr))
	    {
	      PyErr_SetString(PyExc_TypeError, 
			      "CTR counter function didn't return a string");
	      Py_DECREF(ctr);
	      return NULL;
	    }
	  if (PyString_Size(ctr) != BLOCK_SIZE) {
	      PyErr_SetString(PyExc_TypeError, 
			      "CTR counter function returned string of incorrect length");
	      Py_DECREF(ctr);
	      return NULL;
	  }
	  memcpy(temp, PyString_AsString, BLOCK_SIZE);
	  Py_DECREF(ctr);
	  block_encrypt(&(self->st), temp);
	  for(j=0; j<BLOCK_SIZE; j++)
	    {
	      buffer[i+j] = str[i+j]^temp[j];
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

static char ALG_Sync__doc__[] =
"For objects using the PGP feedback mode, this method modifies the IV, "
"synchronizing it with the preceding ciphertext.";

static PyObject *
ALG_Sync(ALGobject *self, PyObject *args)
{
  if (self->cipherMode!=MODE_PGP) 
    {
      PyErr_SetString(PyExc_SystemError, "sync() operation not defined for "
   	         "this feedback mode");
      return(NULL);
    }

  if (self->count!=8) 
    {
      memmove(self->IV+BLOCK_SIZE-self->count, self->IV, self->count);
      memcpy(self->IV, self->oldCipher+self->count, BLOCK_SIZE-self->count);
      self->count=8;
    }
  Py_INCREF(Py_None);
  return Py_None;
}

#if 0
void PrintState(self, msg)
     ALGobject *self;
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


/* ALG object methods */

static PyMethodDef ALGmethods[] =
{
 {"encrypt", (PyCFunction) ALG_Encrypt, 0, ALG_Encrypt__doc__},
 {"decrypt", (PyCFunction) ALG_Decrypt, 0, ALG_Decrypt__doc__},
 {"sync", (PyCFunction) ALG_Sync, 0, ALG_Sync__doc__},
 {NULL, NULL}			/* sentinel */
};


static int
ALGsetattr(PyObject *ptr, char *name, PyObject *v)
{
  ALGobject *self=(ALGobject *)ptr;
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
  if (PyString_Size(v)!=BLOCK_SIZE) 
    {
      PyErr_SetString(PyExc_ValueError, "ALG IV must be "
		      "BLOCK_SIZE bytes long");
      return -1;
    }
  memcpy(self->IV, PyString_AsString(v), BLOCK_SIZE);
  return (0);
}

static PyObject *
ALGgetattr(PyObject *s, char *name)
{
  ALGobject *self = (ALGobject*)s;
  if (strcmp(name, "IV") == 0) 
    {
      return(PyString_FromStringAndSize(self->IV, BLOCK_SIZE));
    }
  if (strcmp(name, "mode") == 0)
     {
       return(PyInt_FromLong((long)(self->cipherMode)));
     }
  if (strcmp(name, "block_size") == 0)
     {
       return PyInt_FromLong(BLOCK_SIZE);
     }
  if (strcmp(name, "key_size") == 0)
     {
       return PyInt_FromLong(KEY_SIZE);
     }
 return Py_FindMethod(ALGmethods, (PyObject *) self, name);
}

/* List of functions defined in the module */

static struct PyMethodDef modulemethods[] =
{
 {"new", (PyCFunction) ALGnew, METH_VARARGS|METH_KEYWORDS, ALGnew__doc__},
 {NULL, NULL}			/* sentinel */
};

static PyTypeObject ALGtype =
{
 PyObject_HEAD_INIT(NULL)
 0,				/*ob_size*/
 "ALG",		/*tp_name*/
 sizeof(ALGobject),	/*tp_size*/
 0,				/*tp_itemsize*/
 /* methods */
 ALGdealloc,	/*tp_dealloc*/
 0,				/*tp_print*/
 ALGgetattr,	/*tp_getattr*/
 ALGsetattr,    /*tp_setattr*/
 0,			/*tp_compare*/
 (reprfunc) 0,			/*tp_repr*/
 0,				/*tp_as_number*/
};

/* Initialization function for the module (*must* be called initxx) */

#define insint(n,v) {PyObject *o=PyInt_FromLong(v); if (o!=NULL) {PyDict_SetItemString(d,n,o); Py_DECREF(o);}}


#define _STR(x) #x
#define _XSTR(x) _STR(x)
#define _PASTE(x,y) x##y
#define _PASTE2(x,y) _PASTE(x,y)
#define _MODULE_NAME _PASTE2(init,MODULE_NAME)
#define _MODULE_STRING _XSTR(MODULE_NAME)

void
_MODULE_NAME (void)
{
 PyObject *m, *d;

 ALGtype.ob_type = &PyType_Type;

 /* Create the module and add the functions */
 m = Py_InitModule("Crypto.Cipher." _MODULE_STRING, modulemethods);

 /* Add some symbolic constants to the module */
 d = PyModule_GetDict(m);

 insint("MODE_ECB", MODE_ECB);
 insint("MODE_CBC", MODE_CBC);
 insint("MODE_CFB", MODE_CFB);
 insint("MODE_PGP", MODE_PGP);
 insint("MODE_OFB", MODE_OFB);
 insint("MODE_CTR", MODE_CTR);
 insint("block_size", BLOCK_SIZE);
 insint("key_size", KEY_SIZE);

 /* Check for errors */
 if (PyErr_Occurred())
   Py_FatalError("can't initialize module " _MODULE_STRING);
}

