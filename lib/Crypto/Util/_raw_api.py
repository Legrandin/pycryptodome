# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

from __future__ import annotations

import _thread
import abc
import os
import sys
import threading
import weakref
from importlib import machinery
from typing import Any, List, Optional, Tuple, Union

from Crypto.Util._file_system import pycryptodome_filename

# List of file suffixes for Python extensions
extension_suffixes = machinery.EXTENSION_SUFFIXES

# Which types with buffer interface we support (apart from byte strings)
_buffer_type = (bytearray, memoryview)

# While a C function runs, the GIL is released, so another thread could
# resize a bytearray, or release a memoryview, whose memory the C function
# is using. CPython prevents that for as long as the object returned by
# c_uint8_ptr() is alive, but PyPy may not: PyPy 7.3 cannot lock any buffer,
# PyPy 8.0 can lock a bytearray but not a memoryview.
# So, on PyPy, if another thread exists, C functions get a private copy of
# the buffers that PyPy cannot lock (see c_uint8_ptr and c_uint8_ptr_out).
_is_pypy = "__pypy__" in sys.builtin_module_names

# The buffer types that this PyPy keeps locked (found when cffi is loaded)
_pypy_locked_types: tuple = ()


def _must_copy(data: Any) -> bool:
    """Whether C code must get a private copy of the bytearray or
    memoryview data, instead of its memory (see above).

    With one thread only, nothing can change data while a C function runs:
    C code never starts Python threads, and signal handlers only run
    when it returns.
    """
    return _is_pypy and not isinstance(data, _pypy_locked_types) and _thread._count() > 0


class _VoidPointer:
    @abc.abstractmethod
    def get(self) -> Any:
        """Return the memory location we point to"""
        return

    @abc.abstractmethod
    def address_of(self) -> Any:
        """Return a raw pointer to this pointer"""
        return


try:
    # Starting from v2.18, pycparser (used by cffi for in-line ABI mode)
    # stops working correctly when PYOPTIMIZE==2 or the parameter -OO is
    # passed. In that case, we fall back to ctypes.
    # Note that PyPy ships with an old version of pycparser so we can keep
    # using cffi there.
    # See https://github.com/Legrandin/pycryptodome/issues/228
    if "__pypy__" not in sys.builtin_module_names and sys.flags.optimize == 2:
        raise ImportError("CFFI with optimize=2 fails due to pycparser bug.")

    # cffi < 1.16.0 crashes on CPython 3.12+ for Windows due to a removed C API.
    # See https://groups.google.com/g/python-cffi/c/oZkOIZ_zi5k
    import cffi

    if (
        sys.version_info >= (3, 12)
        and os.name == "nt"
        and sys.implementation.name == "cpython"
        and cffi.__version_info__ < (1, 16)
    ):
        raise ImportError("CFFI 1.16.0+ is required with CPython 3.12+ on Windows")

    # ffi.from_buffer() with a type (used by c_uint8_ptr) requires cffi 1.12+
    if cffi.__version_info__ < (1, 12):
        raise ImportError("CFFI 1.12.0+ is required")

    ffi: Any = cffi.FFI()
    null_pointer: Any = ffi.NULL

    _Array = ffi.new("uint8_t[1]").__class__.__bases__

    def _find_pypy_locked_types() -> tuple:
        """Return the buffer types that cannot be resized or released
        while ffi.from_buffer() uses them"""

        locked: list[type] = []
        data = bytearray(1)
        ptr = ffi.from_buffer("uint8_t[]", data)
        try:
            data.append(0)
        except BufferError:
            locked.append(bytearray)
        data = bytearray(1)
        view = memoryview(data)
        ptr = ffi.from_buffer("uint8_t[]", view)
        try:
            view.release()
        except BufferError:
            try:
                data.append(0)
            except BufferError:
                locked.append(memoryview)
        del ptr
        return tuple(locked)

    if _is_pypy:
        _pypy_locked_types = _find_pypy_locked_types()

    # Declarations already passed to ffi.cdef(), and the lock that
    # protects it when modules are imported from several threads
    _declared: set = set()
    _declared_lock = threading.Lock()

    def load_lib(name: str, cdecl: str) -> Any:
        """Load a shared library and return a handle to it.

        @name,  either an absolute path or the name of a library
                in the system search path.

        @cdecl, the C function declarations.
        """

        if hasattr(ffi, "RTLD_DEEPBIND") and not os.getenv("PYCRYPTODOME_DISABLE_DEEPBIND"):
            lib = ffi.dlopen(name, ffi.RTLD_DEEPBIND)
        else:
            lib = ffi.dlopen(name)
        # Several libraries can export the same functions (for instance,
        # a portable and an optimized build of the same code), but
        # cffi rejects a second declaration of a function.
        with _declared_lock:
            if cdecl not in _declared:
                ffi.cdef(cdecl)
                _declared.add(cdecl)
        return lib

    def c_ulong(x: int) -> Any:
        """Convert a Python integer to unsigned long"""
        return x

    c_ulonglong = c_ulong
    c_uint = c_ulong
    c_ubyte = c_ulong

    def c_size_t(x: int) -> Any:
        """Convert a Python integer to size_t"""
        return x

    def create_string_buffer(init_or_size: Union[bytes, int], size: Optional[int] = None) -> Any:
        """Allocate the given amount of bytes (initially set to 0)"""

        if isinstance(init_or_size, bytes):
            size = max(len(init_or_size) + 1, size or 0)
            result = ffi.new("uint8_t[]", size)
            result[:] = init_or_size
        else:
            if size:
                raise ValueError("Size must be specified once only")
            result = ffi.new("uint8_t[]", init_or_size)
        return result

    def get_c_string(c_string: Any) -> bytes:
        """Convert a C string into a Python byte sequence"""
        return ffi.string(c_string)

    def get_raw_buffer(buf: Any) -> bytes:
        """Convert a C buffer into a Python byte sequence"""
        return ffi.buffer(buf)[:]

    def c_uint8_ptr(data: Union[bytes, memoryview, bytearray]) -> Any:
        """Pass data to C code, which only reads it"""
        if isinstance(data, _buffer_type):
            if _is_pypy and _must_copy(data):
                return bytes(data)
            # The returned object holds the buffer of data, which cannot
            # be resized or freed (e.g. by another thread, while the GIL
            # is released during a C call) for as long as it is alive.
            return ffi.from_buffer("uint8_t[]", data)
        elif isinstance(data, (bytes, _Array)):
            return data
        else:
            raise TypeError("Object type %s cannot be passed to C code" % type(data))

    def _c_uint8_ptr_from_address(address: int) -> Any:
        return ffi.cast("uint8_t *", address)

    class VoidPointer_cffi(_VoidPointer):
        """Model a newly allocated pointer to void"""

        def __init__(self):
            self._pp = ffi.new("void *[1]")

        def get(self):
            return self._pp[0]

        def address_of(self):
            return self._pp

    def VoidPointer() -> _VoidPointer:
        return VoidPointer_cffi()

    backend: str = "cffi"

except ImportError:
    import ctypes
    from ctypes import (  # type: ignore[assignment]
        CDLL,
        byref,
        c_size_t,
        c_uint,
        c_ulong,
        c_ulonglong,
        c_void_p,
        create_string_buffer,
    )
    from ctypes import Array as _Array  # type: ignore[assignment]
    from ctypes.util import find_library

    null_pointer = None
    cached_architecture: List[str] = []

    def c_ubyte(c: int) -> Any:  # type: ignore[misc]
        if not (0 <= c < 256):
            raise OverflowError()
        return ctypes.c_ubyte(c)

    def load_lib(name: str, cdecl: str) -> Any:
        if not cached_architecture:
            # platform.architecture() creates a subprocess, so caching the
            # result makes successive imports faster.
            import platform

            cached_architecture[:] = platform.architecture()
        _bits, linkage = cached_architecture
        if "." not in name and not linkage.startswith("Win"):
            full_name = find_library(name)
            if full_name is None:
                raise OSError("Cannot load library '%s'" % name)
            name = full_name
        return CDLL(name)

    def get_c_string(c_string: Any) -> bytes:
        return c_string.value

    def get_raw_buffer(buf: Any) -> bytes:
        return buf.raw

    # ---- Get raw pointer ---

    _c_ssize_t = ctypes.c_ssize_t

    _PyBUF_SIMPLE = 0
    _PyObject_GetBuffer = ctypes.pythonapi.PyObject_GetBuffer
    _PyBuffer_Release = ctypes.pythonapi.PyBuffer_Release
    _py_object = ctypes.py_object
    _c_ssize_p = ctypes.POINTER(_c_ssize_t)

    # See Include/object.h for CPython
    # and https://github.com/pallets/click/blob/master/src/click/_winconsole.py
    class _Py_buffer(ctypes.Structure):
        _fields_ = [
            ("buf", c_void_p),
            ("obj", ctypes.py_object),
            ("len", _c_ssize_t),
            ("itemsize", _c_ssize_t),
            ("readonly", ctypes.c_int),
            ("ndim", ctypes.c_int),
            ("format", ctypes.c_char_p),
            ("shape", _c_ssize_p),
            ("strides", _c_ssize_p),
            ("suboffsets", _c_ssize_p),
            ("internal", c_void_p),
        ]

    def c_uint8_ptr(data: Union[bytes, memoryview, bytearray]) -> Any:
        if isinstance(data, (bytes, _Array)):
            return data
        elif isinstance(data, bytearray):
            # Fast path: the array holds the buffer of data until it is
            # garbage collected, so data cannot be resized or freed
            # (e.g. by another thread, while the GIL is released during
            # a C call).
            # The memoryview locks the buffer and reads its length at once:
            # with len(data) first, another thread could shrink data
            # before from_buffer() locks it.
            view = memoryview(data)
            return (ctypes.c_ubyte * view.nbytes).from_buffer(view)
        elif isinstance(data, _buffer_type):
            # memoryview objects can be read-only, which from_buffer()
            # does not accept
            obj = _py_object(data)
            buf = _Py_buffer()
            _PyObject_GetBuffer(obj, byref(buf), _PyBUF_SIMPLE)
            try:
                buffer_type = ctypes.c_ubyte * buf.len
                result = buffer_type.from_address(buf.buf)
                # Hold the buffer of data until the returned array is
                # garbage collected: until then, data cannot be resized
                # or freed (e.g. by another thread, while the GIL is
                # released during a C call).
                weakref.finalize(result, _PyBuffer_Release, byref(buf))
            except BaseException:
                _PyBuffer_Release(byref(buf))
                raise
            return result
        else:
            raise TypeError("Object type %s cannot be passed to C code" % type(data))

    def _c_uint8_ptr_from_address(address: int) -> Any:
        return c_void_p(address)

    # ---

    class VoidPointer_ctypes(_VoidPointer):
        """Model a newly allocated pointer to void"""

        def __init__(self):
            self._p = c_void_p()

        def get(self):
            return self._p

        def address_of(self):
            return byref(self._p)

    def VoidPointer() -> _VoidPointer:
        return VoidPointer_ctypes()

    backend = "ctypes"


# Only on CPython, C code can write the output directly into a new bytes
# object, which is then returned without copying it. This is what C extensions
# do with PyBytes_FromStringAndSize(NULL, size): the content is undefined,
# and it must be filled in before anything else gets the object.
# Private prototypes, so that the ones in ctypes.pythonapi are not changed.
_PyBytes_FromStringAndSize: Any = None
_PyBytes_AsString: Any = None
if sys.implementation.name == "cpython":
    try:
        import ctypes as _ctypes

        _PyBytes_FromStringAndSize = _ctypes.PYFUNCTYPE(
            _ctypes.py_object, _ctypes.c_void_p, _ctypes.c_ssize_t
        )(("PyBytes_FromStringAndSize", _ctypes.pythonapi))
        _PyBytes_AsString = _ctypes.PYFUNCTYPE(_ctypes.c_void_p, _ctypes.py_object)(
            ("PyBytes_AsString", _ctypes.pythonapi)
        )
    except (ImportError, AttributeError):
        _PyBytes_FromStringAndSize = None

# For shorter outputs, the usual copy is cheap
_MIN_BYTES_OUTPUT = 64 * 1024


def create_bytes_output(size: int) -> Optional[Tuple[bytes, Any]]:
    """Allocate a new bytes object of the given size, for C code to write
    the output of a function into, so that it does not need to be copied.

    Return the object and a pointer to its content (which is undefined),
    or None if it is not possible (or not worth it): then, use
    create_string_buffer() and get_raw_buffer() instead.

    Nothing else can get the object (or a reference to it) until the
    C code has completely written it; the caller must hold the object
    for as long as the pointer is in use.
    """

    # The empty bytes object is a shared singleton
    if _PyBytes_FromStringAndSize is None or size < max(_MIN_BYTES_OUTPUT, 1):
        return None
    obj = _PyBytes_FromStringAndSize(None, size)
    address = _PyBytes_AsString(obj)
    return obj, _c_uint8_ptr_from_address(address)


def c_uint8_ptr_len(data: Union[bytes, memoryview, bytearray]) -> Tuple[Any, int]:
    """Like c_uint8_ptr(), but also return the length of the memory that
    C code gets. Pass C code that length, never len(data): another thread
    could resize data in the meantime, but not the memory that C code gets,
    for as long as the returned pointer is in use."""

    ptr = c_uint8_ptr(data)
    return ptr, len(ptr)


class c_uint8_ptr_out:
    """Pass a buffer to C code that writes into it::

        with c_uint8_ptr_out(buf) as ptr:
            lib.function(..., ptr, ...)

    Usually, ptr is just c_uint8_ptr(buf). If the C code must not get the
    memory of buf (see _must_copy), it gets a private copy instead, which is
    copied back into buf when the C function returns (without an exception).
    """

    def __init__(self, data: Any) -> None:
        self._data = data
        self._copy: Any = None

    def __enter__(self) -> Any:
        if _is_pypy and isinstance(self._data, _buffer_type) and _must_copy(self._data):
            self._copy = create_string_buffer(len(self._data))
            self._copy[0 : len(self._data)] = bytes(self._data)
            return self._copy
        return c_uint8_ptr(self._data)

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._copy is not None and exc_type is None:
            self._data[:] = get_raw_buffer(self._copy)


class SmartPointer:
    """Class to hold a non-managed piece of memory"""

    def __init__(self, raw_pointer: Any, destructor: Any) -> None:
        self._raw_pointer = raw_pointer
        self._destructor = destructor

    def get(self) -> Any:
        return self._raw_pointer

    def release(self) -> Any:
        rp, self._raw_pointer = self._raw_pointer, None
        return rp

    def __del__(self):
        try:
            if self._raw_pointer is not None:
                self._destructor(self._raw_pointer)
                self._raw_pointer = None
        except AttributeError:
            pass


def load_pycryptodome_raw_lib(name: str, cdecl: str) -> Any:
    """Load a shared library and return a handle to it.

    @name,  the name of the library expressed as a PyCryptodome module,
            for instance Crypto.Cipher._raw_cbc.

    @cdecl, the C function declarations.
    """

    split = name.split(".")
    dir_comps, basename = split[:-1], split[-1]
    attempts = []
    for ext in extension_suffixes:
        try:
            filename = basename + ext
            full_name = pycryptodome_filename(dir_comps, filename)
            if not os.path.isfile(full_name):
                attempts.append("Not found '%s'" % filename)
                continue
            return load_lib(full_name, cdecl)
        except OSError as exp:
            attempts.append("Cannot load '%s': %s" % (filename, str(exp)))
    raise OSError("Cannot load native module '%s': %s" % (name, ", ".join(attempts)))


def is_buffer(x: Any) -> bool:
    """Return True if object x supports the buffer interface"""
    return isinstance(x, (bytes, bytearray, memoryview))


def is_writeable_buffer(x: Any) -> bool:
    return isinstance(x, bytearray) or (isinstance(x, memoryview) and not x.readonly)
