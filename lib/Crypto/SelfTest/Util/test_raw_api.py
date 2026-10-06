# ===================================================================
#
# Copyright (c) 2026, Legrandin <helderijs@gmail.com>
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

"""Self-test suite for Crypto.Util._raw_api"""

import _thread
import gc
import sys
import threading

import pytest

from Crypto.Hash import SHA3_256, keccak
from Crypto.Util import _raw_api
from Crypto.Util.strxor import strxor


class TestLoadLib:
    def test_same_declarations_twice(self):
        # The second load must not declare the functions again
        lib1 = _raw_api.load_pycryptodome_raw_lib("Crypto.Hash._keccak", keccak._keccak_cdecl)
        lib2 = _raw_api.load_pycryptodome_raw_lib("Crypto.Hash._keccak", keccak._keccak_cdecl)
        assert lib1 is not None and lib2 is not None

    @pytest.mark.skipif(_raw_api.backend != "cffi", reason="Only cffi keeps track of declarations")
    def test_same_declarations_from_threads(self):
        """Several threads load libraries with the same, new declarations.
        Without a lock, two of them may both pass them to ffi.cdef(),
        and the second call fails."""

        def worker(barrier, cdecl, errors):
            barrier.wait()
            try:
                _raw_api.load_pycryptodome_raw_lib("Crypto.Hash._keccak", cdecl)
            except Exception as e:
                errors.append(e)

        n_threads = 8
        old_interval = sys.getswitchinterval()
        # Switch threads as often as possible, to make the race likely
        sys.setswitchinterval(1e-6)
        try:
            for trial in range(30):
                # Declarations seen for the first time (the functions are never called)
                cdecl = "".join("int not_called_%d_%d(void);" % (trial, i) for i in range(50))
                barrier = threading.Barrier(n_threads)
                errors = []
                threads = [
                    threading.Thread(target=worker, args=(barrier, cdecl, errors)) for _ in range(n_threads)
                ]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                assert errors == []
        finally:
            sys.setswitchinterval(old_interval)


def _not_locked(buffer_type):
    """Skip a test if this interpreter cannot lock buffers of that type
    while C code uses them (PyPy 7.3: none, PyPy 8.0: only bytearray)"""

    locked = not _raw_api._is_pypy or buffer_type in _raw_api._pypy_locked_types
    return pytest.mark.skipif(not locked, reason="This PyPy cannot lock a %s" % buffer_type.__name__)


class TestUint8Ptr:
    """While the C code runs, the GIL is released: another thread must not
    be able to resize or free a buffer that the C code is using.
    So, c_uint8_ptr() must hold the buffer for as long as its result lives."""

    @_not_locked(bytearray)
    def test_bytearray_held(self):
        data = bytearray(b"abc")
        ptr = _raw_api.c_uint8_ptr(data)
        with pytest.raises(BufferError):
            data.extend(b"d")
        del ptr
        gc.collect()
        data.extend(b"d")

    @_not_locked(memoryview)
    @pytest.mark.parametrize("data", [bytearray(b"abc"), b"abc"], ids=["writable", "read-only"])
    def test_memoryview_held(self, data):
        mv = memoryview(data)
        ptr = _raw_api.c_uint8_ptr(mv)
        with pytest.raises(BufferError):
            mv.release()
        del ptr
        gc.collect()
        mv.release()

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            bytearray(),
            b"abc",
            bytearray(b"abc"),
            memoryview(b"xabcx")[1:4],
            memoryview(bytearray(b"abc")),
        ],
        ids=["bytes0", "bytearray0", "bytes", "bytearray", "memoryview-ro", "memoryview-rw"],
    )
    def test_content(self, data):
        assert SHA3_256.new(data).digest() == SHA3_256.new(bytes(data)).digest()

    @_not_locked(bytearray)
    def test_resize_from_other_thread(self):
        """Resize a bytearray while another thread hashes it in C."""

        data = bytearray(32 << 20)
        digest_long = SHA3_256.new(bytes(data)).digest()
        digest_short = SHA3_256.new(bytes(16)).digest()
        started = threading.Event()
        result = []

        def hasher():
            started.set()
            result.append(SHA3_256.new(data).digest())

        t = threading.Thread(target=hasher)
        t.start()
        started.wait()
        try:
            # Most likely, the C code is running now. Without the fix,
            # this would free the memory it reads (crash or wrong digest).
            del data[16:]
            resized = True
        except BufferError:
            resized = False
        t.join()

        if resized:
            # Only possible before or after the C code ran
            assert result[0] in (digest_long, digest_short)
        else:
            assert result == [digest_long]


class _OtherThread:
    """A second thread, alive for the duration of the with block"""

    def __enter__(self):
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._stop.wait)
        self._thread.start()

    def __exit__(self, *args):
        self._stop.set()
        self._thread.join()


@pytest.mark.skipif(_raw_api.backend != "cffi", reason="PyPy always uses cffi")
class TestPyPyCopies:
    """On PyPy, C code gets a private copy of the buffers that PyPy cannot
    lock, but only if another thread exists (see _raw_api._must_copy).
    On CPython, these tests pretend to be on a PyPy that cannot lock anything."""

    @pytest.fixture(autouse=True)
    def pypy_without_locks(self, monkeypatch):
        if not _raw_api._is_pypy:
            monkeypatch.setattr(_raw_api, "_is_pypy", True)
            monkeypatch.setattr(_raw_api, "_pypy_locked_types", ())

    @pytest.mark.parametrize(
        "data", [bytearray(b"abc"), memoryview(bytearray(b"abc"))], ids=["bytearray", "memoryview"]
    )
    def test_input(self, data):
        locked = isinstance(data, _raw_api._pypy_locked_types)
        # One thread: no copy (unless a thread from another test is still alive)
        if _thread._count() == 0:
            assert not isinstance(_raw_api.c_uint8_ptr(data), bytes)
        # Another thread: a private copy, unless this PyPy can lock data
        with _OtherThread():
            ptr = _raw_api.c_uint8_ptr(data)
            assert isinstance(ptr, bytes) != locked
            if isinstance(ptr, bytes):
                assert ptr == b"abc"

    @pytest.mark.parametrize("threads", [1, 2], ids=["one thread", "two threads"])
    def test_output(self, threads):
        # A C function writes into the buffer (strxor), with or without a copy
        out = bytearray(3)
        if threads == 2:
            with _OtherThread():
                strxor(b"abc", b"\x01\x01\x01", output=out)
        else:
            strxor(b"abc", b"\x01\x01\x01", output=out)
        assert out == b"`cb"

    def test_bytes_never_copied(self):
        data = b"abc"
        with _OtherThread():
            assert _raw_api.c_uint8_ptr(data) is data


@pytest.mark.skipif(not _raw_api._is_pypy, reason="PyPy only")
def test_pypy_locked_types():
    """The probe matches what this PyPy really does"""
    data = bytearray(1)
    ptr = _raw_api.ffi.from_buffer("uint8_t[]", data)
    try:
        data.append(0)
        resizable = True
    except BufferError:
        resizable = False
    del ptr
    assert (bytearray in _raw_api._pypy_locked_types) == (not resizable)
