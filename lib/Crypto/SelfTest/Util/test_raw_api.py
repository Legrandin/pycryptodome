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

import gc
import sys
import threading

import pytest

from Crypto.Hash import SHA3_256, keccak
from Crypto.Util import _raw_api


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


# PyPy cannot lock a buffer: a bytearray can always be resized, and a
# memoryview released, even while a C function uses their memory
skip_on_pypy = pytest.mark.skipif(
    "__pypy__" in sys.builtin_module_names, reason="PyPy cannot prevent a buffer from being resized"
)


class TestUint8Ptr:
    """While the C code runs, the GIL is released: another thread must not
    be able to resize or free a buffer that the C code is using.
    So, c_uint8_ptr() must hold the buffer for as long as its result lives."""

    @skip_on_pypy
    def test_bytearray_held(self):
        data = bytearray(b"abc")
        ptr = _raw_api.c_uint8_ptr(data)
        with pytest.raises(BufferError):
            data.extend(b"d")
        del ptr
        gc.collect()
        data.extend(b"d")

    @skip_on_pypy
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

    @skip_on_pypy
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
