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

    def test_shrink_after_len(self):
        """Another thread shrinks a bytearray right after its length is read,
        but before its buffer is held (likely on free-threaded builds)"""

        class ShrinkingBytearray(bytearray):
            def __len__(self):
                length = super().__len__()
                if length > 16:
                    del self[16:]
                return length

        data = ShrinkingBytearray(b"x" * 1024)
        ptr, length = _raw_api.c_uint8_ptr_len(data)
        assert length in (1024, 16)
        assert bytes(ptr) == b"x" * length


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


class _LyingBytearray(bytearray):
    """A bytearray that claims to be 'extra' bytes longer than it is, like
    a bytearray that another thread shrinks right after its length is read"""

    def __init__(self, data, extra):
        super().__init__(data)
        self.extra = extra

    def __len__(self):
        return super().__len__() + self.extra


class TestLengthsFromHeldBuffer:
    """C code must get the length of the buffer it actually uses,
    never one read separately through len()"""

    def test_hash_input(self):
        data = _LyingBytearray(b"abc", 64)
        try:
            digest = SHA3_256.new(data).digest()
        except ValueError:
            return
        assert digest == SHA3_256.new(b"abc").digest()

    def test_cipher_input(self):
        from Crypto.Cipher import AES

        data = _LyingBytearray(16, 64)
        try:
            ct = AES.new(b"k" * 16, AES.MODE_ECB).encrypt(data)
        except ValueError:
            return
        assert ct == AES.new(b"k" * 16, AES.MODE_ECB).encrypt(bytes(16))

    @pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR", "CFB", "OFB"])
    def test_cipher_output(self, mode):
        from Crypto.Cipher import AES

        kwargs = {"ECB": {}, "CTR": {"nonce": bytes(8)}}.get(mode, {"iv": bytes(16)})
        cipher = AES.new(b"k" * 16, getattr(AES, "MODE_" + mode), **kwargs)
        out = _LyingBytearray(0, 32)  # 0 bytes, but len() says 32
        with pytest.raises(ValueError):
            cipher.encrypt(bytes(32), output=out)

    def test_stream_cipher_output(self):
        from Crypto.Cipher import ChaCha20, Salsa20

        for cipher in (
            ChaCha20.new(key=bytes(32), nonce=bytes(8)),
            Salsa20.new(key=bytes(32), nonce=bytes(8)),
        ):
            with pytest.raises(ValueError):
                cipher.encrypt(bytes(64), output=_LyingBytearray(0, 64))

    def test_strxor(self):
        from Crypto.Util.strxor import strxor, strxor_c

        with pytest.raises(ValueError):
            strxor(bytes(64), _LyingBytearray(0, 64))
        with pytest.raises(ValueError):
            strxor(bytes(64), bytes(64), output=_LyingBytearray(0, 64))
        with pytest.raises(ValueError):
            strxor_c(bytes(64), 1, output=_LyingBytearray(0, 64))

    def test_ocb(self):
        from Crypto.Cipher import AES

        cipher = AES.new(b"k" * 16, AES.MODE_OCB, nonce=bytes(15))
        try:
            cipher.update(_LyingBytearray(0, 64))
        except ValueError:
            pass
        cipher = AES.new(b"k" * 16, AES.MODE_OCB, nonce=bytes(15))
        try:
            ct = cipher.encrypt(_LyingBytearray(0, 64))
        except ValueError:
            return
        assert ct == b""
