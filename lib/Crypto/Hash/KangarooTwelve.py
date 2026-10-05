# ===================================================================
#
# Copyright (c) 2021, Legrandin <helderijs@gmail.com>
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

import os
import threading
from typing import Optional, Union

from Crypto.Util._raw_api import (
    c_size_t,
    c_uint8_ptr,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)
from Crypto.Util.number import long_to_bytes

from . import TurboSHAKE128
from .keccak import _load_avx2_bmi2_lib

Buffer = Union[bytes, bytearray, memoryview]

_k12_cdecl = """
                        int k12_leaves(const uint8_t *in,
                                       size_t n_leaves,
                                       uint8_t *cvs);
                        int k12_oneshot(const uint8_t *in,
                                        size_t in_len,
                                        const uint8_t *custom,
                                        size_t custom_len,
                                        uint8_t *out,
                                        size_t out_len);
                        """

_raw_k12_portable_lib = load_pycryptodome_raw_lib("Crypto.Hash._k12", _k12_cdecl)


# It also hashes 4 leaves at a time with AVX2
_raw_k12_avx2_lib = _load_avx2_bmi2_lib(_k12_cdecl)

# The implementation in use (the tests can replace it)
if _raw_k12_avx2_lib is not None:
    _raw_k12_lib = _raw_k12_avx2_lib
else:
    _raw_k12_lib = _raw_k12_portable_lib


def _length_encode(x):
    if x == 0:
        return b"\x00"

    S = long_to_bytes(x)
    return S + bytes([len(S)])


def _hash_leaves(leaves: memoryview, cvs: memoryview) -> None:
    """Compute the chaining values of complete 8192-byte leaves.

    The C function does not use any shared state, so different ranges
    of leaves can be processed concurrently, each one into its own
    slice of a common CV buffer.

    Args:
        leaves (memoryview): ``n`` leaves, ``8192 * n`` bytes
        cvs (memoryview): writeable output buffer, ``32 * n`` bytes
    """

    n_leaves = len(leaves) // 8192
    assert len(leaves) == 8192 * n_leaves
    assert len(cvs) == 32 * n_leaves
    if n_leaves == 0:
        return

    result = _raw_k12_lib.k12_leaves(c_uint8_ptr(leaves), c_size_t(n_leaves), c_uint8_ptr(cvs))
    if result:
        raise ValueError("Error %d while hashing K12 leaves" % result)


# Minimum amount of whole leaves (256 KiB) that each thread must hash:
# with less, starting the thread costs more than what it saves.
_MIN_LEAVES_PER_THREAD = 32


def _available_cores():
    """Return the number of CPU cores this process can run on."""

    # Python 3.13+: it takes into account CPU affinity and -X cpu_count
    if hasattr(os, "process_cpu_count"):
        count = os.process_cpu_count()
    elif hasattr(os, "sched_getaffinity"):
        count = len(os.sched_getaffinity(0))
    elif hasattr(os, "cpu_count"):
        count = os.cpu_count()
    else:
        import multiprocessing

        try:
            count = multiprocessing.cpu_count()
        except NotImplementedError:
            count = None
    return count or 1


def _hash_leaves_threaded(leaves: memoryview, cvs: memoryview, threads: int) -> None:
    """Like :func:`_hash_leaves`, but split the leaves into ``threads``
    contiguous ranges, which are processed in parallel.
    Fewer threads are used if a range would be shorter than
    ``_MIN_LEAVES_PER_THREAD`` leaves.
    The calling thread processes the first range.
    """

    n_leaves = len(leaves) // 8192
    threads = min(threads, n_leaves // _MIN_LEAVES_PER_THREAD)
    if threads <= 1:
        _hash_leaves(leaves, cvs)
        return

    errors = []

    def worker(start, end):
        try:
            _hash_leaves(leaves[8192 * start : 8192 * end], cvs[32 * start : 32 * end])
        except Exception as e:
            errors.append(e)

    # Ranges differ by at most one leaf
    bounds = [n_leaves * i // threads for i in range(threads + 1)]

    workers = []
    for i in range(1, threads):
        t = threading.Thread(target=worker, args=(bounds[i], bounds[i + 1]))
        t.daemon = True
        t.start()
        workers.append(t)

    worker(bounds[0], bounds[1])

    for t in workers:
        t.join()

    if errors:
        raise errors[0]


# Possible states for a KangarooTwelve instance, which depend on the amount of data processed so far.
SHORT_MSG = 1  # Still within the first 8192 bytes, but it is not certain we will exceed them.
LONG_MSG_S0 = 2  # Still within the first 8192 bytes, and it is certain we will exceed them.
LONG_MSG_SX = 3  # Beyond the first 8192 bytes.
SQUEEZING = 4  # No more data to process.


class K12_XOF:
    """A KangarooTwelve hash object.
    Do not instantiate directly.
    Use the :func:`new` function.
    """

    def __init__(self, data: Optional[Buffer], custom: Optional[bytes], threads: int = 1) -> None:

        if custom is None:
            custom = b""

        if not isinstance(threads, int) or isinstance(threads, bool):
            raise TypeError("'threads' must be an integer")
        if threads < 0:
            raise ValueError("'threads' must be a non-negative integer")
        if threads == 0:
            threads = _available_cores()
        self._threads = threads

        self._custom = custom + _length_encode(len(custom))
        self._state = SHORT_MSG
        self._padding: Optional[int] = None  # Final padding is only decided in read()

        # Internal hash that consumes FinalNode
        # The real domain separation byte will be known before squeezing
        self._hash1 = TurboSHAKE128.new(domain=1)
        self._length1 = 0

        # Internal hash that produces CV_i (reset each time)
        self._hash2: Optional[TurboSHAKE128.TurboSHAKE] = None
        self._length2 = 0

        # Incremented by one for each 8192-byte block
        self._ctr = 0

        if data:
            self.update(data)

    def update(self, data: Buffer) -> K12_XOF:
        """Hash the next piece of data.

        .. note::
            For better performance, submit chunks with a length multiple of 8192 bytes.

        Args:
            data (byte string/byte array/memoryview): The next chunk of the
              message to hash.
        """

        if self._state == SQUEEZING:
            raise TypeError("You cannot call 'update' after the first 'read'")

        if self._state == SHORT_MSG:
            next_length = self._length1 + len(data)

            if next_length + len(self._custom) <= 8192:
                self._length1 = next_length
                self._hash1.update(data)
                return self

            # Switch to tree hashing
            self._state = LONG_MSG_S0

        if self._state == LONG_MSG_S0:
            data_mem = memoryview(data)
            assert self._length1 < 8192
            dtc = min(len(data), 8192 - self._length1)
            self._hash1.update(data_mem[:dtc])
            self._length1 += dtc

            if self._length1 < 8192:
                return self

            # Finish hashing S_0 and start S_1
            assert self._length1 == 8192

            divider = b"\x03" + b"\x00" * 7
            self._hash1.update(divider)
            self._length1 += 8

            self._hash2 = TurboSHAKE128.new(domain=0x0B)
            self._length2 = 0
            self._ctr = 1

            self._state = LONG_MSG_SX
            return self.update(data_mem[dtc:])

        # LONG_MSG_SX
        assert self._state == LONG_MSG_SX
        index = 0
        len_data = len(data)

        # All iteractions could actually run in parallel
        data_mem = memoryview(data)
        assert self._hash2 is not None
        while index < len_data:
            if self._length2 == 0 and len_data - index >= 8192:
                index = self._update_full_leaves(data_mem, index)
                continue

            new_index = min(index + 8192 - self._length2, len_data)
            self._hash2.update(data_mem[index:new_index])
            self._length2 += new_index - index
            index = new_index

            if self._length2 == 8192:
                cv_i = self._hash2.read(32)
                self._hash1.update(cv_i)
                self._length1 += 32
                self._hash2._reset()
                self._length2 = 0
                self._ctr += 1

        return self

    def _update_full_leaves(self, data_mem: memoryview, index: int) -> int:
        """Hash as many complete 8192-byte leaves as available,
        starting at offset ``index`` of ``data_mem``.

        This is the hot path for long messages: all leaves are hashed
        with a single call to the raw Keccak library.

        :return: the offset of the first byte not consumed
        """

        assert self._length2 == 0

        n_leaves = (len(data_mem) - index) // 8192
        end = index + 8192 * n_leaves

        cvs = bytearray(32 * n_leaves)
        if self._threads > 1:
            _hash_leaves_threaded(data_mem[index:end], memoryview(cvs), self._threads)
        else:
            _hash_leaves(data_mem[index:end], memoryview(cvs))
        self._hash1.update(cvs)

        self._length1 += 32 * n_leaves
        self._ctr += n_leaves
        return end

    def read(self, length: int) -> bytes:
        """
        Produce more bytes of the digest.

        .. note::
            You cannot use :meth:`update` anymore after the first call to
            :meth:`read`.

        Args:
            length (integer): the amount of bytes this method must return

        :return: the next piece of XOF output (of the given length)
        :rtype: byte string
        """

        if not isinstance(length, int) or isinstance(length, bool):
            raise TypeError("'length' must be an integer")
        if length < 0:
            raise ValueError("'length' must be a non-negative integer")

        custom_was_consumed = False

        # The message and the customization string together may still
        # exceed 8192 bytes, if update() was never called
        if self._state == SHORT_MSG and self._length1 + len(self._custom) > 8192:
            self._state = LONG_MSG_S0

        if self._state == SHORT_MSG:
            self._hash1.update(self._custom)
            self._padding = 0x07
            self._state = SQUEEZING

        if self._state == LONG_MSG_S0:
            self.update(self._custom)
            custom_was_consumed = True
            assert self._state == LONG_MSG_SX

        if self._state == LONG_MSG_SX:
            if not custom_was_consumed:
                self.update(self._custom)

            # Is there still some leftover data in hash2?
            if self._length2 > 0:
                assert self._hash2 is not None
                cv_i = self._hash2.read(32)
                self._hash1.update(cv_i)
                self._length1 += 32
                self._hash2._reset()
                self._length2 = 0
                self._ctr += 1

            trailer = _length_encode(self._ctr - 1) + b"\xff\xff"
            self._hash1.update(trailer)

            self._padding = 0x06
            self._state = SQUEEZING

        assert self._padding is not None
        self._hash1._domain = self._padding
        return self._hash1.read(length)

    def new(self, data: Optional[Buffer] = None, custom: Optional[bytes] = b"", threads: int = 1) -> K12_XOF:
        return type(self)(data, custom, threads)


def new(data: Optional[Buffer] = None, custom: Optional[bytes] = None, threads: int = 1) -> K12_XOF:
    """Return a fresh instance of a KangarooTwelve object.

    Args:
       data (bytes/bytearray/memoryview):
        Optional.
        The very first chunk of the message to hash.
        It is equivalent to an early call to :meth:`update`.
       custom (bytes):
        Optional.
        A customization byte string.
       threads (integer):
        Optional.
        The maximum number of threads used to hash long messages
        (default: 1, no extra threads).
        Use 0 for as many threads as the CPU cores available
        to this process.
        Each thread hashes at least 256 KiB of a single call to
        :meth:`K12_XOF.update` (or of ``data``): with shorter
        inputs, fewer threads are used, or none at all.
        For best results, do not exceed the number of physical cores.
        The output does not depend on the number of threads.

    :Return: A :class:`K12_XOF` object
    """

    return K12_XOF(data, custom, threads)


def digest(data: Buffer, *, length: int, custom: Optional[bytes] = None) -> bytes:
    """Compute the KangarooTwelve output for a complete message, in one go.

    It returns the same bytes as ``new(data, custom).read(length)``,
    but it is much faster for short messages.

    Args:
       data (bytes/bytearray/memoryview):
        The whole message to hash.
       length (integer):
        Keyword-only. The amount of bytes to return.
       custom (bytes):
        Optional, keyword-only.
        A customization byte string.

    :Return: the output of the XOF, ``length`` bytes long
    :rtype: byte string
    """

    if custom is None:
        custom = b""

    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("'length' must be an integer")
    if length < 0:
        raise ValueError("'length' must be a non-negative integer")

    out = create_string_buffer(length)
    result = _raw_k12_lib.k12_oneshot(
        c_uint8_ptr(data),
        c_size_t(len(data)),
        c_uint8_ptr(custom),
        c_size_t(len(custom)),
        out,
        c_size_t(length),
    )
    if result:
        raise ValueError("Error %d while computing KangarooTwelve" % result)
    return get_raw_buffer(out)
