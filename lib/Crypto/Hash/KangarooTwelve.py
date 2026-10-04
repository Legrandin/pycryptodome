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

from Crypto.Util.number import long_to_bytes
from Crypto.Util.py3compat import bchr
from Crypto.Util._raw_api import create_string_buffer, c_size_t, c_ubyte

from . import TurboSHAKE128
from .keccak import _raw_keccak_lib

def _length_encode(x):
    if x == 0:
        return b'\x00'

    S = long_to_bytes(x)
    return S + bchr(len(S))


# Possible states for a KangarooTwelve instance, which depend on the amount of data processed so far.
SHORT_MSG = 1       # Still within the first 8192 bytes, but it is not certain we will exceed them.
LONG_MSG_S0 = 2     # Still within the first 8192 bytes, and it is certain we will exceed them.
LONG_MSG_SX = 3     # Beyond the first 8192 bytes.
SQUEEZING = 4       # No more data to process.


class K12_XOF(object):
    """A KangarooTwelve hash object.
    Do not instantiate directly.
    Use the :func:`new` function.
    """

    def __init__(self, data, custom):

        if custom == None:
            custom = b''

        self._custom = custom + _length_encode(len(custom))
        self._state = SHORT_MSG
        self._padding = None        # Final padding is only decided in read()

        # Internal hash that consumes FinalNode
        # The real domain separation byte will be known before squeezing
        self._hash1 = TurboSHAKE128.new(domain=1)
        self._length1 = 0

        # Internal hash that produces CV_i (reset each time)
        self._hash2 = None
        self._length2 = 0

        # Incremented by one for each 8192-byte block
        self._ctr = 0

        if data:
            self.update(data)

    def update(self, data):
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
            assert(self._length1 < 8192)
            dtc = min(len(data), 8192 - self._length1)
            self._hash1.update(data_mem[:dtc])
            self._length1 += dtc

            if self._length1 < 8192:
                return self

            # Finish hashing S_0 and start S_1
            assert(self._length1 == 8192)

            divider = b'\x03' + b'\x00' * 7
            self._hash1.update(divider)
            self._length1 += 8

            self._hash2 = TurboSHAKE128.new(domain=0x0B)
            self._length2 = 0
            self._ctr = 1

            self._state = LONG_MSG_SX
            return self.update(data_mem[dtc:])

        # LONG_MSG_SX
        assert(self._state == LONG_MSG_SX)
        index = 0
        len_data = len(data)

        # All iteractions could actually run in parallel
        data_mem = memoryview(data)
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

    def _update_full_leaves(self, data_mem, index):
        """Hash as many complete 8192-byte leaves as available,
        starting at offset ``index`` of ``data_mem``.

        This is the hot path for long messages: it calls the raw Keccak
        library directly to minimize the per-leaf overhead.

        :return: the offset of the first byte not consumed
        """

        assert self._length2 == 0

        absorb = _raw_keccak_lib.keccak_absorb
        squeeze = _raw_keccak_lib.keccak_squeeze
        reset = _raw_keccak_lib.keccak_reset

        state1 = self._hash1._state.get()
        state2 = self._hash2._state.get()
        leaf_len = c_size_t(8192)
        cv_len = c_size_t(32)
        domain2 = c_ubyte(self._hash2._domain)
        cv_i = create_string_buffer(32)

        n_leaves = (len(data_mem) - index) // 8192
        for _ in range(n_leaves):
            leaf = data_mem[index:index + 8192].tobytes()
            index += 8192

            result = absorb(state2, leaf, leaf_len)
            if result:
                raise ValueError("Error %d while hashing K12 leaf" % result)
            result = squeeze(state2, cv_i, cv_len, domain2)
            if result:
                raise ValueError("Error %d while hashing K12 leaf" % result)
            result = reset(state2)
            if result:
                raise ValueError("Error %d while hashing K12 leaf" % result)
            result = absorb(state1, cv_i, cv_len)
            if result:
                raise ValueError("Error %d while hashing K12 leaf" % result)

        self._length1 += 32 * n_leaves
        self._ctr += n_leaves
        return index

    def read(self, length):
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

        custom_was_consumed = False

        # The message and the customization string together may still
        # exceed 8192 bytes, if update() was never called
        if self._state == SHORT_MSG and \
                self._length1 + len(self._custom) > 8192:
            self._state = LONG_MSG_S0

        if self._state == SHORT_MSG:
            self._hash1.update(self._custom)
            self._padding = 0x07
            self._state = SQUEEZING

        if self._state == LONG_MSG_S0:
            self.update(self._custom)
            custom_was_consumed = True
            assert(self._state == LONG_MSG_SX)

        if self._state == LONG_MSG_SX:
            if not custom_was_consumed:
                self.update(self._custom)

            # Is there still some leftover data in hash2?
            if self._length2 > 0:
                cv_i = self._hash2.read(32)
                self._hash1.update(cv_i)
                self._length1 += 32
                self._hash2._reset()
                self._length2 = 0
                self._ctr += 1

            trailer = _length_encode(self._ctr - 1) + b'\xFF\xFF'
            self._hash1.update(trailer)

            self._padding = 0x06
            self._state = SQUEEZING

        self._hash1._domain = self._padding
        return self._hash1.read(length)

    def new(self, data=None, custom=b''):
        return type(self)(data, custom)


def new(data=None, custom=None):
    """Return a fresh instance of a KangarooTwelve object.

    Args:
       data (bytes/bytearray/memoryview):
        Optional.
        The very first chunk of the message to hash.
        It is equivalent to an early call to :meth:`update`.
       custom (bytes):
        Optional.
        A customization byte string.

    :Return: A :class:`K12_XOF` object
    """

    return K12_XOF(data, custom)
