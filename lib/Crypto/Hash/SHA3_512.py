#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================


from __future__ import annotations

from typing import Optional, Union

from Crypto.Hash.keccak import _raw_keccak_lib
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_ubyte,
    c_uint8_ptr,
    create_string_buffer,
    get_raw_buffer,
)

Buffer = Union[bytes, bytearray, memoryview]


class SHA3_512_Hash:
    """A SHA3-512 hash object.
    Do not instantiate directly.
    Use the :func:`new` function.

    :ivar oid: ASN.1 Object ID
    :vartype oid: string

    :ivar digest_size: the size in bytes of the resulting hash
    :vartype digest_size: integer
    """

    # The size of the resulting hash in bytes.
    digest_size: int = 64

    # ASN.1 Object ID
    oid: str = "2.16.840.1.101.3.4.2.10"

    # Input block size for HMAC
    block_size: int = 72

    def __init__(self, data: Optional[Buffer], update_after_digest: bool) -> None:
        self._update_after_digest = update_after_digest
        self._digest_done = False
        self._padding = 0x06

        state = VoidPointer()
        result = _raw_keccak_lib.keccak_init(state.address_of(), c_size_t(self.digest_size * 2), c_ubyte(24))
        if result:
            raise ValueError("Error %d while instantiating SHA-3/512" % result)
        self._state = SmartPointer(state.get(), _raw_keccak_lib.keccak_destroy)
        if data:
            self.update(data)

    def update(self, data: Buffer) -> SHA3_512_Hash:
        """Continue hashing of a message by consuming the next chunk of data.

        Args:
            data (byte string/byte array/memoryview): The next chunk of the message being hashed.
        """

        if self._digest_done and not self._update_after_digest:
            raise TypeError("You can only call 'digest' or 'hexdigest' on this object")

        result = _raw_keccak_lib.keccak_absorb(self._state.get(), c_uint8_ptr(data), c_size_t(len(data)))
        if result:
            raise ValueError("Error %d while updating SHA-3/512" % result)
        return self

    def digest(self) -> bytes:
        """Return the **binary** (non-printable) digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Binary form.
        :rtype: byte string
        """

        self._digest_done = True

        bfr = create_string_buffer(self.digest_size)
        result = _raw_keccak_lib.keccak_digest(
            self._state.get(), bfr, c_size_t(self.digest_size), c_ubyte(self._padding)
        )
        if result:
            raise ValueError("Error %d while instantiating SHA-3/512" % result)

        self._digest_value = get_raw_buffer(bfr)
        return self._digest_value

    def hexdigest(self) -> str:
        """Return the **printable** digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Hexadecimal encoded.
        :rtype: string
        """

        return "".join(["%02x" % x for x in self.digest()])

    def copy(self) -> SHA3_512_Hash:
        """Return a copy ("clone") of the hash object.

        The copy will have the same internal state as the original hash
        object.
        This can be used to efficiently compute the digests of strings that
        share a common initial substring.

        :return: A hash object of the same type
        """

        clone = self.new()
        result = _raw_keccak_lib.keccak_copy(self._state.get(), clone._state.get())
        if result:
            raise ValueError("Error %d while copying SHA3-512" % result)
        return clone

    def new(self, data: Optional[Buffer] = None) -> SHA3_512_Hash:
        """Create a fresh SHA3-521 hash object."""

        return type(self)(data, self._update_after_digest)


def new(data: Optional[Buffer] = None, *, update_after_digest: bool = False) -> SHA3_512_Hash:
    """Create a new hash object.

    Args:
        data (byte string/byte array/memoryview):
            The very first chunk of the message to hash.
            It is equivalent to an early call to :meth:`update`.
        update_after_digest (boolean):
            Whether :meth:`digest` can be followed by another :meth:`update`
            (default: ``False``).

    :Return: A :class:`SHA3_512_Hash` hash object
    """

    return SHA3_512_Hash(data, update_after_digest)


# The size of the resulting hash in bytes.
digest_size: int = SHA3_512_Hash.digest_size

# Input block size for HMAC
block_size: int = 72
