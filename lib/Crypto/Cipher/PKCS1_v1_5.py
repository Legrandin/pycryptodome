#
#  Cipher/PKCS1-v1_5.py : PKCS#1 v1.5
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

from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar, Union, overload

__all__ = ["new", "PKCS115_Cipher"]

from Crypto import Random
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes

from ._pkcs1_oaep_decode import pkcs1_decode, pkcs1_decode_implicit

if TYPE_CHECKING:
    from Crypto.PublicKey.RSA import RsaKey

Buffer = Union[bytes, bytearray, memoryview]

T = TypeVar("T")


class _NoSentinel:
    """Default value of the sentinel parameter of decrypt()"""

    def __repr__(self) -> str:
        return "<no sentinel>"


_NO_SENTINEL: Any = _NoSentinel()


def _irprf(kdk: bytes, label: bytes, length: int) -> bytes:
    """The Implicit Rejection Pseudo-Random Function (IRPRF),
    section 7.1 of draft-irtf-cfrg-rsa-guidance."""

    # Step 1 (the bit length must fit into 2 bytes)
    if len(kdk) != 32 or length * 8 > 0xFFFF:
        raise ValueError("Invalid IRPRF parameters")

    # Steps 2-5
    bit_length = (length * 8).to_bytes(2, "big")
    blocks = [
        HMAC.new(kdk, i.to_bytes(2, "big") + label + bit_length, digestmod=SHA256).digest()
        for i in range((length + 31) // 32)
    ]
    return b"".join(blocks)[:length]


class PKCS115_Cipher:
    """This cipher can perform PKCS#1 v1.5 RSA encryption or decryption.
    Do not instantiate directly. Use :func:`Crypto.Cipher.PKCS1_v1_5.new` instead."""

    def __init__(self, key: RsaKey, randfunc: Callable[[int], bytes]) -> None:
        """Initialize this PKCS#1 v1.5 cipher object.

        :Parameters:
         key : an RSA key object
          If a private half is given, both encryption and decryption are possible.
          If a public half is given, only encryption is possible.
         randfunc : callable
          Function that returns random bytes.
        """

        self._key = key
        self._randfunc = randfunc

    def can_encrypt(self) -> bool:
        """Return True if this cipher object can be used for encryption."""
        return self._key.can_encrypt()

    def can_decrypt(self) -> bool:
        """Return True if this cipher object can be used for decryption."""
        return self._key.has_private()

    def encrypt(self, message: Buffer) -> bytes:
        """Produce the PKCS#1 v1.5 encryption of a message.

        This function is named ``RSAES-PKCS1-V1_5-ENCRYPT``, and it is specified in
        `section 7.2.1 of RFC8017
        <https://tools.ietf.org/html/rfc8017#page-28>`_.

        :param message:
            The message to encrypt, also known as plaintext. It can be of
            variable length, but not longer than the RSA modulus (in bytes) minus 11.
        :type message: bytes/bytearray/memoryview

        :Returns: A byte string, the ciphertext in which the message is encrypted.
            It is as long as the RSA modulus (in bytes).

        :Raises ValueError:
            If the RSA key length is not sufficiently long to deal with the given
            message.
        """

        # See 7.2.1 in RFC8017
        k = self._key.size_in_bytes()
        mLen = len(message)

        # Step 1
        if mLen > k - 11:
            raise ValueError("Plaintext is too long.")
        # Step 2a
        ps_bytes: list[bytes] = []
        while len(ps_bytes) != k - mLen - 3:
            new_byte = self._randfunc(1)
            if new_byte[0] == 0x00:
                continue
            ps_bytes.append(new_byte)
        ps = b"".join(ps_bytes)
        # Step 2b
        em = b"\x00\x02" + ps + b"\x00" + bytes(message)
        # Step 3a (OS2IP)
        em_int = bytes_to_long(em)
        # Step 3b (RSAEP)
        m_int = self._key._encrypt(em_int)
        # Step 3c (I2OSP)
        c = long_to_bytes(m_int, k)
        return c

    @overload
    def decrypt(self, ciphertext: Buffer, *, expected_pt_len: Optional[int] = 0) -> bytes: ...

    @overload
    def decrypt(
        self, ciphertext: Buffer, sentinel: T, expected_pt_len: Optional[int] = 0
    ) -> Union[bytes, T]: ...

    def decrypt(
        self, ciphertext: Buffer, sentinel: T = _NO_SENTINEL, expected_pt_len: Optional[int] = 0
    ) -> Union[bytes, T]:
        r"""Decrypt a PKCS#1 v1.5 ciphertext.

        This is the function ``RSAES-PKCS1-V1_5-DECRYPT`` specified in
        `section 7.2.2 of RFC8017
        <https://tools.ietf.org/html/rfc8017#page-29>`_,
        with the *implicit rejection* of
        `section 7.2 of draft-irtf-cfrg-rsa-guidance
        <https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-guidance/>`_:
        when the padding is not correct, the function does **not** fail,
        and it returns instead a pseudo-random message.
        That message only depends on the private key and on the ciphertext
        (the same ciphertext always results in the same message),
        and it cannot be told apart from the message of a ciphertext with
        correct padding by those who do not know the private key.

        Args:
          ciphertext (bytes/bytearray/memoryview):
            The ciphertext that contains the message to recover.
          expected_pt_len (integer):
            The length the plaintext is known to have, or 0 if unknown.
            When it is not 0, a plaintext of a different length is also
            rejected (and the pseudo-random message has this length).
          sentinel (any type):
            The object to return when the padding is not correct.
            If present, the function does not perform implicit rejection.
            Do not pass it, unless the party that submitted the ciphertext
            can never find out (directly or indirectly) that ``sentinel``
            was returned.

        Returns (byte string):
            The original message, or the pseudo-random message
            (or ``sentinel``, if passed) in case the padding is not correct.

        Raises:
          ValueError: if the ciphertext does not have the length of
            the modulus, or if it is not smaller than the modulus.
          TypeError: if the RSA key is not private.

        .. warning::
            PKCS#1 v1.5 decryption is intrinsically vulnerable to
            `Bleichenbacher's`__ attack. **Use PKCS#1 OAEP instead**.

            Implicit rejection hides from the caller if the padding was
            correct. The protocol that uses this function must then also
            treat in the same way messages that are random or that have
            an unexpected length (for instance, they must fail later and
            in the same way as a message that has the expected format but
            the wrong value).

            With a ``sentinel``, the result of the padding check is
            something that the caller can detect, and any difference in the
            behaviour of the application that follows from it is the oracle
            exploited by the attack. This includes subtle differences:
            for instance, a random ``sentinel`` changes at each call,
            whereas the plaintext of a ciphertext with correct padding does not.

            .. __: https://dx.doi.org/10.1007/BFb0055716
        """

        if expected_pt_len is None:
            expected_pt_len = 0

        # See 7.2.2 in RFC8017
        k = self._key.size_in_bytes()

        # Step 1
        if len(ciphertext) != k:
            raise ValueError("Ciphertext with incorrect length (not %d bytes)" % k)

        if sentinel is not _NO_SENTINEL:
            return self._decrypt_sentinel(ciphertext, sentinel, expected_pt_len)

        # Step 2a (O2SIP)
        ct_int = bytes_to_long(ciphertext)

        # Step 2b (RSADP) and Step 2c (I2OSP)
        em = self._key._decrypt_to_bytes(ct_int)

        # Step 3.1 of the draft (KDK)
        d_hash = SHA256.new(self._key._d.to_bytes(k)).digest()
        kdk = HMAC.new(d_hash, ciphertext, digestmod=SHA256).digest()

        # Step 3.2 of the draft (CL and AM)
        cl = _irprf(kdk, b"length", 256)
        am = _irprf(kdk, b"message", k)

        # Steps 3.3, 4 and 5 of the draft (in constant time)
        output = bytearray(k)
        size = pkcs1_decode_implicit(em, am, cl, expected_pt_len, output)
        if size < 0:
            raise ValueError("Incorrect PKCS#1 v1.5 parameters")
        return bytes(output[size:])

    def _decrypt_sentinel(self, ciphertext: Buffer, sentinel: T, expected_pt_len: int) -> Union[bytes, T]:
        """The decryption with a sentinel (no implicit rejection)."""

        k = self._key.size_in_bytes()

        # Step 2a (O2SIP)
        ct_int = bytes_to_long(ciphertext)

        # Step 2b (RSADP) and Step 2c (I2OSP)
        em = self._key._decrypt_to_bytes(ct_int)

        # Step 3 (not constant time when the sentinel is not a byte string)
        output = bytes(bytearray(k))
        if not isinstance(sentinel, (bytes, bytearray, memoryview)) or len(sentinel) > k:
            # A placeholder of k bytes: the number of bytes to skip is 0 only
            # when the padding is not correct (it is at least 11 otherwise)
            size = pkcs1_decode(em, bytes(k), expected_pt_len, output)
            if size < 0:
                raise ValueError("Incorrect PKCS#1 v1.5 parameters")
            if size == 0:
                return sentinel
            return output[size:]

        # Step 3 (somewhat constant time)
        size = pkcs1_decode(em, sentinel, expected_pt_len, output)
        if size < 0:
            raise ValueError("Incorrect PKCS#1 v1.5 parameters")
        return output[size:]


def new(key: RsaKey, randfunc: Optional[Callable[[int], bytes]] = None) -> PKCS115_Cipher:
    """Create a cipher for performing PKCS#1 v1.5 encryption or decryption.

    :param key:
      The key to use to encrypt or decrypt the message. This is a `Crypto.PublicKey.RSA` object.
      Decryption is only possible if *key* is a private RSA key.
    :type key: RSA key object

    :param randfunc:
      Function that return random bytes.
      The default is :func:`Crypto.Random.get_random_bytes`.
    :type randfunc: callable

    :returns: A cipher object `PKCS115_Cipher`.
    """

    if randfunc is None:
        randfunc = Random.get_random_bytes
    return PKCS115_Cipher(key, randfunc)
