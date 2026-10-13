#
#  PublicKey/DSA.py : DSA signature primitive
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Callable, Optional, Union

__all__ = ["generate", "construct", "DsaKey", "import_key"]

import binascii
import itertools
import struct

from Crypto import IncorrectPassphraseError, KdfLimitError, PassphraseRequiredError, Random
from Crypto.Hash import SHA256
from Crypto.IO import PEM, PKCS8
from Crypto.Math.Numbers import Integer
from Crypto.Math.Primality import COMPOSITE, PROBABLY_PRIME, test_probable_prime
from Crypto.PublicKey import (
    _create_subject_public_key_info,
    _expand_subject_public_key_info,
    _extract_subject_public_key_info,
)
from Crypto.Util._bytes import tobytes
from Crypto.Util.asn1 import (
    DerInteger,
    DerSequence,
)

if TYPE_CHECKING:
    from Crypto.IO._PBES import ProtParams

RNG = Callable[[int], bytes]
Int = Union[int, Integer]

#   ; The following ASN.1 types are relevant for DSA
#
#   SubjectPublicKeyInfo    ::=     SEQUENCE {
#       algorithm   AlgorithmIdentifier,
#       subjectPublicKey BIT STRING
#   }
#
#   id-dsa ID ::= { iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 1 }
#
#   ; See RFC3279
#   Dss-Parms  ::=  SEQUENCE  {
#       p INTEGER,
#       q INTEGER,
#       g INTEGER
#   }
#
#   DSAPublicKey ::= INTEGER
#
#   DSSPrivatKey_OpenSSL ::= SEQUENCE
#       version INTEGER,
#       p INTEGER,
#       q INTEGER,
#       g INTEGER,
#       y INTEGER,
#       x INTEGER
#   }
#


class DsaKey:
    r"""Class defining an actual DSA key.
    Do not instantiate directly.
    Use :func:`generate`, :func:`construct` or :func:`import_key` instead.

    :ivar p: DSA modulus
    :vartype p: integer

    :ivar q: Order of the subgroup
    :vartype q: integer

    :ivar g: Generator
    :vartype g: integer

    :ivar y: Public key
    :vartype y: integer

    :ivar x: Private key
    :vartype x: integer

    :undocumented: exportKey, publickey
    """

    _keydata = ["y", "g", "p", "q", "x"]

    def __init__(self, key_dict: Mapping[str, Integer]) -> None:
        input_set = set(key_dict.keys())
        public_set = {"y", "g", "p", "q"}
        if not public_set.issubset(input_set):
            raise ValueError("Some DSA components are missing = %s" % str(public_set - input_set))
        extra_set = input_set - public_set
        if extra_set and extra_set != {"x"}:
            raise ValueError("Unknown DSA components = %s" % str(extra_set - {"x"}))
        self._key = dict(key_dict)

    def _sign(self, m, k):
        if not self.has_private():
            raise TypeError("DSA public key cannot be used for signing")
        if not (1 < k < self.q):
            raise ValueError("k is not between 2 and q-1")

        x, q, p, g = (self._key[comp] for comp in ["x", "q", "p", "g"])

        blind_factor = Integer.random_range(min_inclusive=1, max_exclusive=q)
        inv_blind_k = (blind_factor * k).inverse(q)
        blind_x = x * blind_factor

        r = pow(g, k, p) % q  # r = (g**k mod p) mod q
        s = (inv_blind_k * (blind_factor * m + blind_x * r)) % q
        return map(int, (r, s))

    def _verify(self, m, sig):
        r, s = sig
        y, q, p, g = (self._key[comp] for comp in ["y", "q", "p", "g"])
        if not (0 < r < q) or not (0 < s < q):
            return False
        w = Integer(s).inverse(q)
        u1 = (w * m) % q
        u2 = (w * r) % q
        v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
        return v == r

    def has_private(self) -> bool:
        """Whether this is a DSA private key"""

        return "x" in self._key

    def can_encrypt(self) -> bool:  # legacy
        return False

    def can_sign(self) -> bool:  # legacy
        return True

    def public_key(self) -> DsaKey:
        """A matching DSA public key.

        Returns:
            a new :class:`DsaKey` object
        """

        public_components = {k: self._key[k] for k in ("y", "g", "p", "q")}
        return DsaKey(public_components)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DsaKey):
            return False
        # Same components (x is only in private keys)
        return self._key == other._key

    def __getstate__(self) -> None:
        # DSA key is not pickable
        from pickle import PicklingError

        raise PicklingError

    def domain(self) -> tuple[int, int, int]:
        """The DSA domain parameters.

        Returns
            tuple : (p,q,g)
        """

        return (int(self._key["p"]), int(self._key["q"]), int(self._key["g"]))

    def __repr__(self) -> str:
        attrs = []
        for k in self._keydata:
            if k == "p":
                bits = Integer(self.p).size_in_bits()
                attrs.append("p(%d)" % (bits,))
            elif hasattr(self, k):
                attrs.append(k)
        if self.has_private():
            attrs.append("private")
        return "<%s @0x%x %s>" % (self.__class__.__name__, id(self), ",".join(attrs))

    def __getattr__(self, item: str) -> int:
        try:
            return int(self._key[item])
        except KeyError:
            raise AttributeError(item)

    def export_key(
        self,
        format: str = "PEM",
        pkcs8: Optional[bool] = None,
        passphrase: Optional[Union[str, bytes]] = None,
        protection: Optional[str] = None,
        randfunc: Optional[RNG] = None,
        prot_params: Optional[ProtParams] = None,
    ) -> bytes:
        """Export this DSA key.

        Args:
          format (string):
            The encoding for the output:

            - *'PEM'* (default). ASCII as per `RFC1421`_/ `RFC1423`_.
            - *'DER'*. Binary ASN.1 encoding.
            - *'OpenSSH'*. ASCII one-liner as per `RFC4253`_.
              Only suitable for public keys, not for private keys.

          passphrase (string):
            *Private keys only*. The pass phrase to protect the output.

          pkcs8 (boolean):
            *Private keys only*. If ``True`` (default), the key is encoded
            with `PKCS#8`_. If ``False``, it is encoded in the custom
            OpenSSL/OpenSSH container.

          protection (string):
            *Only in combination with a pass phrase*.
            The encryption scheme to use to protect the output.

            If :data:`pkcs8` takes value ``True``, this is the PKCS#8
            algorithm to use for deriving the secret and encrypting
            the private DSA key.
            The default is ``'PBKDF2WithHMAC-SHA256AndAES256-CBC'``.
            For a complete list of algorithms, see
            :ref:`the encryption parameters of PKCS#8<enc_params>`.

            If :data:`pkcs8` is ``False``, the obsolete PEM encryption scheme is
            used, and :data:`protection` is not allowed. It derives the key
            with a single round of MD5, and is therefore easy to brute force:
            use it only with a high-entropy passphrase (like 16 random bytes),
            for compatibility with old software.

            The combination ``format='DER'`` and ``pkcs8=False`` is not allowed
            if a passphrase is present.

          randfunc (callable):
            A function that returns random bytes.
            By default it is :func:`Crypto.Random.get_random_bytes`.

          prot_params (dict):
            *Only with PKCS#8 and a pass phrase*.
            The parameters to use to derive the encryption key
            from the passphrase.
            For all possible values,
            refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.

        Returns:
          byte string : the encoded key

        Raises:
          ValueError : when the format is unknown, when you try to encrypt a private
            key with *DER* format and OpenSSL/OpenSSH, when you pass
            ``protection`` or ``prot_params`` with ``pkcs8=False`` or without
            a passphrase, or when the passphrase is empty.

        .. warning::
            If you don't provide a pass phrase, the private key will be
            exported in the clear!

        .. _RFC1421:    https://www.rfc-editor.org/rfc/rfc1421
        .. _RFC1423:    https://www.rfc-editor.org/rfc/rfc1423
        .. _RFC4253:    https://www.rfc-editor.org/rfc/rfc4253
        .. _`PKCS#8`:   https://www.rfc-editor.org/rfc/rfc5958
        """

        if passphrase is not None:
            passphrase = tobytes(passphrase)

        if randfunc is None:
            randfunc = Random.get_random_bytes

        if format == "OpenSSH":
            tup1 = [self._key[x].to_bytes() for x in ("p", "q", "g", "y")]

            def func(x):
                if x[0] & 0x80:
                    return bytes([0]) + x
                else:
                    return x

            tup2 = [func(x) for x in tup1]
            keyparts = [b"ssh-dss"] + tup2
            keystring = b"".join([struct.pack(">I", len(kp)) + kp for kp in keyparts])
            return b"ssh-dss " + binascii.b2a_base64(keystring)[:-1]

        # DER format is always used, even in case of PEM, which simply
        # encodes it into BASE64.
        params = DerSequence([self.p, self.q, self.g])
        if self.has_private():
            if passphrase is None:
                if protection or prot_params:
                    raise ValueError("'protection' and 'prot_params' require a passphrase")
            elif not passphrase:
                raise ValueError("Empty passphrase")
            if pkcs8 is None:
                pkcs8 = True
            if pkcs8:
                private_key = DerInteger(self.x).encode()
                binary_key = PKCS8.wrap(
                    private_key,
                    oid,
                    passphrase,
                    protection,
                    prot_params=prot_params,
                    key_params=params,
                    randfunc=randfunc,
                )
                if passphrase:
                    key_type = "ENCRYPTED PRIVATE"
                else:
                    key_type = "PRIVATE"
                passphrase = None
            else:
                if protection or prot_params:
                    raise ValueError("'protection' and 'prot_params' are only supported for PKCS#8")
                if format != "PEM" and passphrase:
                    raise ValueError("DSA private key cannot be encrypted")
                ints = [0, self.p, self.q, self.g, self.y, self.x]
                binary_key = DerSequence(ints).encode()
                key_type = "DSA PRIVATE"
        else:
            if pkcs8:
                raise ValueError("PKCS#8 is only meaningful for private keys")

            binary_key = _create_subject_public_key_info(oid, DerInteger(self.y), params)
            key_type = "PUBLIC"

        if format == "DER":
            return binary_key
        if format == "PEM":
            pem_str = PEM.encode(binary_key, key_type + " KEY", passphrase, randfunc)
            return tobytes(pem_str)
        raise ValueError("Unknown key format '%s'. Cannot export the DSA key." % format)

    # Backward-compatibility
    exportKey = export_key
    publickey = public_key

    # Methods defined in PyCrypto that we don't support anymore

    def sign(self, M, K):
        raise NotImplementedError("Use module Crypto.Signature.DSS instead")

    def verify(self, M, signature):
        raise NotImplementedError("Use module Crypto.Signature.DSS instead")

    def encrypt(self, plaintext, K):
        raise NotImplementedError

    def decrypt(self, ciphertext):
        raise NotImplementedError

    def blind(self, M, B):
        raise NotImplementedError

    def unblind(self, M, B):
        raise NotImplementedError

    def size(self):
        raise NotImplementedError


def _generate_domain(L, randfunc):
    """Generate a new set of DSA domain parameters"""

    N = {1024: 160, 2048: 224, 3072: 256}.get(L)
    if N is None:
        raise ValueError("Invalid modulus length (%d)" % L)

    outlen = SHA256.digest_size * 8
    n = (L + outlen - 1) // outlen - 1  # ceil(L/outlen) -1
    b_ = L - 1 - (n * outlen)

    # Generate q (A.1.1.2)
    q = Integer(4)
    upper_bit = 1 << (N - 1)
    while test_probable_prime(q, randfunc) != PROBABLY_PRIME:
        seed = randfunc(64)
        U = Integer.from_bytes(SHA256.new(seed).digest()) & (upper_bit - 1)
        q = U | upper_bit | 1

    assert q.size_in_bits() == N

    # Generate p (A.1.1.2)
    offset = 1
    upper_bit = 1 << (L - 1)
    while True:
        V = [SHA256.new(seed + Integer(offset + j).to_bytes()).digest() for j in range(n + 1)]
        V = [Integer.from_bytes(v) for v in V]
        W = sum(
            [V[i] * (1 << (i * outlen)) for i in range(n)], (V[n] & ((1 << b_) - 1)) * (1 << (n * outlen))
        )

        X = Integer(W + upper_bit)  # 2^{L-1} < X < 2^{L}
        assert X.size_in_bits() == L

        c = X % (q * 2)
        p = X - (c - 1)  # 2q divides (p-1)
        if p.size_in_bits() == L and test_probable_prime(p, randfunc) == PROBABLY_PRIME:
            break
        offset += n + 1

    # Generate g (A.2.3, index=1)
    e = (p - 1) // q
    for count in itertools.count(1):
        U = seed + b"ggen" + bytes([1]) + Integer(count).to_bytes()
        W = Integer.from_bytes(SHA256.new(U).digest())
        g = pow(W, e, p)
        if g != 1:
            break

    return (p, q, g, seed)


def generate(
    bits: int, randfunc: Optional[RNG] = None, domain: Optional[tuple[int, int, int]] = None
) -> DsaKey:
    """Generate a new DSA key pair.

    The algorithm follows Appendix A.1/A.2 and B.1 of `FIPS 186-4`_,
    respectively for domain generation and key pair generation.

    Args:
      bits (integer):
        Key length, or size (in bits) of the DSA modulus *p*.
        It must be 1024, 2048 or 3072.

      randfunc (callable):
        Random number generation function; it accepts a single integer N
        and return a string of random data N bytes long.
        If not specified, :func:`Crypto.Random.get_random_bytes` is used.

      domain (tuple):
        The DSA domain parameters *p*, *q* and *g* as a list of 3
        integers. Size of *p* and *q* must comply to `FIPS 186-4`_.
        If not specified, the parameters are created anew.

    Returns:
      :class:`DsaKey` : a new DSA key object

    Raises:
      ValueError : when **bits** is too little, too big, or not a multiple of 64.

    .. _FIPS 186-4: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    if randfunc is None:
        randfunc = Random.get_random_bytes

    if domain:
        p, q, g = map(Integer, domain)

        ## Perform consistency check on domain parameters
        # P and Q must be prime
        fmt_error = test_probable_prime(p) == COMPOSITE
        fmt_error |= test_probable_prime(q) == COMPOSITE
        # Verify Lagrange's theorem for sub-group
        fmt_error |= ((p - 1) % q) != 0
        fmt_error |= g <= 1 or g >= p
        fmt_error |= pow(g, q, p) != 1
        if fmt_error:
            raise ValueError("Invalid DSA domain parameters")
    else:
        p, q, g, _ = _generate_domain(bits, randfunc)

    L = p.size_in_bits()
    N = q.size_in_bits()

    if bits != L:
        raise ValueError("Mismatch between size of modulus (%d) and 'bits' parameter (%d)" % (L, bits))

    if (L, N) not in [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]:
        raise ValueError("Lengths of p and q (%d, %d) are not compatible with FIPS 186-3" % (L, N))

    if not 1 < g < p:
        raise ValueError("Incorrent DSA generator")

    # B.1.1
    c = Integer.random(exact_bits=N + 64, randfunc=randfunc)
    x = c % (q - 1) + 1  # 1 <= x <= q-1
    y = pow(g, x, p)

    key_dict = {"y": y, "g": g, "p": p, "q": q, "x": x}
    return DsaKey(key_dict)


def construct(
    tup: Union[tuple[Int, Int, Int, Int], tuple[Int, Int, Int, Int, Int], Sequence[Int]],
    consistency_check: bool = True,
) -> DsaKey:
    """Construct a DSA key from a tuple of valid DSA components.

    Args:
      tup (tuple):
        A tuple of long integers, with 4 or 5 items
        in the following order:

            1. Public key (*y*).
            2. Sub-group generator (*g*).
            3. Modulus, finite field order (*p*).
            4. Sub-group order (*q*).
            5. Private key (*x*). Optional.

      consistency_check (boolean):
        If ``True``, the library will verify that the provided components
        fulfil the main DSA properties.

    Raises:
      ValueError: when the key being imported fails the most basic DSA validity checks.

    Returns:
      :class:`DsaKey` : a DSA key object
    """

    key_dict = dict(zip(("y", "g", "p", "q", "x"), map(Integer, tup)))
    key = DsaKey(key_dict)

    fmt_error = False
    if consistency_check:
        # The components as Integers, as x is secret
        y, g, p, q = (key_dict[comp] for comp in ("y", "g", "p", "q"))
        # P and Q must be prime
        fmt_error = test_probable_prime(p) == COMPOSITE
        fmt_error |= test_probable_prime(q) == COMPOSITE
        # Verify Lagrange's theorem for sub-group
        fmt_error |= ((p - 1) % q) != 0
        fmt_error |= g <= 1 or g >= p
        fmt_error |= pow(g, q, p) != 1
        # Public key
        fmt_error |= y <= 0 or y >= p
        if "x" in key_dict:
            x = key_dict["x"]
            fmt_error |= x <= 0 or x >= q
            fmt_error |= pow(g, x, p) != y

    if fmt_error:
        raise ValueError("Invalid DSA key components")

    return key


# Dss-Parms  ::=  SEQUENCE  {
#       p       OCTET STRING,
#       q       OCTET STRING,
#       g       OCTET STRING
# }
# DSAPublicKey ::= INTEGER --  public key, y


def _import_openssl_private(encoded, passphrase, params):
    if params:
        raise ValueError("DSA private key already comes with parameters")
    der = DerSequence().decode(encoded, nr_elements=6, only_ints_expected=True)
    if der[0] != 0:
        raise ValueError("No version found")
    tup = [der[comp] for comp in (4, 3, 1, 2, 5)]
    return construct(tup)


def _import_subjectPublicKeyInfo(encoded, passphrase, params):
    algoid, encoded_key, emb_params = _expand_subject_public_key_info(encoded)
    if algoid != oid:
        raise ValueError("No DSA subjectPublicKeyInfo")
    if params and emb_params:
        raise ValueError("Too many DSA parameters")

    y = DerInteger().decode(encoded_key).value
    p, q, g = list(DerSequence().decode(params or emb_params))
    tup = (y, g, p, q)
    return construct(tup)


def _import_x509_cert(encoded, passphrase, params):
    sp_info = _extract_subject_public_key_info(encoded)
    return _import_subjectPublicKeyInfo(sp_info, None, params)


def _import_pkcs8(encoded, passphrase, params, max_iteration_count=None, threads=1, max_memory=None):
    if params:
        raise ValueError("PKCS#8 already includes parameters")
    k = PKCS8.unwrap(encoded, passphrase, max_iteration_count, threads=threads, max_memory=max_memory)
    if k[0] != oid:
        raise ValueError("No PKCS#8 encoded DSA key")
    x = DerInteger().decode(k[1]).value
    p, q, g = list(DerSequence().decode(k[2]))
    tup = (pow(g, x, p), g, p, q, x)
    return construct(tup)


def _import_key_der(key_data, passphrase, params, max_iteration_count=None, threads=1, max_memory=None):
    """Import a DSA key (public or private half), encoded in DER form."""

    decodings = (_import_openssl_private, _import_subjectPublicKeyInfo, _import_x509_cert)

    for decoding in decodings:
        try:
            return decoding(key_data, passphrase, params)
        except ValueError:
            pass

    try:
        return _import_pkcs8(key_data, passphrase, params, max_iteration_count, threads, max_memory)
    except (KdfLimitError, PassphraseRequiredError, IncorrectPassphraseError):
        raise
    except ValueError:
        pass

    raise ValueError("DSA key format is not supported")


def import_key(
    extern_key: Union[str, bytes],
    passphrase: Optional[Union[str, bytes]] = None,
    *,
    max_iteration_count: Optional[int] = None,
    threads: int = 1,
    max_memory: Optional[int] = None,
) -> DsaKey:
    """Import a DSA key.

    Args:
      extern_key (string or byte string):
        The DSA key to import.

        The following formats are supported for a DSA **public** key:

        - X.509 certificate (binary DER or PEM)
        - X.509 ``subjectPublicKeyInfo`` (binary DER or PEM)
        - OpenSSH (ASCII one-liner, see `RFC4253`_)

        The following formats are supported for a DSA **private** key:

        - `PKCS#8`_ ``PrivateKeyInfo`` or ``EncryptedPrivateKeyInfo``
          DER SEQUENCE (binary or PEM)
        - OpenSSL/OpenSSH custom format (binary or PEM)

        For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.

      passphrase (string):
        In case of an encrypted private key, this is the pass phrase
        from which the decryption key is derived.

        Encryption may be applied either at the `PKCS#8`_ or at the PEM level.

      max_iteration_count (integer):
        The maximum value allowed for the PBKDF2 iteration count or
        the scrypt cost *N·r·p/8* (that is, *N* for the usual *r=8* and *p=1*)
        of a `PKCS#8`_ encrypted key.
        A malicious key could require an extremely high number of
        iterations, tying up the CPU for hours.
        The default value is None: a limit for each KDF, which keeps
        the key derivation to about one minute at most
        (see :ref:`the limits for decryption<pkcs8_limits>`).
        Set it to ``0`` to disable the check.

      threads (integer):
        The maximum number of threads used to derive the decryption key
        with scrypt (default: 1, no extra threads; 0 for all CPU cores).
        Only a `PKCS#8`_ key protected with scrypt and a parallelization
        parameter larger than 1 can use them.

      max_memory (integer):
        The maximum memory (in bytes) for the key derivation of a `PKCS#8`_
        encrypted key, as a limit on the **total** of all threads together
        (not on each thread).
        Only scrypt uses a significant amount: 128 · (*N* + 2) · *r* bytes for
        **each** thread, plus 256 · *r* · *p* bytes for all the flows together.
        If the requested threads do not fit, fewer are used (down to one);
        if a single thread does not fit, the key is rejected.
        The default value is None (a limit of 256 MiB).
        Set it to ``0`` to disable the check.

    Returns:
      :class:`DsaKey` : a DSA key object

    Raises:
      PassphraseRequiredError :
        (a ``ValueError``) when the private key is encrypted,
        but no passphrase was provided.
      IncorrectPassphraseError :
        (a ``ValueError``) when the private key cannot be decrypted
        with the passphrase (most likely, the passphrase is wrong).
      ValueError : when the given key cannot be parsed.

    .. _RFC1421: https://www.rfc-editor.org/rfc/rfc1421
    .. _RFC1423: https://www.rfc-editor.org/rfc/rfc1423
    .. _RFC4253: https://www.rfc-editor.org/rfc/rfc4253
    .. _PKCS#8: https://www.rfc-editor.org/rfc/rfc5958
    """

    PKCS8._check_kdf_params(max_iteration_count, threads, max_memory)
    extern_key = tobytes(extern_key)
    if passphrase is not None:
        passphrase = tobytes(passphrase)

    if extern_key.startswith(b"-----"):
        # This is probably a PEM encoded key
        (der, _marker, enc_flag) = PEM.decode(extern_key.decode("latin-1"), passphrase)
        if enc_flag:
            passphrase = None
        return _import_key_der(der, passphrase, None, max_iteration_count, threads, max_memory)

    if extern_key.startswith(b"ssh-dss "):
        # This is probably a public OpenSSH key
        keystring = binascii.a2b_base64(extern_key.split(b" ")[1])
        keyparts = []
        while len(keystring) > 4:
            length = struct.unpack(">I", keystring[:4])[0]
            keyparts.append(keystring[4 : 4 + length])
            keystring = keystring[4 + length :]
        if keyparts[0] == b"ssh-dss":
            tup = [Integer.from_bytes(keyparts[x]) for x in (4, 3, 1, 2)]
            return construct(tup)

    if len(extern_key) > 0 and extern_key[0] == 0x30:
        # This is probably a DER encoded key
        return _import_key_der(extern_key, passphrase, None, max_iteration_count, threads, max_memory)

    raise ValueError("DSA key format is not supported")


# Backward compatibility
importKey = import_key

#: `Object ID`_ for a DSA key.
#:
#: id-dsa ID ::= { iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 1 }
#:
#: .. _`Object ID`: http://www.alvestrand.no/objectid/1.2.840.10040.4.1.html
oid: str = "1.2.840.10040.4.1"
