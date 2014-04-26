# -*- coding: utf-8 -*-
#
#  Cipher/blockalgo.py
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
"""Module with definitions common to all block ciphers."""

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from Crypto.Util.py3compat import *

from binascii import unhexlify

from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long
import Crypto.Util.Counter
from Crypto.Hash import CMAC
from Crypto.Hash.CMAC import _SmoothMAC
from Crypto.Protocol.KDF import _S2V

from Crypto.Util import _galois

#: *Electronic Code Book (ECB)*.
#: This is the simplest encryption mode. Each of the plaintext blocks
#: is directly encrypted into a ciphertext block, independently of
#: any other block. This mode exposes frequency of symbols
#: in your plaintext. Other modes (e.g. *CBC*) should be used instead.
#:
#: See `NIST SP800-38A`_ , Section 6.1 .
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_ECB = 1

#: *Cipher-Block Chaining (CBC)*. Each of the ciphertext blocks depends
#: on the current and all previous plaintext blocks. An Initialization Vector
#: (*IV*) is required.
#:
#: The *IV* is a data block to be transmitted to the receiver.
#: The *IV* can be made public, but it must be authenticated by the receiver
#: and it should be picked randomly.
#:
#: See `NIST SP800-38A`_ , Section 6.2 .
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_CBC = 2

#: *Cipher FeedBack (CFB)*. This mode is similar to CBC, but it transforms
#: the underlying block cipher into a stream cipher. Plaintext and ciphertext
#: are processed in *segments* of **s** bits. The mode is therefore sometimes
#: labelled **s**-bit CFB. An Initialization Vector (*IV*) is required.
#:
#: When encrypting, each ciphertext segment contributes to the encryption of
#: the next plaintext segment.
#:
#: This *IV* is a data block to be transmitted to the receiver.
#: The *IV* can be made public, but it should be picked randomly.
#: Reusing the same *IV* for encryptions done with the same key lead to
#: catastrophic cryptographic failures.
#:
#: See `NIST SP800-38A`_ , Section 6.3 .
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_CFB = 3

#: This mode should not be used.
MODE_PGP = 4

#: *Output FeedBack (OFB)*. This mode is very similar to CBC, but it
#: transforms the underlying block cipher into a stream cipher.
#: The keystream is the iterated block encryption of an
#: Initialization Vector (*IV*).
#:
#: The *IV* is a data block to be transmitted to the receiver.
#: The *IV* can be made public, but it should be picked randomly.
#:
#: Reusing the same *IV* for encryptions done with the same key lead to
#: catastrophic cryptograhic failures.
#:
#: See `NIST SP800-38A`_ , Section 6.4 .
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_OFB = 5

#: *CounTeR (CTR)*. This mode is very similar to ECB, in that
#: encryption of one block is done independently of all other blocks.
#: Unlike ECB, the block *position* contributes to the encryption and no
#: information leaks about symbol frequency.
#:
#: Each message block is associated to a *counter* which must be unique
#: across all messages that get encrypted with the same key (not just within
#: the same message). The counter is as big as the block size.
#:
#: Counters can be generated in several ways. The most straightword one is
#: to choose an *initial counter block* (which can be made public, similarly
#: to the *IV* for the other modes) and increment its lowest **m** bits by
#: one (modulo *2^m*) for each block. In most cases, **m** is chosen to be half
#: the block size.
#:
#: Reusing the same *initial counter block* for encryptions done with the same
#: key lead to catastrophic cryptograhic failures.
#:
#: See `NIST SP800-38A`_ , Section 6.5 (for the mode) and Appendix B (for how
#: to manage the *initial counter block*).
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_CTR = 6

#: *OpenPGP CFB*. This mode is a variant of CFB, and it is only used in PGP and
#: OpenPGP_ applications. An Initialization Vector (*IV*) is required.
#:
#: Unlike CFB, the IV is not transmitted to the receiver.
#: Instead, the *encrypted* IV is.
#: The IV is a random data block. Two of its bytes are duplicated to act
#: as a checksum for the correctness of the key. The encrypted IV is
#: therefore 2 bytes longer than the clean IV.
#:
#: .. _OpenPGP: http://tools.ietf.org/html/rfc4880
MODE_OPENPGP = 7

#: *Counter with CBC-MAC (CCM)*. This is an Authenticated Encryption with
#: Associated Data (`AEAD`_) mode. It provides both confidentiality and
#: authenticity.
#: The header of the message may be left in the clear, if needed, and it will
#: still be subject to authentication. The decryption step tells the receiver
#: if the message comes from a source that really knowns the secret key.
#: Additionally, decryption detects if any part of the message - including the
#: header - has been modified or corrupted.
#:
#: This mode requires a nonce. The nonce shall never repeat for two
#: different messages encrypted with the same key, but it does not need
#: to be random.
#: Note that there is a trade-off between the size of the nonce and the
#: maximum size of a single message you can encrypt.
#:
#: It is important to use a large nonce if the key is reused across several
#: messages and the nonce is chosen randomly.
#:
#: It is acceptable to us a short nonce if the key is only used a few times or
#: if the nonce is taken from a counter.
#:
#: The following table shows the trade-off when the nonce is chosen at
#: random. The column on the left shows how many messages it takes
#: for the keystream to repeat **on average**. In practice, you will want to
#: stop using the key way before that.
#:
#: +--------------------+---------------+-------------------+
#: | Avg. # of messages |    nonce      |     Max. message  |
#: | before keystream   |    size       |     size          |
#: | repeats            |    (bytes)    |     (bytes)       |
#: +====================+===============+===================+
#: |       2**52        |      13       |        64K        |
#: +--------------------+---------------+-------------------+
#: |       2**48        |      12       |        16M        |
#: +--------------------+---------------+-------------------+
#: |       2**44        |      11       |         4G        |
#: +--------------------+---------------+-------------------+
#: |       2**40        |      10       |         1T        |
#: +--------------------+---------------+-------------------+
#: |       2**36        |       9       |        64P        |
#: +--------------------+---------------+-------------------+
#: |       2**32        |       8       |        16E        |
#: +--------------------+---------------+-------------------+
#:
#: This mode is only available for ciphers that operate on 128 bits blocks
#: (e.g. AES but not TDES).
#:
#: See `NIST SP800-38C`_ or RFC3610_ .
#:
#: .. _`NIST SP800-38C`: http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf
#: .. _RFC3610: https://tools.ietf.org/html/rfc3610
#: .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
MODE_CCM = 8

#: *EAX*. This is an Authenticated Encryption with Associated Data
#: (`AEAD`_) mode. It provides both confidentiality and authenticity.
#:
#: The header of the message may be left in the clear, if needed, and it will
#: still be subject to authentication.
#:
#: The decryption step tells the receiver if the message comes from a source
#: that really knowns the secret key.
#: Additionally, decryption detects if any part of the message - including the
#: header - has been modified or corrupted.
#:
#: This mode requires a nonce. The nonce shall never repeat for two
#: different messages encrypted with the same key, but it does not need to
#: be random.
#
#: This mode is only available for ciphers that operate on 64 or
#: 128 bits blocks.
#:
#: There are no official standards defining EAX. The implementation is based on
#: `a proposal`__ that was presented to NIST.
#:
#: .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
#: .. __: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/eax/eax-spec.pdf
MODE_EAX = 9

#: *Synthetic Initialization Vector*. This is an Authenticated Encryption with
#: Associated Data (`AEAD`_) mode. It provides both confidentiality and
#: authenticity.
#: The header of the message may be left in the clear, if needed, and it will
#: still be subject to authentication. The decryption step tells the receiver
#: if the message comes from a source that really knowns the secret key.
#: Additionally, decryption detects if any part of the message - including the
#: header - has been modified or corrupted.
#:
#: If the data being encrypted is completely unpredictable to an adversary
#: (e.g. a secret key, for key wrapping purposes) a nonce is not strictly
#: required.
#:
#: Otherwise, a nonce has to be provided; the nonce shall never repeat
#: for two different messages encrypted with the same key, but it does not
#: need to be random.
#:
#: Unlike other AEAD modes such as CCM, EAX or GCM, accidental reuse of a
#: nonce is not catastrophic for the confidentiality of the message. The only
#: effect is that an attacker can tell when the same plaintext (and same
#: associated data) is protected with the same key.
#:
#: The length of the MAC is fixed to the block size of the underlying cipher.
#: The key size is twice the length of the key of the underlying cipher.
#:
#: This mode is only available for AES ciphers.
#:
#: +--------------------+---------------+-------------------+
#: |      Cipher        | SIV MAC size  |   SIV key length  |
#: |                    |    (bytes)    |     (bytes)       |
#: +====================+===============+===================+
#: |    AES-128         |      16       |        32         |
#: +--------------------+---------------+-------------------+
#: |    AES-192         |      16       |        48         |
#: +--------------------+---------------+-------------------+
#: |    AES-256         |      16       |        64         |
#: +--------------------+---------------+-------------------+
#:
#: See `RFC5297`_ and the `original paper`__.
#:
#: .. _RFC5297: https://tools.ietf.org/html/rfc5297
#: .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
#: .. __: http://www.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf
MODE_SIV = 10

#: *Galois/Counter Mode (GCM)*. This is an Authenticated Encryption with
#: Associated Data (`AEAD`_) mode. It provides both confidentiality and
#: authenticity.
#: The header of the message may be left in the clear, if needed, and it will
#: still be subject to authentication. The decryption step tells the receiver
#: if the message comes from a source that really knowns the secret key.
#: Additionally, decryption detects if any part of the message - including the
#: header - has been modified or corrupted.
#:
#: This mode requires a nonce. The nonce shall never repeat for two
#: different messages encrypted with the same key, but it does not need to
#: be random.
#:
#: This mode is only available for ciphers that operate on 128 bits blocks
#: (e.g. AES but not TDES).
#:
#: See `NIST SP800-38D`_ .
#:
#: .. _`NIST SP800-38D`: http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
#: .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
MODE_GCM = 11


def _getParameter(name, index, args, kwargs, default=None):
    """Find a parameter in tuple and dictionary arguments a function receives"""

    param = kwargs.get(name)
    if len(args) > index:
        if param:
            raise TypeError("Parameter '%s' is specified twice" % name)
        param = args[index]
    return param or default


class _CBCMAC(_SmoothMAC):

    def __init__(self, key, ciphermod):
        _SmoothMAC.__init__(self, ciphermod.block_size, None, 0)
        self._key = key
        self._factory = ciphermod

    def _ignite(self, data):
        if self._mac:
            raise TypeError("_ignite() cannot be called twice")

        self._buffer.insert(0, data)
        self._buffer_len += len(data)
        self._mac = self._factory.new(self._key, MODE_CBC, bchr(0) * 16)
        self.update(b(""))

    def _update(self, block_data):
        self._t = self._mac.encrypt(block_data)[-16:]

    def _digest(self, left_data):
        return self._t


class _GHASH(_SmoothMAC):
    """GHASH function defined in NIST SP 800-38D, Algorithm 2.

    If X_1, X_2, .. X_m are the blocks of input data, the function
    computes:

       X_1*H^{m} + X_2*H^{m-1} + ... + X_m*H

    in the Galois field GF(2^256) using the reducing polynomial
    (x^128 + x^7 + x^2 + x + 1).
    """

    def __init__(self, hash_subkey, block_size):
        _SmoothMAC.__init__(self, block_size, None, 0)
        self._hash_subkey = _galois.ghash_expand(hash_subkey)
        self._last_y = bchr(0) * 16
        self._mac = _galois.ghash

    def copy(self):
        clone = _GHASH(self._hash_subkey, self._bs)
        _SmoothMAC._deep_copy(self, clone)
        clone._last_y = self._last_y
        return clone

    def _update(self, block_data):
        self._last_y = _galois.ghash(block_data, self._last_y,
                                     self._hash_subkey)

    def _digest(self, left_data):
        return self._last_y


class BlockAlgo:
    """Class modelling an abstract block cipher."""

    def __init__(self, factory, key, *args, **kwargs):
        self.mode = _getParameter('mode', 0, args, kwargs, default=MODE_ECB)
        self.block_size = factory.block_size
        self._factory = factory
        self._tag = None

        if self.mode == MODE_CCM:
            if self.block_size != 16:
                raise TypeError("CCM mode is only available for ciphers that operate on 128 bits blocks")

            self._mac_len = kwargs.get('mac_len', 16)        # t
            if self._mac_len not in (4, 6, 8, 10, 12, 14, 16):
                raise ValueError("Parameter 'mac_len' must be even and in the range 4..16")

            self.nonce = _getParameter('nonce', 1, args, kwargs)   # N
            if not (self.nonce and 7 <= len(self.nonce) <= 13):
                raise ValueError("Length of parameter 'nonce' must be"
                                 " in the range 7..13 bytes")

            self._key = key
            self._msg_len = kwargs.get('msg_len', None)      # p
            self._assoc_len = kwargs.get('assoc_len', None)  # a

            self._cipherMAC = _CBCMAC(key, factory)
            self._done_assoc_data = False      # True when all associated data
                                               # has been processed

            # Allowed transitions after initialization
            self._next = [self.update, self.encrypt, self.decrypt,
                          self.digest, self.verify]

            # Try to start CCM
            self._start_ccm()

        elif self.mode == MODE_OPENPGP:
            self._start_PGP(factory, key, *args, **kwargs)
        elif self.mode == MODE_EAX:
            self._start_eax(factory, key, *args, **kwargs)
        elif self.mode == MODE_SIV:
            self._start_siv(factory, key, *args, **kwargs)
        elif self.mode == MODE_GCM:
            self._start_gcm(factory, key, *args, **kwargs)
        else:
            self._cipher = factory.new(key, *args, **kwargs)
            self.IV = self._cipher.IV

    def _start_gcm(self, factory, key, *args, **kwargs):

        if self.block_size != 16:
            raise TypeError("GCM mode is only available for ciphers that operate on 128 bits blocks")

        self.nonce = _getParameter('nonce', 1, args, kwargs)
        if not self.nonce:
            raise TypeError("MODE_GCM requires a nonce")

        self._mac_len = kwargs.get('mac_len', 16)
        if not (self._mac_len and 4 <= self._mac_len <= 16):
            raise ValueError("Parameter 'mac_len' must not be larger than 16 bytes")

        # Allowed transitions after initialization
        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        self._done_assoc_data = False

        # Length of the ciphertext or plaintext
        self._msg_len = 0

        # Step 1 in SP800-38D, Algorithm 4 (encryption) - Compute H
        # See also Algorithm 5 (decryption)
        hash_subkey = factory.new(key).encrypt(bchr(0) * 16)

        # Step 2 - Compute J0 (integer, not byte string!)
        if len(self.nonce) == 12:
            self._j0 = bytes_to_long(self.nonce + b("\x00\x00\x00\x01"))
        else:
            fill = (16 - (len(self.nonce) % 16)) % 16 + 8
            ghash_in = (self.nonce +
                        bchr(0) * fill +
                        long_to_bytes(8 * len(self.nonce), 8))

            mac = _GHASH(hash_subkey, factory.block_size)
            mac.update(ghash_in)
            self._j0 = bytes_to_long(mac.digest())

        # Step 3 - Prepare GCTR cipher for encryption/decryption
        ctr = Counter.new(128, initial_value=self._j0 + 1,
                          allow_wraparound=True)
        self._cipher = self._factory.new(key, MODE_CTR, counter=ctr)

        # Step 5 - Bootstrat GHASH
        self._cipherMAC = _GHASH(hash_subkey, factory.block_size)

        # Step 6 - Prepare GCTR cipher for GMAC
        ctr = Counter.new(128, initial_value=self._j0, allow_wraparound=True)
        self._tag_cipher = self._factory.new(key, MODE_CTR, counter=ctr)

    def _start_siv(self, factory, key, *args, **kwargs):

        subkey_size, rem = divmod(len(key), 2)
        if rem:
            raise ValueError("MODE_SIV requires a key twice as long as for the underlying cipher")

        # IV is optional
        self.nonce = _getParameter('nonce', 1, args, kwargs)

        self._cipherMAC = _S2V(key[:subkey_size], ciphermod=factory)
        self._subkey_ctr = key[subkey_size:]
        self._mac_len = factory.block_size

        self._cipherMAC = self._cipherMAC

        # Allowed transitions after initialization
        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

    def _siv_ctr_cipher(self, tag):
        """Create a new CTR cipher from the MAC in SIV mode"""

        tag_int = bytes_to_long(tag)
        init_counter = tag_int ^ (tag_int & 0x8000000080000000L)
        ctr = Counter.new(self._factory.block_size * 8,
                          initial_value=init_counter,
                          allow_wraparound=True)

        return self._factory.new(self._subkey_ctr, MODE_CTR, counter=ctr)

    def _start_eax(self, factory, key, *args, **kwargs):

        self.nonce = _getParameter('nonce', 1, args, kwargs)
        if not self.nonce:
            raise TypeError("MODE_EAX requires a nonce")

        # Allowed transitions after initialization
        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        self._mac_len = kwargs.get('mac_len', self.block_size)
        if not (self._mac_len and 4 <= self._mac_len <= self.block_size):
            raise ValueError("Parameter 'mac_len' must not be larger than %d"
                             % self.block_size)

        self._omac = [
                CMAC.new(key, bchr(0) * (self.block_size - 1) + bchr(i),
                         ciphermod=factory)
                for i in xrange(0, 3)
                ]

        # Compute MAC of nonce
        self._omac[0].update(self.nonce)

        self._cipherMAC = self._omac[1]

        # MAC of the nonce is also the initial counter for CTR encryption
        counter_int = bytes_to_long(self._omac[0].digest())
        counter_obj = Crypto.Util.Counter.new(
                        self.block_size * 8,
                        initial_value=counter_int,
                        allow_wraparound=True)
        self._cipher = factory.new(key, MODE_CTR, counter=counter_obj)

    def _start_PGP(self, factory, key, *args, **kwargs):
        # OPENPGP mode. For details, see 13.9 in RCC4880.
        #
        # A few members are specifically created for this mode:
        #  - _encrypted_iv, set in this constructor
        #  - _done_first_block, set to True after the first encryption
        #  - _done_last_block, set to True after a partial block is processed

        self._done_first_block = False
        self._done_last_block = False
        self.IV = _getParameter('IV', 1, args, kwargs)
        if self.IV is None:
            # TODO: Decide whether 'IV' or 'iv' should be used going forward,
            # and deprecate the other.  'IV' is consistent with the rest of
            # PyCrypto, but 'iv' is more common in Python generally.  For now,
            # we'll support both here.  When in doubt, use a positional
            # parameter for now.
            self.IV = _getParameter('iv', 1, args, kwargs)
        if not self.IV:
            raise ValueError("MODE_OPENPGP requires an IV")

        # Instantiate a temporary cipher to process the IV
        IV_cipher = factory.new(
                        key,
                        MODE_CFB,
                        b('\x00') * self.block_size,    # IV for CFB
                        segment_size=self.block_size * 8)

        # The cipher will be used for...
        if len(self.IV) == self.block_size:
            # ... encryption
            self._encrypted_IV = IV_cipher.encrypt(
                    self.IV + self.IV[-2:] +            # Plaintext
                    b('\x00') * (self.block_size - 2)   # Padding
                    )[:self.block_size + 2]
        elif len(self.IV) == self.block_size + 2:
            # ... decryption
            self._encrypted_IV = self.IV
            self.IV = IV_cipher.decrypt(
                        self.IV +                           # Ciphertext
                        b('\x00') * (self.block_size - 2)   # Padding
                        )[:self.block_size + 2]
            if self.IV[-2:] != self.IV[-4:-2]:
                raise ValueError("Failed integrity check for OPENPGP IV")
            self.IV = self.IV[:-2]
        else:
            raise ValueError("Length of IV must be %d or %d bytes for MODE_OPENPGP"
                % (self.block_size, self.block_size+2))

        # Instantiate the cipher for the real PGP data
        self._cipher = factory.new(
                            key,
                            MODE_CFB,
                            self._encrypted_IV[-self.block_size:],
                            segment_size=self.block_size * 8
                            )

    def _start_ccm(self, assoc_len=None, msg_len=None):
        # CCM mode. This method creates the 2 ciphers used for the MAC
        # (self._cipherMAC) and for the encryption/decryption (self._cipher).
        #
        # Member _assoc_buffer may already contain user data that needs to be
        # authenticated.

        if self._cipherMAC.can_reduce():
            # Already started
            return
        if assoc_len is not None:
            self._assoc_len = assoc_len
        if msg_len is not None:
            self._msg_len = msg_len
        if None in (self._assoc_len, self._msg_len):
            return

        # q is the length of Q, the encoding of the message length
        q = 15 - len(self.nonce)

        ## Compute B_0
        flags = (
                64 * (self._assoc_len > 0) +
                8 * divmod(self._mac_len - 2, 2)[0] +
                (q - 1)
                )
        b_0 = bchr(flags) + self.nonce + long_to_bytes(self._msg_len, q)

        # Start CBC MAC with zero IV
        assoc_len_encoded = b('')
        if self._assoc_len > 0:
            if self._assoc_len < (2 ** 16 - 2 ** 8):
                enc_size = 2
            elif self._assoc_len < (2L ** 32):
                assoc_len_encoded = b('\xFF\xFE')
                enc_size = 4
            else:
                assoc_len_encoded = b('\xFF\xFF')
                enc_size = 8
            assoc_len_encoded += long_to_bytes(self._assoc_len, enc_size)
        self._cipherMAC._ignite(b_0 + assoc_len_encoded)

        # Start CTR cipher
        prefix = bchr(q - 1) + self.nonce
        ctr = Counter.new(128 - len(prefix) * 8, prefix, initial_value=0)
        self._cipher = self._factory.new(self._key, MODE_CTR, counter=ctr)
        # Will XOR against CBC MAC
        self._s_0 = self._cipher.encrypt(bchr(0) * 16)

    def update(self, assoc_data):
        """Protect associated data

        When using an AEAD mode like CCM, EAX, GCM or SIV, and
        if there is any associated data, the caller has to invoke
        this function one or more times, before using
        ``decrypt`` or ``encrypt``.

        By *associated data* it is meant any data (e.g. packet headers) that
        will not be encrypted and will be transmitted in the clear.
        However, the receiver is still able to detect any modification to it.
        In CCM and GCM, the *associated data* is also called
        *additional authenticated data* (AAD).
        In EAX, the *associated data* is called *header*.

        If there is no associated data, this method must not be called.

        The caller may split associated data in segments of any size, and
        invoke this method multiple times, each time with the next segment.

        :Parameters:
          assoc_data : byte string
            A piece of associated data. There are no restrictions on its size.
        """

        if self.mode not in (MODE_CCM, MODE_EAX, MODE_SIV, MODE_GCM):
            raise TypeError("update() not supported by this mode of operation")

        if self.update not in self._next:
            raise TypeError("update() can only be called immediately after initialization")

        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        return self._cipherMAC.update(assoc_data)

    def encrypt(self, plaintext):
        """Encrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have encrypted a message
        you cannot encrypt (or decrypt) another message using the same
        object.

        For `MODE_SIV` (always) and `MODE_CCM` (when ``msg_len`` was not
        passed at initialization), this method can be called only **once**.

        For all other modes, the data to encrypt can be broken up in two or
        more pieces and `encrypt` can be called multiple times.

        That is, the statement:

            >>> c.encrypt(a) + c.encrypt(b)

        is equivalent to:

             >>> c.encrypt(a+b)

        That also means that you cannot reuse an object for encrypting
        or decrypting other data with the same key.

        This function does not add any padding to the plaintext.

         - For `MODE_ECB` and `MODE_CBC`, *plaintext* length (in bytes) must be
           a multiple of *block_size*.

         - For `MODE_CFB`, *plaintext* length (in bytes) must be a multiple
           of *segment_size*/8.

         - For `MODE_OFB`, `MODE_CTR` and all AEAD modes
           *plaintext* can be of any length.

         - For `MODE_OPENPGP`, *plaintext* must be a multiple of *block_size*,
           unless it is the last chunk of the message.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
        :Return:
            the encrypted data, as a byte string. It is as long as
            *plaintext* with one exception: when encrypting the first message
            chunk with `MODE_OPENPGP`, the encypted IV is prepended to the
            returned ciphertext.
        """

        if self.mode == MODE_OPENPGP:
            padding_length = (self.block_size - len(plaintext) % self.block_size) % self.block_size
            if padding_length > 0:
                # CFB mode requires ciphertext to have length multiple
                # of block size,
                # but PGP mode allows the last block to be shorter
                if self._done_last_block:
                    raise ValueError("Only the last chunk is allowed to have length not multiple of %d bytes",
                        self.block_size)
                self._done_last_block = True
                padded = plaintext + b('\x00') * padding_length
                res = self._cipher.encrypt(padded)[:len(plaintext)]
            else:
                res = self._cipher.encrypt(plaintext)
            if not self._done_first_block:
                res = self._encrypted_IV + res
                self._done_first_block = True
            return res

        if self.mode in (MODE_CCM, MODE_EAX, MODE_SIV, MODE_GCM):
            if self.encrypt not in self._next:
                raise TypeError("encrypt() can only be called after initialization or an update()")
            self._next = [self.encrypt, self.digest]

        if self.mode == MODE_CCM:
            if self._assoc_len is None:
                self._start_ccm(assoc_len=self._cipherMAC.get_len())
            if self._msg_len is None:
                self._start_ccm(msg_len=len(plaintext))
                self._next = [self.digest]
            if not self._done_assoc_data:
                self._cipherMAC.zero_pad()
                self._done_assoc_data = True

            self._cipherMAC.update(plaintext)

        if self.mode == MODE_SIV:
            self._next = [self.digest]

            if self.nonce:
                self._cipherMAC.update(self.nonce)

            self._cipherMAC.update(plaintext)
            self._cipher = self._siv_ctr_cipher(self._cipherMAC.derive())

        ct = self._cipher.encrypt(plaintext)

        if self.mode == MODE_EAX:
            self._omac[2].update(ct)

        if self.mode == MODE_GCM:
            if not self._done_assoc_data:
                self._cipherMAC.zero_pad()
                self._done_assoc_data = True
            self._cipherMAC.update(ct)
            self._msg_len += len(plaintext)

        return ct

    def decrypt(self, ciphertext):
        """Decrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have decrypted a message
        you cannot decrypt (or encrypt) another message with the same
        object.

        For `MODE_SIV` (always) and `MODE_CCM` (when ``msg_len`` was not
        passed at initialization), this method can be called only **once**.

        For all other modes, the data to decrypt can be broken up in two or
        more pieces and `decrypt` can be called multiple times.

        That is, the statement:

            >>> c.decrypt(a) + c.decrypt(b)

        is equivalent to:

             >>> c.decrypt(a+b)

        That also means that you cannot reuse an object for encrypting
        or decrypting other data with the same key.

        This function does not remove any padding from the plaintext.

         - For `MODE_ECB` and `MODE_CBC`, *ciphertext* length (in bytes) must
           be a multiple of *block_size*.

         - For `MODE_CFB`, *ciphertext* length (in bytes) must be a multiple
           of *segment_size*/8.

         - For `MODE_OFB`, `MODE_CTR` and all AEAD modes
           *ciphertext* can be of any length.

         - For `MODE_OPENPGP`, *plaintext* must be a multiple of *block_size*,
           unless it is the last chunk of the message.

         - For `MODE_SIV`, *ciphertext* can be of any length, but it must also
           include the MAC (concatenated at the end).

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt (plus the MAC, for `MODE_SIV` only).

        :Return: the decrypted data (byte string).
        """

        if self.mode == MODE_OPENPGP:
            padding_length = (self.block_size - len(ciphertext) % self.block_size) % self.block_size
            if padding_length > 0:
                # CFB mode requires ciphertext to have length multiple
                # of block size,
                # but PGP mode allows the last block to be shorter
                if self._done_last_block:
                    raise ValueError("Only the last chunk is allowed to have length not multiple of %d bytes",
                        self.block_size)
                self._done_last_block = True
                padded = ciphertext + b('\x00') * padding_length
                res = self._cipher.decrypt(padded)[:len(ciphertext)]
            else:
                res = self._cipher.decrypt(ciphertext)
            return res

        if self.mode == MODE_SIV:
            raise TypeError("decrypt() not allowed for SIV mode."
                            " Use decrypt_and_verify() instead.")

        if self.mode in (MODE_CCM, MODE_EAX, MODE_GCM):

            if self.decrypt not in self._next:
                raise TypeError("decrypt() can only be called after initialization or an update()")
            self._next = [self.decrypt, self.verify]

            if self.mode == MODE_CCM:
                if self._assoc_len is None:
                    self._start_ccm(assoc_len=self._cipherMAC.get_len())
                if self._msg_len is None:
                    self._start_ccm(msg_len=len(ciphertext))
                    self._next = [self.verify]
                if not self._done_assoc_data:
                    self._cipherMAC.zero_pad()
                    self._done_assoc_data = True

            if self.mode == MODE_GCM:
                if not self._done_assoc_data:
                    self._cipherMAC.zero_pad()
                    self._done_assoc_data = True

                self._cipherMAC.update(ciphertext)
                self._msg_len += len(ciphertext)

            if self.mode == MODE_EAX:
                self._omac[2].update(ciphertext)

        pt = self._cipher.decrypt(ciphertext)

        if self.mode == MODE_CCM:
            self._cipherMAC.update(pt)

        return pt

    def digest(self):
        """Compute the *binary* MAC tag in an AEAD mode.

        When using an AEAD mode like CCM or EAX, the caller invokes
        this function at the very end.

        This method returns the MAC that shall be sent to the receiver,
        together with the ciphertext.

        :Return: the MAC, as a byte string.
        """

        if self.mode not in (MODE_CCM, MODE_EAX, MODE_SIV, MODE_GCM):
            raise TypeError("digest() not supported by this mode of operation")

        if self.digest not in self._next:
            raise TypeError("digest() cannot be called when decrypting or validating a message")
        self._next = [self.digest]

        return self._compute_mac()

    def _compute_mac(self):
        """Compute MAC without any FSM checks."""

        if self._tag:
            return self._tag

        if self.mode == MODE_CCM:

            if self._assoc_len is None:
                self._start_ccm(assoc_len=self._cipherMAC.get_len())
            if self._msg_len is None:
                self._start_ccm(msg_len=0)
            self._cipherMAC.zero_pad()
            self._tag = strxor(self._cipherMAC.digest(),
                               self._s_0)[:self._mac_len]

        if self.mode == MODE_GCM:

            # Step 5 in NIST SP 800-38D, Algorithm 4 - Compute S
            self._cipherMAC.zero_pad()
            auth_len = self._cipherMAC.get_len() - self._msg_len
            for tlen in (auth_len, self._msg_len):
                self._cipherMAC.update(long_to_bytes(8 * tlen, 8))
            s_tag = self._cipherMAC.digest()

            # Step 6 - Compute T
            self._tag = self._tag_cipher.encrypt(s_tag)[:self._mac_len]

        if self.mode == MODE_EAX:
            tag = bchr(0) * self.block_size
            for i in xrange(3):
                tag = strxor(tag, self._omac[i].digest())
            self._tag = tag[:self._mac_len]

        if self.mode == MODE_SIV:
            self._tag = self._cipherMAC.derive()

        return self._tag

    def hexdigest(self):
        """Compute the *printable* MAC tag in an AEAD mode.

        This method is like `digest`.

        :Return: the MAC, as a hexadecimal string.
        """
        return "".join(["%02x" % bord(x) for x in self.digest()])

    def verify(self, mac_tag):
        """Validate the *binary* MAC tag in an AEAD mode.

        When using an AEAD mode like CCM or EAX, the caller invokes
        this function at the very end.

        This method checks if the decrypted message is indeed valid
        (that is, if the key is correct) and it has not been
        tampered with while in transit.

        :Parameters:
          mac_tag : byte string
            This is the *binary* MAC, as received from the sender.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if self.mode not in (MODE_CCM, MODE_EAX, MODE_SIV, MODE_GCM):
            raise TypeError("verify() not supported by this mode of operation")

        if self.verify not in self._next:
            raise TypeError("verify() cannot be called when encrypting a message")
        self._next = [self.verify]

        res = 0
        # Constant-time comparison
        for x, y in zip(self._compute_mac(), mac_tag):
            res |= bord(x) ^ bord(y)
        if res or len(mac_tag) != self._mac_len:
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        """Validate the *printable* MAC tag in an AEAD mode.

        This method is like `verify`.

        :Parameters:
          hex_mac_tag : string
            This is the *printable* MAC, as received from the sender.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        self.verify(unhexlify(hex_mac_tag))

    def encrypt_and_digest(self, plaintext):
        """Perform encrypt() and digest() in one step.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
        :Return:
            a tuple with two byte strings:

            - the encrypted data
            - the MAC
        """

        return self.encrypt(plaintext), self.digest()

    def decrypt_and_verify(self, ciphertext, mac_tag):
        """Perform decrypt() and verify() in one step.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt.
          mac_tag : byte string
            This is the *binary* MAC, as received from the sender.

        :Return: the decrypted data (byte string).
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if self.mode == MODE_SIV:
            if self.decrypt not in self._next:
                raise TypeError("decrypt() can only be called"
                                " after initialization or an update()")
            self._next = [self.verify]

            # Take the MAC and start the cipher for decryption
            self._mac = mac_tag
            self._cipher = self._siv_ctr_cipher(self._mac)

            pt = self._cipher.decrypt(ciphertext)

            if self.nonce:
                self._cipherMAC.update(self.nonce)
            if pt:
                self._cipherMAC.update(pt)
        else:
            pt = self.decrypt(ciphertext)

        self.verify(mac_tag)
        return pt
