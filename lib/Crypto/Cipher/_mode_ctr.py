# -*- coding: utf-8 -*-
#
#  Cipher/mode_ctr.py : CTR mode
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

"""
Counter (CTR) mode.
"""

from ctypes import CDLL, byref, c_void_p, create_string_buffer

from Crypto.Util.py3compat import *
from Crypto.Util._modules import get_mod_name

raw_ctr_lib = CDLL(get_mod_name("Crypto.Cipher._raw_ctr"))


class RawCtrMode(object):
    """*CounTeR (CTR)* mode.

    This mode is very similar to ECB, in that
    encryption of one block is done independently of all other blocks.

    Unlike ECB, the block *position* contributes to the encryption
    and no information leaks about symbol frequency.

    Each message block is associated to a *counter* which
    must be unique across all messages that get encrypted
    with the same key (not just within the same message).
    The counter is as big as the block size.

    Counters can be generated in several ways. The most
    straightword one is to choose an *initial counter block*
    (which can be made public, similarly to the *IV* for the
    other modes) and increment its lowest **m** bits by one
    (modulo *2^m*) for each block. In most cases, **m** is
    chosen to be half the block size.

    See `NIST SP800-38A`_ , Section 6.5 (for the mode) and
    Appendix B (for how to manage the *initial counter block*).

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    """

    def __init__(self, block_cipher, initial_counter_block,
                 prefix_len, counter_len, little_endian):
        """Create a new block cipher, configured in CTR mode.

        :Parameters:
          block_cipher : C pointer
            A pointer to the low-level block cipher instance.

          initial_counter_block : byte string
            The initial plaintext to use to generate the key stream.

            It is as large as the cipher block, and it embeds
            the initial value of the counter.

            This value must not be reused.
            It shall contain a nonce or a random component.
            Reusing the *initial counter block* for encryptions
            performed with the same key compromises confidentiality.

          prefix_len : integer
            The amount of bytes at the beginning of the counter block
            that never change.

          counter_len : integer
            The length in bytes of the counter embedded in the counter
            block.

          little_endian : boolean
            True if the counter in the counter block is an integer encoded
            in little endian mode. If False, it is big endian.
        """

        self._state = None
        state = c_void_p()
        result = raw_ctr_lib.CTR_start_operation(block_cipher,
                                                 initial_counter_block,
                                                 len(initial_counter_block),
                                                 prefix_len,
                                                 counter_len,
                                                 little_endian,
                                                 byref(state))
        if result:
            raise ValueError("Error %X while instatiating the CTR mode"
                             % result)
        self._state = state.value

        #: The block size of the underlying cipher, in bytes.
        self.block_size = len(initial_counter_block)

    def encrypt(self, plaintext):
        """Encrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have encrypted a message
        you cannot encrypt (or decrypt) another message using the same
        object.

        The data to encrypt can be broken up in two or
        more pieces and `encrypt` can be called multiple times.

        That is, the statement:

            >>> c.encrypt(a) + c.encrypt(b)

        is equivalent to:

             >>> c.encrypt(a+b)

        This function does not add any padding to the plaintext.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
            It can be of any length.
        :Return:
            the encrypted data, as a byte string.
            It is as long as *plaintext*.
        """

        ciphertext = create_string_buffer(len(plaintext))
        result = raw_ctr_lib.CTR_encrypt(self._state, plaintext, ciphertext,
                                         len(plaintext))
        if result:
            raise ValueError("Error %X while encrypting in CTR mode" % result)
        return ciphertext.raw

    def decrypt(self, ciphertext):
        """Decrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have decrypted a message
        you cannot decrypt (or encrypt) another message with the same
        object.

        The data to decrypt can be broken up in two or
        more pieces and `decrypt` can be called multiple times.

        That is, the statement:

            >>> c.decrypt(a) + c.decrypt(b)

        is equivalent to:

             >>> c.decrypt(a+b)

        This function does not remove any padding from the plaintext.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt.
            It can be of any length.

        :Return: the decrypted data (byte string).
        """

        plaintext = create_string_buffer(len(ciphertext))
        result = raw_ctr_lib.CTR_decrypt(self._state, ciphertext, plaintext,
                                         len(ciphertext))
        if result:
            raise ValueError("Error %X while decrypting in CTR mode" % result)
        return plaintext.raw

    def __del__(self):
        if self._state:
            raw_ctr_lib.CTR_stop_operation(self._state)
            self._state = None


def _create_ctr_cipher(factory, **kwargs):

    cipher_state, stop_op = factory._create_base_cipher(kwargs)
    try:

        try:
            counter = kwargs.pop("counter")
        except KeyError:
            # Require by unit test
            raise TypeError("Missing 'counter' parameter for CTR mode")

        # 'counter' used to be a callable object, but now it is
        # just a dictionary for backward compatibility.
        counter_len = counter.pop("counter_len")
        prefix = counter.pop("prefix")
        suffix = counter.pop("suffix")
        initial_value = counter.pop("initial_value")
        little_endian = counter.pop("little_endian")

        # Compute initial counter block
        words = []
        while initial_value > 0:
            words.append(bchr(initial_value & 255))
            initial_value >>= 8
        words += [bchr(0)] * max(0, counter_len - len(words))
        if not little_endian:
            words.reverse()
        initial_counter_block = prefix + b("").join(words) + suffix

        if kwargs:
            raise ValueError("Unknown parameters for CTR mode: %s"
                             % str(kwargs))
        return RawCtrMode(cipher_state, initial_counter_block,
                          len(prefix), counter_len, little_endian)
    except:
        stop_op(cipher_state)
        raise
