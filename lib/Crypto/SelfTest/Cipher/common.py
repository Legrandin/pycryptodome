#
#  SelfTest/Hash/common.py: Common code for Crypto.SelfTest.Hash
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


"""Self-testing for PyCrypto hash modules"""

from binascii import a2b_hex, b2a_hex

import pytest


class _NoDefault:
    pass  # sentinel object


def _extract(d, k, default=_NoDefault):
    """Get an item from a dictionary, and remove it from the dictionary."""
    try:
        retval = d[k]
    except KeyError:
        if default is _NoDefault:
            raise
        return default
    del d[k]
    return retval


class _Vector:
    """A test vector for a cipher module, with all data in hexadecimal"""

    def __init__(self, module, params):
        self.module = module

        # Extract the parameters
        params = params.copy()
        self.description = _extract(params, "description")
        self.key = _extract(params, "key").encode("latin-1")
        self.plaintext = _extract(params, "plaintext").encode("latin-1")
        self.ciphertext = _extract(params, "ciphertext").encode("latin-1")
        _extract(params, "module_name", None)
        self.assoc_data = _extract(params, "assoc_data", None)
        self.mac = _extract(params, "mac", None)
        if self.assoc_data:
            self.mac = self.mac.encode("latin-1")

        mode = _extract(params, "mode", None)

        if mode is not None:
            # Block cipher
            self.mode = getattr(self.module, "MODE_" + mode)

            self.iv = _extract(params, "iv", None)
            if self.iv is None:
                self.iv = _extract(params, "nonce", None)
            if self.iv is not None:
                self.iv = self.iv.encode("latin-1")

        else:
            # Stream cipher
            self.mode = None
            self.iv = _extract(params, "iv", None)
            if self.iv is not None:
                self.iv = self.iv.encode("latin-1")

        self.extra_params = params

    def new(self):
        params = self.extra_params.copy()
        key = a2b_hex(self.key)

        old_style = []
        if self.mode is not None:
            old_style = [self.mode]
        if self.iv is not None:
            old_style += [a2b_hex(self.iv)]

        return self.module.new(key, *old_style, **params)


def _encrypt_decrypt(vector, wrap):
    """Encrypt the plaintext and decrypt the ciphertext of a vector,
    passing all data through the given wrapper (e.g. bytearray)"""

    plaintext = a2b_hex(vector.plaintext)
    ciphertext = a2b_hex(vector.ciphertext)
    assoc_data = []
    if vector.assoc_data:
        assoc_data = [wrap(a2b_hex(x.encode("latin-1"))) for x in vector.assoc_data]

    cipher = vector.new()
    decipher = vector.new()

    # Only AEAD modes
    for comp in assoc_data:
        cipher.update(comp)
        decipher.update(comp)

    ct = b2a_hex(cipher.encrypt(wrap(plaintext)))
    pt = b2a_hex(decipher.decrypt(wrap(ciphertext)))
    return cipher, decipher, ct, pt


def _check_vector(vector):
    #
    # Repeat the same encryption or decryption twice and verify
    # that the result is always the same
    #
    ct = None
    pt = None
    for _i in range(2):
        cipher, decipher, ctX, ptX = _encrypt_decrypt(vector, bytes)
        if ct:
            assert ct == ctX
            assert pt == ptX
        ct, pt = ctX, ptX

    assert vector.ciphertext == ct  # encrypt
    assert vector.plaintext == pt  # decrypt

    if vector.mac:
        mac = b2a_hex(cipher.digest())
        assert vector.mac == mac
        decipher.verify(a2b_hex(vector.mac))


def _check_vector_wrapped(vector, wrap):
    """Verify we can use the given type (e.g. bytearray) for encrypting and decrypting"""

    cipher, decipher, ct, pt = _encrypt_decrypt(vector, wrap)

    assert vector.ciphertext == ct  # encrypt
    assert vector.plaintext == pt  # decrypt

    if vector.mac:
        mac = b2a_hex(cipher.digest())
        assert vector.mac == mac
        decipher.verify(wrap(a2b_hex(vector.mac)))


def _check_vector_streaming(vector):
    """The cipher should behave like a stream cipher"""

    plaintext = a2b_hex(vector.plaintext)
    ciphertext = a2b_hex(vector.ciphertext)

    # Test counter mode encryption, 3 bytes at a time
    ct3 = []
    cipher = vector.new()
    for i in range(0, len(plaintext), 3):
        ct3.append(cipher.encrypt(plaintext[i : i + 3]))
    ct3 = b2a_hex(b"".join(ct3))
    assert vector.ciphertext == ct3  # encryption (3 bytes at a time)

    # Test counter mode decryption, 3 bytes at a time
    pt3 = []
    cipher = vector.new()
    for i in range(0, len(ciphertext), 3):
        pt3.append(cipher.encrypt(ciphertext[i : i + 3]))
    pt3 = b2a_hex(b"".join(pt3))
    assert vector.plaintext == pt3  # decryption (3 bytes at a time)


def _make_params(i, row, module_name, default_mode):
    # Build the "params" dictionary with
    # - plaintext
    # - ciphertext
    # - key
    # - mode (for block ciphers, default is ECB)
    # - (optionally) description
    # - (optionally) any other parameter that this cipher mode requires
    params = {}
    if len(row) == 3:
        (params["plaintext"], params["ciphertext"], params["key"]) = row
    elif len(row) == 4:
        (params["plaintext"], params["ciphertext"], params["key"], params["description"]) = row
    elif len(row) == 5:
        (
            params["plaintext"],
            params["ciphertext"],
            params["key"],
            params["description"],
            extra_params,
        ) = row
        params.update(extra_params)
    else:
        raise AssertionError("Unsupported tuple size %d" % (len(row),))

    if default_mode is not None and "mode" not in params:
        params["mode"] = default_mode

    # Build the display-name for the test
    p2 = params.copy()
    p_key = _extract(p2, "key")
    p_plaintext = _extract(p2, "plaintext")
    _extract(p2, "ciphertext")
    p_mode = _extract(p2, "mode", None)
    p_description = _extract(p2, "description", None)

    if p_description is not None:
        description = p_description
    elif p_mode in (None, "ECB") and not p2:
        description = "p=%s, k=%s" % (p_plaintext, p_key)
    else:
        description = "p=%s, k=%s, %r" % (p_plaintext, p_key, p2)
    params["description"] = "%s #%d: %s" % (module_name, i + 1, description)
    params["module_name"] = module_name
    return params


def make_block_tests(module, module_name, test_data, additional_params={}):
    """Return a pytest test class for a block cipher module,
    with one test for each row in test_data"""

    all_params = []
    for i, row in enumerate(test_data):
        params = _make_params(i, row, module_name, "ECB")
        params.update(additional_params)
        all_params.append(params)
    vectors = [_Vector(module, params) for params in all_params]
    ids = [vector.description for vector in vectors]

    first = all_params[0]
    key = a2b_hex(first["key"].encode("latin-1"))

    class BlockCipherTests:
        def test_roundtrip(self):
            """.decrypt() output of .encrypt() should not be garbled"""
            plaintext = 100 * first["plaintext"].encode("latin-1")
            ciphertext = module.new(key, module.MODE_ECB).encrypt(plaintext)
            assert plaintext == module.new(key, module.MODE_ECB).decrypt(ciphertext)

        def test_iv_length(self):
            with pytest.raises(TypeError):
                module.new(key, module.MODE_ECB, b"")

        def test_no_default_ecb(self):
            with pytest.raises(TypeError):
                module.new(key)

        def test_bytearray(self):
            _check_vector_wrapped(vectors[0], bytearray)

        def test_block_size(self):
            cipher = module.new(key, module.MODE_ECB)
            assert cipher.block_size == module.block_size

        @pytest.mark.parametrize("vector", vectors, ids=ids)
        def test_vector(self, vector):
            _check_vector(vector)

    return BlockCipherTests


def make_stream_tests(module, module_name, test_data):
    """Return a pytest test class for a stream cipher module,
    with two tests for each row in test_data"""

    vectors = [_Vector(module, _make_params(i, row, module_name, None)) for i, row in enumerate(test_data)]
    ids = [vector.description for vector in vectors]

    class StreamCipherTests:
        def test_bytearray(self):
            _check_vector_wrapped(vectors[0], bytearray)

        def test_memoryview(self):
            _check_vector_wrapped(vectors[0], memoryview)

        @pytest.mark.parametrize("vector", vectors, ids=ids)
        def test_vector(self, vector):
            _check_vector(vector)

        @pytest.mark.parametrize("vector", vectors, ids=ids)
        def test_vector_streaming(self, vector):
            _check_vector_streaming(vector)

    return StreamCipherTests
