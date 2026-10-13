#
#  SelfTest/Cipher/test_message_too_long.py: Self-test for MessageTooLongError
#
# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import sys

import pytest

from Crypto import MessageTooLongError
from Crypto.Cipher import AES, ChaCha20, Salsa20, _mode_gcm
from Crypto.Cipher._mode_ccm import CCMMessageTooLongError

KEY = bytes(range(16))


def test_hierarchy():
    # For backward compatibility: CCM raised a ValueError, CTR and Salsa20 an OverflowError
    assert issubclass(MessageTooLongError, ValueError)
    assert issubclass(MessageTooLongError, OverflowError)
    assert CCMMessageTooLongError is MessageTooLongError


class FakeLength:
    """Data whose length is checked before any byte of it is read."""

    def __init__(self, length):
        self._length = length

    def __len__(self):
        return self._length


class TestCCM:
    def test_msg_len(self):
        # With a nonce of 13 bytes, the message length takes 2 bytes
        AES.new(KEY, AES.MODE_CCM, nonce=bytes(13), msg_len=2**16 - 1)
        with pytest.raises(MessageTooLongError):
            AES.new(KEY, AES.MODE_CCM, nonce=bytes(13), msg_len=2**16)

    def test_longer_than_declared(self):
        cipher = AES.new(KEY, AES.MODE_CCM, nonce=bytes(11), msg_len=10)
        cipher.encrypt(bytes(10))
        with pytest.raises(MessageTooLongError):
            cipher.encrypt(bytes(1))

        cipher = AES.new(KEY, AES.MODE_CCM, nonce=bytes(11), msg_len=10)
        with pytest.raises(MessageTooLongError):
            cipher.decrypt(bytes(11))

    def test_undeclared_too_long_for_nonce(self):
        cipher = AES.new(KEY, AES.MODE_CCM, nonce=bytes(13))
        with pytest.raises(MessageTooLongError):
            cipher.encrypt(bytes(2**16))

    def test_assoc_data_longer_than_declared(self):
        cipher = AES.new(KEY, AES.MODE_CCM, nonce=bytes(11), assoc_len=4)
        cipher.update(bytes(4))
        with pytest.raises(MessageTooLongError):
            cipher.update(bytes(1))


class TestGCM:
    # The limits (64 GiB of data) are too large to reach: start close to them

    @pytest.mark.parametrize("method", ["encrypt", "decrypt"])
    def test_data(self, method):
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=bytes(12))
        cipher._msg_len = _mode_gcm._MAX_MSG_LEN - 1
        with pytest.raises(MessageTooLongError):
            getattr(cipher, method)(bytes(2))
        # Nothing was processed: the last byte can still go
        getattr(cipher, method)(bytes(1))
        with pytest.raises(MessageTooLongError):
            getattr(cipher, method)(bytes(1))

    def test_assoc_data(self):
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=bytes(12))
        cipher._auth_len = _mode_gcm._MAX_AAD_LEN - 1
        with pytest.raises(MessageTooLongError):
            cipher.update(bytes(2))
        cipher.update(bytes(1))

    def test_limits(self):
        # NIST SP 800-38D: 2**39 - 256 bits of data, 2**64 - 1 bits of AAD
        assert _mode_gcm._MAX_MSG_LEN * 8 == 2**39 - 256
        assert _mode_gcm._MAX_AAD_LEN * 8 <= 2**64 - 1 < (_mode_gcm._MAX_AAD_LEN + 1) * 8


class TestCTR:
    @pytest.mark.parametrize("method", ["encrypt", "decrypt"])
    def test_counter_wraps(self, method):
        # A nonce of 15 bytes leaves a counter of 1 byte: 256 blocks
        cipher = AES.new(KEY, AES.MODE_CTR, nonce=bytes(15))
        getattr(cipher, method)(bytes(256 * 16))
        with pytest.raises(MessageTooLongError):
            getattr(cipher, method)(bytes(1))


class TestKeyWrap:
    # On a 32-bit Python, len() cannot return 2**32 (OverflowError), and no
    # buffer can be that long: the limit of KW and KWP cannot be reached
    @pytest.mark.skipif(sys.maxsize < 2**32, reason="len() is limited to 2**31 - 1 on 32-bit Python")
    @pytest.mark.parametrize("mode", [AES.MODE_KW, AES.MODE_KWP])
    def test_too_long(self, mode):
        cipher = AES.new(KEY, mode)
        with pytest.raises(MessageTooLongError):
            cipher.seal(FakeLength(2**32))


class TestSalsa20:
    @pytest.mark.parametrize("method", ["encrypt", "decrypt"])
    def test_end_of_key_stream(self, method):
        cipher = Salsa20.new(key=bytes(32), nonce=bytes(8))
        cipher.seek(2**70 - 1)
        getattr(cipher, method)(bytes(1))
        with pytest.raises(MessageTooLongError):
            getattr(cipher, method)(bytes(1))


def _chacha20_block(key, nonce, counter):
    """Reference ChaCha20 block function (RFC 8439, and the original
    version with a 64-bit counter and a 64-bit nonce)."""

    def rotl(v, c):
        return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF

    def quarter(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotl(x[b] ^ x[c], 7)

    def words(b):
        return [int.from_bytes(b[i : i + 4], "little") for i in range(0, len(b), 4)]

    if len(nonce) == 8:
        ctr = [counter & 0xFFFFFFFF, counter >> 32]
    else:
        ctr = [counter]
    state = words(b"expand 32-byte k") + words(key) + ctr + words(nonce)
    x = list(state)
    for _ in range(10):
        quarter(x, 0, 4, 8, 12)
        quarter(x, 1, 5, 9, 13)
        quarter(x, 2, 6, 10, 14)
        quarter(x, 3, 7, 11, 15)
        quarter(x, 0, 5, 10, 15)
        quarter(x, 1, 6, 11, 12)
        quarter(x, 2, 7, 8, 13)
        quarter(x, 3, 4, 9, 14)
    return b"".join(((a + b) & 0xFFFFFFFF).to_bytes(4, "little") for a, b in zip(x, state))


class TestChaCha20:
    key = bytes(range(32))

    @pytest.mark.parametrize("nonce_len, blocks", [(8, 2**64), (12, 2**32)])
    def test_reference(self, nonce_len, blocks):
        nonce = bytes(range(nonce_len))
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        assert cipher.encrypt(bytes(128)) == _chacha20_block(self.key, nonce, 0) + _chacha20_block(
            self.key, nonce, 1
        )

    @pytest.mark.parametrize("nonce_len, blocks", [(8, 2**64), (12, 2**32)])
    @pytest.mark.parametrize("method", ["encrypt", "decrypt"])
    def test_end_of_key_stream(self, method, nonce_len, blocks):
        nonce = bytes(range(nonce_len))
        ref = _chacha20_block(self.key, nonce, blocks - 2) + _chacha20_block(self.key, nonce, blocks - 1)

        # The last two blocks, up to the last byte
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        cipher.seek(64 * (blocks - 2) + 5)
        assert getattr(cipher, method)(bytes(64)) == ref[5:69]
        assert getattr(cipher, method)(bytes(59)) == ref[69:]

        # No more, and no key stream from block 0 if the caller carries on
        for _ in range(3):
            with pytest.raises(MessageTooLongError):
                getattr(cipher, method)(bytes(1))
        assert getattr(cipher, method)(b"") == b""

    @pytest.mark.parametrize("nonce_len, blocks", [(8, 2**64), (12, 2**32)])
    def test_beyond_the_end_in_one_call(self, nonce_len, blocks):
        # Nothing is encrypted, and the position does not change
        nonce = bytes(range(nonce_len))
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        cipher.seek(64 * (blocks - 1) + 10)
        output = bytearray(55)
        with pytest.raises(MessageTooLongError):
            cipher.encrypt(bytes(55), output=output)
        assert output == bytearray(55)
        assert cipher.encrypt(bytes(54)) == _chacha20_block(self.key, nonce, blocks - 1)[10:]

    @pytest.mark.parametrize("method", ["encrypt", "decrypt"])
    def test_xchacha20(self, method):
        # The nonce of 24 bytes leaves a 32-bit block counter
        cipher = ChaCha20.new(key=self.key, nonce=bytes(24))
        cipher.seek(64 * (2**32 - 1))
        getattr(cipher, method)(bytes(64))
        with pytest.raises(MessageTooLongError):
            getattr(cipher, method)(bytes(1))

    @pytest.mark.parametrize("nonce_len, blocks", [(8, 2**64), (12, 2**32)])
    def test_seek_after_the_end(self, nonce_len, blocks):
        nonce = bytes(range(nonce_len))
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        cipher.seek(64 * (blocks - 1))
        cipher.encrypt(bytes(64))
        with pytest.raises(MessageTooLongError):
            cipher.encrypt(bytes(1))
        cipher.seek(0)
        assert cipher.encrypt(bytes(64)) == _chacha20_block(self.key, nonce, 0)
