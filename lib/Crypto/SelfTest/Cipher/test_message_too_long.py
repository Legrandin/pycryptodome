#
#  SelfTest/Cipher/test_message_too_long.py: Self-test for MessageTooLongError
#
# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

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


class TestChaCha20:
    @pytest.mark.parametrize("nonce_len, blocks", [(8, 2**64), (12, 2**32)])
    @pytest.mark.parametrize("method", ["encrypt", "decrypt"])
    def test_end_of_key_stream(self, method, nonce_len, blocks):
        cipher = ChaCha20.new(key=bytes(32), nonce=bytes(nonce_len))
        cipher.seek(64 * (blocks - 2))
        getattr(cipher, method)(bytes(64))
        with pytest.raises(MessageTooLongError):
            getattr(cipher, method)(bytes(65))
