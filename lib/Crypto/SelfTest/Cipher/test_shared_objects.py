"""Stream ciphers shared by several threads.

Using the same cipher object from several threads at once is not supported
(the output is undefined, and the key stream may be reused), but it must
never corrupt memory or crash the process.
"""

import ctypes
import threading

import pytest

from Crypto.Cipher import AES, ChaCha20, Salsa20

FACTORIES = {
    "AES-CTR": lambda: AES.new(b"k" * 16, AES.MODE_CTR, nonce=b"n" * 8),
    "ChaCha20": lambda: ChaCha20.new(key=b"k" * 32, nonce=b"n" * 8),
    "ChaCha20-IETF": lambda: ChaCha20.new(key=b"k" * 32, nonce=b"n" * 12),
    "XChaCha20": lambda: ChaCha20.new(key=b"k" * 32, nonce=b"n" * 24),
    "Salsa20": lambda: Salsa20.new(key=b"k" * 32, nonce=b"n" * 8),
}


@pytest.mark.parametrize("name", sorted(FACTORIES))
def test_shared_cipher_does_not_crash(name):
    cipher = FACTORIES[name]()
    chunks = [bytes(n) for n in (1, 15, 17, 63, 65, 129, 1000)]
    errors = []

    def hammer(i):
        try:
            for j in range(5000):
                if j % 50 == 0 and hasattr(cipher, "seek"):
                    cipher.seek(j * 7)
                else:
                    cipher.encrypt(chunks[(i + j) % len(chunks)])
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=hammer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


# The start of the C state of each cipher, up to the position in the key stream


class _ChaCha20State(ctypes.Structure):
    _fields_ = [("h", ctypes.c_uint32 * 16), ("nonceSize", ctypes.c_size_t), ("usedKeyStream", ctypes.c_uint)]


class _Salsa20State(ctypes.Structure):
    _fields_ = [
        ("input", ctypes.c_uint32 * 16),
        ("block", ctypes.c_uint8 * 64),
        ("blockindex", ctypes.c_uint8),
    ]


class _CtrState(ctypes.Structure):
    _fields_ = [
        ("cipher", ctypes.c_void_p),
        ("block_len", ctypes.c_size_t),
        ("counter_blocks", ctypes.c_void_p),
        ("counter_offset", ctypes.c_size_t),
        ("counter_len", ctypes.c_size_t),
        ("add", ctypes.c_void_p),
        ("keystream", ctypes.c_void_p),
        ("used_ks", ctypes.c_size_t),
    ]


def _c_state(cipher, struct_type):
    from Crypto.Util import _raw_api

    ptr = cipher._state.get()
    if _raw_api.backend == "cffi":
        address = int(_raw_api.ffi.cast("uintptr_t", ptr))
    else:
        address = ptr.value
    return struct_type.from_address(address)


@pytest.mark.parametrize(
    "name, struct_type, field, bad_value",
    [
        ("AES-CTR", _CtrState, "used_ks", 1 << 20),
        ("ChaCha20", _ChaCha20State, "usedKeyStream", 1 << 20),
        ("ChaCha20-IETF", _ChaCha20State, "usedKeyStream", 65),
        ("XChaCha20", _ChaCha20State, "usedKeyStream", 1000),
        ("Salsa20", _Salsa20State, "blockindex", 200),
    ],
)
def test_inconsistent_position_is_rejected(name, struct_type, field, bad_value):
    # The state that a race could leave behind: the position in the key
    # stream is beyond its end. It must be rejected, never used to read memory.
    cipher = FACTORIES[name]()
    cipher.encrypt(b"x" * 10)
    setattr(_c_state(cipher, struct_type), field, bad_value)
    with pytest.raises(ValueError):
        cipher.encrypt(b"x" * 100)
