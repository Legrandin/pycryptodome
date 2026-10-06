"""Hash and MAC objects shared by several threads.

Using the same object from several threads at once is not supported (the
result is undefined), but it must never corrupt memory or crash the process.
Separate objects must be fully independent.
"""

import threading

import pytest

from Crypto.Cipher import ChaCha20
from Crypto.Hash import (
    MD2,
    MD4,
    MD5,
    RIPEMD160,
    SHA1,
    SHA3_256,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHAKE128,
    BLAKE2b,
    BLAKE2s,
    Poly1305,
    TurboSHAKE128,
)

FACTORIES = {
    "MD2": MD2.new,
    "MD4": MD4.new,
    "MD5": MD5.new,
    "SHA1": SHA1.new,
    "SHA224": SHA224.new,
    "SHA256": SHA256.new,
    "SHA384": SHA384.new,
    "SHA512": SHA512.new,
    "RIPEMD160": RIPEMD160.new,
    "BLAKE2b": lambda: BLAKE2b.new(digest_bytes=64),
    "BLAKE2s": lambda: BLAKE2s.new(digest_bytes=32),
    "SHA3_256": lambda: SHA3_256.new(update_after_digest=True),
    "SHAKE128": SHAKE128.new,
    "TurboSHAKE128": TurboSHAKE128.new,
    "Poly1305": lambda: Poly1305.new(key=b"k" * 32, cipher=ChaCha20, nonce=b"n" * 12),
}


def _run_threads(target, n_threads=8):
    errors = []

    def wrapper(i):
        try:
            target(i)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=wrapper, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise errors[0]


@pytest.mark.parametrize("name", sorted(FACTORIES))
def test_shared_object_does_not_crash(name):
    obj = FACTORIES[name]()
    chunks = [bytes(range(n)) for n in (1, 15, 17, 63, 65, 129, 200)]
    # Poly1305 does not accept update() after digest()
    update_only = name == "Poly1305"

    def hammer(i):
        for j in range(3000):
            try:
                if update_only or j % 10:
                    obj.update(chunks[(i + j) % len(chunks)])
                elif hasattr(obj, "read"):
                    obj.read(33)
                else:
                    obj.digest()
            except TypeError:
                pass  # e.g. update() after read()

    _run_threads(hammer)


def test_md4_independent_objects():
    # MD4 used to share a static buffer between all objects, so threads
    # computing digests of different objects got wrong results
    data = [bytes([i]) * (100 + 37 * i) for i in range(8)]
    expected = [MD4.new(d).digest() for d in data]

    def check(i):
        h = MD4.new(data[i])
        wrong = sum(h.digest() != expected[i] for _ in range(20000))
        assert wrong == 0

    _run_threads(check)
