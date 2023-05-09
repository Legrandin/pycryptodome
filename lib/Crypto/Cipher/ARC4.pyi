from typing import Any, Iterable

class ARC4Cipher:
    block_size: int
    key_size: int

    def __init__(self, key: bytes | bytearray, *args: Any, **kwargs: Any) -> None: ...
    def encrypt(self, plaintext: bytes | bytearray) -> bytes: ...
    def decrypt(self, ciphertext: bytes | bytearray) -> bytes: ...

def new(key: bytes | bytearray, drop : int = ...) -> ARC4Cipher: ...

block_size: int
key_size: Iterable[int]
