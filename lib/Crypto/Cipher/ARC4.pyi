from typing import Any, Union, Iterable, ByteString

class ARC4Cipher:
    block_size: int
    key_size: int

    def __init__(self, key: ByteString, *args: Any, **kwargs: Any) -> None: ...
    def encrypt(self, plaintext: ByteString) -> bytes: ...
    def decrypt(self, ciphertext: ByteString) -> bytes: ...

def new(key: ByteString, drop : int = ...) -> ARC4Cipher: ...

block_size: int
key_size: Iterable[int]
