from typing import Any
from typing import Union


class ARC4Cipher:
    block_size: int
    key_size: int

    def __init__(self, key: Union[bytes, bytearray, memoryview], *args: Any, **kwargs: Any) -> None: ...
    def encrypt(self, plaintext: Union[bytes, bytearray, memoryview]) -> bytes: ...
    def decrypt(self, ciphertext: Union[bytes, bytearray, memoryview]) -> bytes: ...

def new(key: Union[bytes, bytearray, memoryview], *args: Any, **kwargs: Any) -> ARC4Cipher: ...

block_size: int
key_size: range
