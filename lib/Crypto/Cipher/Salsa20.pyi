from typing import Union, Tuple


class Salsa20Cipher:
    nonce: Union[bytes, bytearray, memoryview]
    block_size: int
    key_size: int

    def __init__(self, key: bytes, nonce: Union[bytes, bytearray, memoryview]) -> None: ...
    def encrypt(self, plaintext: Union[bytes, bytearray, memoryview]) -> bytes: ...
    def decrypt(self, ciphertext: Union[bytes, bytearray, memoryview]) -> bytes: ...

def new(key: Union[bytes, bytearray, memoryview], nonce: Union[bytes, bytearray, memoryview]) -> Salsa20Cipher: ...

block_size: int
key_size: Tuple[int, int]

