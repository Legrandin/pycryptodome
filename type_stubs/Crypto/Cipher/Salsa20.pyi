from typing import Union, Tuple, Optional


class Salsa20Cipher:
    nonce: Union[bytes, bytearray, memoryview]
    block_size: int
    key_size: int

    def __init__(self, key: bytes, nonce: Union[bytes, bytearray, memoryview]) -> None: ...
    def encrypt(self, plaintext: Union[bytes, bytearray, memoryview]) -> bytes: ...
    def decrypt(self, ciphertext: Union[bytes, bytearray, memoryview]) -> bytes: ...

def new(key: Union[bytes, bytearray, memoryview], nonce: Optional[Union[bytes, bytearray, memoryview]]=None) -> Salsa20Cipher: ...

block_size: int
key_size: Tuple[int, int]

