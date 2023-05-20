from typing import Union, Tuple, overload

class Salsa20Cipher:
    nonce: bytes
    block_size: int
    key_size: int

    def __init__(self,
                 key: bytes | bytearray,
                 nonce: bytes | bytearray) -> None: ...
    @overload
    def encrypt(self, plaintext: bytes | bytearray) -> bytes: ...
    @overload
    def encrypt(self, plaintext: bytes | bytearray, output: Union[bytearray, memoryview]) -> None: ...
    @overload
    def decrypt(self, plaintext: bytes | bytearray) -> bytes: ...
    @overload
    def decrypt(self, plaintext: bytes | bytearray, output: Union[bytearray, memoryview]) -> None: ...

def new(key: bytes | bytearray, nonce: bytes | bytearray | None = ...) -> Salsa20Cipher: ...

block_size: int
key_size: Tuple[int, int]
