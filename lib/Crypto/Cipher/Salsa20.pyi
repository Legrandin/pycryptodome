from typing import Union, Tuple, Optional, overload, ByteString, Optional

class Salsa20Cipher:
    nonce: bytes
    block_size: int
    key_size: int

    def __init__(self,
                 key: ByteString,
                 nonce: ByteString) -> None: ...
    @overload
    def encrypt(self, plaintext: ByteString) -> bytes: ...
    @overload
    def encrypt(self, plaintext: ByteString, output: Union[bytearray, memoryview]) -> None: ...
    @overload
    def decrypt(self, plaintext: ByteString) -> bytes: ...
    @overload
    def decrypt(self, plaintext: ByteString, output: Union[bytearray, memoryview]) -> None: ...

def new(key: ByteString, nonce: Optional[ByteString] = ...) -> Salsa20Cipher: ...

block_size: int
key_size: Tuple[int, int]

