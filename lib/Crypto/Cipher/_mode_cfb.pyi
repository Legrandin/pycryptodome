from typing import Union

from Crypto.common import SmartPointer

__all__ = ['CfbMode']


class CfbMode(object):
    block_size: int
    iv: Union[bytes, bytearray, memoryview]
    IV: Union[bytes, bytearray, memoryview]

    def __init__(self, block_cipher: SmartPointer, iv: Union[bytes, bytearray, memoryview], segment_size: int) -> None: ...
    def encrypt(self, plaintext: Union[bytes, bytearray, memoryview]) -> bytes: ...
    def decrypt(self, ciphertext: Union[bytes, bytearray, memoryview]) -> bytes: ...