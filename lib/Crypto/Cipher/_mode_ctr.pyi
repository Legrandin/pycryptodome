from typing import Union

from Crypto.common import SmartPointer

__all__ = ['CtrMode']

class CtrMode(object):
    nonce: bytes
    block_size: int
    def __init__(self, block_cipher: SmartPointer, initial_counter_block: Union[bytes, bytearray, memoryview],
                 prefix_len: int, counter_len: int, little_endian: bool) -> None: ...
    def encrypt(self, plaintext: Union[bytes, bytearray, memoryview]) -> bytes: ...
    def decrypt(self, ciphertext: Union[bytes, bytearray, memoryview]) -> bytes: ...