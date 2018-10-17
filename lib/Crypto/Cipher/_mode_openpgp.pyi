from types import ModuleType
from typing import Union, Any

__all__ = ['OpenPgpMode']

class OpenPgpMode(object):
    block_size: int
    iv: Union[bytes, bytearray, memoryview]
    IV: Union[bytes, bytearray, memoryview]
    def __init__(self, factory: ModuleType, key: Union[bytes, bytearray, memoryview], iv: Union[bytes, bytearray, memoryview], cipher_params: Any) -> None: ...
    def encrypt(self, plaintext: Union[bytes, bytearray, memoryview]) -> bytes: ...
    def decrypt(self, ciphertext: Union[bytes, bytearray, memoryview]) -> bytes: ...
