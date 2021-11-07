from typing import Union

from .KMAC128 import KMAC_Hash

Buffer = Union[bytes, bytearray, memoryview]

def new(key: Buffer,
        data: Buffer = ...,
	    digest_bytes: int = ...,
	    digest_bits: int = ...,
        custom: Buffer = ...) -> KMAC_Hash: ...
