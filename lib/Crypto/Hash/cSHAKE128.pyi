from typing import Union, Optional

Buffer = Union[bytes, bytearray, memoryview]

class cSHAKE_XOF(object):
    oid: str
    def __init__(self,
                 data:     Optional[Buffer] = ...,
                 function: Optional[bytes] = ...,
                 custom:   Optional[bytes] = ...) -> None: ...
    def update(self, data: Buffer) -> cSHAKE_XOF: ...
    def read(self, length: int) -> bytes: ...

def new(data:     Optional[Buffer] = ...,
        custom:   Optional[bytes] = ...) -> cSHAKE_XOF: ...
