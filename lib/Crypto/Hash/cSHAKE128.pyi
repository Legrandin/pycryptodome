from typing import Union, Optional

Buffer = Union[bytes, bytearray, memoryview]

class cSHAKE128_XOF(object):
    oid: str
    def __init__(self,
                 data:     Optional[Buffer] = ...,
                 function: Optional[bytes] = ...,
                 custom:   Optional[bytes] = ...) -> None: ...
    def update(self, data: Buffer) -> cSHAKE128_XOF: ...
    def read(self, length: int) -> bytes: ...
    def new(self, data: Optional[Buffer] = ...) -> cSHAKE128_XOF: ...

def new(data:     Optional[Buffer] = ...,
        function: Optional[bytes] = ...,
        custom:   Optional[bytes] = ...) -> cSHAKE128_XOF: ...
