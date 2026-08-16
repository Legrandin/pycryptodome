from typing import Union
from typing_extensions import TypedDict

Buffer = Union[bytes, bytearray, memoryview]
CounterBuffer = Union[bytes, bytearray]

class CounterParams(TypedDict):
    counter_len: int
    prefix: CounterBuffer
    suffix: Buffer
    initial_value: int
    little_endian: bool

def new(nbits: int, prefix: CounterBuffer=..., suffix: Buffer=..., initial_value: int=1,
        little_endian: bool=False, allow_wraparound: bool=False) -> \
        CounterParams: ...
