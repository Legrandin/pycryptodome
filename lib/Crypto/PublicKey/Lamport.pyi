from typing import Tuple, ByteString, Optional, Union, Callable, Generator, Literal

class LamportKey(object):
    def __init__(self, key: Tuple[Tuple[bytes, bytes]], is_private: bool, h: Callable[[ByteString], bytes], used: bool=False) -> None: ...
    def _sign(self, message: ByteString) -> Tuple[bytes, ...]: ...
    def sign(self, message: ByteString) -> Tuple[bytes, ...]: ...
    def _verify(self, message: ByteString) -> Tuple[bytes, ...]: ...
    def verify(self, message: ByteString) -> Tuple[bytes, ...]: ...
    def has_private(self) -> bool: ...
    def publickey(self) -> LamportKey: ...

def generate(bits: int, onewayfunc: Optional[Union[str, Callable[[ByteString], bytes]]]="2.16.840.1.101.3.4.2.8")) -> LamportKey: ...
def construct(key=Tuple[Tuple[bytes, bytes]], is_private: bool, onewayfunc: Optional[Union[str, Callable[[ByteString], bytes]]]="2.16.840.1.101.3.4.2.8"), used: bool=False) -> LamportKey: ...
def _s2p(Callable[[ByteString], bytes], Tuple[Tuple[bytes, bytes]]) -> Tuple[Tuple[bytes, bytes]]: ...
def _iterbits(ByteString) -> Generator[Literal[0, 1], None, None]: ...