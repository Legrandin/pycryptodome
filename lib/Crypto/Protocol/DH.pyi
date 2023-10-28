from typing import TypedDict, Callable, TypeVar, Generic
from typing_extensions import Unpack, NotRequired

from Crypto.PublicKey.ECC import EccKey

T = TypeVar('T')

class RequestParams(TypedDict, Generic[T]):
    kdf: Callable[[bytes|bytearray|memoryview], T]
    static_priv: NotRequired[EccKey]
    static_pub: NotRequired[EccKey]
    eph_priv: NotRequired[EccKey]
    eph_pub: NotRequired[EccKey]

def key_agreement(**kwargs: Unpack[RequestParams[T]]) -> T: ...
