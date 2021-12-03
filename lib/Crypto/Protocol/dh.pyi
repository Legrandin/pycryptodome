from typing import TypedDict, Callable
from typing_extensions import Unpack

from Crypto.PublicKey.ECC import EccKey

PRF = Callable[[bytes|bytearray|memoryview], bytes]

class RequestParams(TypedDict):
    kdf: PRF
    static_priv: EccKey
    static_pub: EccKey
    eph_priv: EccKey
    eph_pub: EccKey

def key_agreement(**kwargs: Unpack[RequestParams]) -> bytes: ...
