from typing import Optional, Callable

from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature.pss import Hash, _PSS_SigScheme


class PSS_SigScheme(_PSS_SigScheme):
    def verify(self, msg_hash: Hash, signature: bytes) -> bool: ...


def new(rsa_key: RsaKey, mgfunc: Optional[Callable]=None, saltLen: Optional[int]=None, randfunc: Optional[Callable]=None) -> PSS_SigScheme: ...
