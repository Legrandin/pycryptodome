from Crypto.PublicKey.RSA import RsaKey

from Crypto.Signature.pkcs1_15 import Hash, _PKCS115_SigScheme


class PKCS115_SigScheme(_PKCS115_SigScheme):
    def verify(self, msg_hash: Hash, signature: bytes) -> bool: ...


def new(rsa_key: RsaKey) -> PKCS115_SigScheme: ...
