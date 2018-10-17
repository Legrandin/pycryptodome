from typing import Union, Any

from Crypto.Hash.BLAKE2b import BLAKE2b_Hash
from Crypto.Hash.BLAKE2s import BLAKE2s_Hash
from Crypto.Hash.CMAC import CMAC
from Crypto.Hash.HMAC import HMAC
from Crypto.Hash.MD2 import MD2Hash
from Crypto.Hash.MD4 import MD4Hash
from Crypto.Hash.MD5 import MD5Hash
from Crypto.Hash.RIPEMD160 import RIPEMD160Hash
from Crypto.Hash.SHA1 import SHA1Hash
from Crypto.Hash.SHA224 import SHA224Hash
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Hash.SHA384 import SHA384Hash
from Crypto.Hash.SHA3_224 import SHA3_224_Hash
from Crypto.Hash.SHA3_256 import SHA3_256_Hash
from Crypto.Hash.SHA3_384 import SHA3_384_Hash
from Crypto.Hash.SHA3_512 import SHA3_512_Hash
from Crypto.Hash.SHA512 import SHA512Hash
from Crypto.Hash.SHAKE128 import SHAKE128_XOF
from Crypto.Hash.SHAKE256 import SHAKE256_XOF
from Crypto.Hash.keccak import Keccak_Hash

SmartPointer = Any

HashAlgorithm = Union[BLAKE2b_Hash, BLAKE2s_Hash, CMAC, HMAC, Keccak_Hash, MD2Hash, MD4Hash, MD5Hash, RIPEMD160Hash,
                      SHA1Hash, SHA224Hash, SHA256Hash, SHA384Hash, SHA512Hash, SHA3_224_Hash, SHA3_256_Hash,
                      SHA3_384_Hash, SHA3_512_Hash, SHAKE128_XOF, SHAKE256_XOF]
