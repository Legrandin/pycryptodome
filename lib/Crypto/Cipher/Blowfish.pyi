from typing import Any, Union

from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher._mode_cfb import CfbMode
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_ofb import OfbMode
from Crypto.Cipher._mode_openpgp import OpenPgpMode

BlowfishMode = int

MODE_ECB: BlowfishMode
MODE_CBC: BlowfishMode
MODE_CFB: BlowfishMode
MODE_OFB: BlowfishMode
MODE_CTR: BlowfishMode
MODE_OPENPGP: BlowfishMode
MODE_EAX: BlowfishMode

def new(key: Union[bytes, bytearray, memoryview], mode: BlowfishMode, *args: Any, **kwargs: Any) -> Union[CtrMode, EaxMode, OpenPgpMode, CbcMode, CfbMode, OfbMode, EcbMode]: ...

block_size: int
key_size: range
