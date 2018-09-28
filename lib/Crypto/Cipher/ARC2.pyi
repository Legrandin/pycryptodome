from typing import Union, Any

from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher._mode_cfb import CfbMode
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_ofb import OfbMode
from Crypto.Cipher._mode_openpgp import OpenPgpMode

ARC2Mode = int

MODE_ECB: ARC2Mode
MODE_CBC: ARC2Mode
MODE_CFB: ARC2Mode
MODE_OFB: ARC2Mode
MODE_CTR: ARC2Mode
MODE_OPENPGP: ARC2Mode
MODE_EAX: ARC2Mode

def new(key: Union[bytes, bytearray, memoryview], mode: ARC2Mode, *args: Any, **kwargs: Any) -> Union[CtrMode, CbcMode, EaxMode, EcbMode, OfbMode, CfbMode, OpenPgpMode]: ...

block_size: int
key_size: range
