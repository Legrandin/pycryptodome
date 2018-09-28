from typing import Union, Any

from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher._mode_cfb import CfbMode
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_ofb import OfbMode
from Crypto.Cipher._mode_openpgp import OpenPgpMode

CASTMode = int

MODE_ECB: CASTMode
MODE_CBC: CASTMode
MODE_CFB: CASTMode
MODE_OFB: CASTMode
MODE_CTR: CASTMode
MODE_OPENPGP: CASTMode
MODE_EAX: CASTMode

def new(key: Union[bytes, bytearray, memoryview], mode: CASTMode, *args: Any, **kwargs: Any) -> Union[CtrMode, EaxMode, OpenPgpMode, CbcMode, CfbMode, OfbMode, EcbMode]: ...

block_size: int
key_size = range
