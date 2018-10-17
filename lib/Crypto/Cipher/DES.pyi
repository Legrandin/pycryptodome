from typing import Union, Any

from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher._mode_cfb import CfbMode
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_ofb import OfbMode
from Crypto.Cipher._mode_openpgp import OpenPgpMode

DESMode = int

MODE_ECB: DESMode
MODE_CBC: DESMode
MODE_CFB: DESMode
MODE_OFB: DESMode
MODE_CTR: DESMode
MODE_OPENPGP: DESMode
MODE_EAX: DESMode


def new(key: Union[bytes, bytearray, memoryview], mode: DESMode, *args: Any, **kwargs: Any) -> Union[CtrMode, EaxMode, OpenPgpMode, CbcMode, CfbMode, OfbMode, EcbMode]: ...


block_size: int
key_size: int
