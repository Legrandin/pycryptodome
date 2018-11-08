from typing import Any, Union, Tuple, Optional

from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher._mode_cfb import CfbMode
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_ofb import OfbMode
from Crypto.Cipher._mode_openpgp import OpenPgpMode

AESMode = int

MODE_ECB: AESMode
MODE_CBC: AESMode
MODE_CFB: AESMode
MODE_OFB: AESMode
MODE_CTR: AESMode
MODE_OPENPGP: AESMode
MODE_CCM: AESMode
MODE_EAX: AESMode
MODE_SIV: AESMode
MODE_GCM: AESMode
MODE_OCB: AESMode

def new(__key: Union[bytes, bytearray, memoryview],
        __mode: AESMode,
        iv : Optional[Union[bytes, bytearray, memoryview]],
        nonce : Optional[Union[bytes, bytearray, memoryview]],
        segment_size : Optional[int],
        mac_len : Optional[int],
        msg_len : Optional[int],
        assoc_len : Optional[int],
        initial_value : Optional[int],
        use_aesni : Optional[bool]) -> \
        Union[CtrMode, CbcMode, EaxMode, EcbMode, OfbMode, CfbMode, OpenPgpMode]: ...

block_size: int
key_size: Tuple[int, int, int]
