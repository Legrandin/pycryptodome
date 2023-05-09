from typing import Union, Dict, Iterable

from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher._mode_cfb import CfbMode
from Crypto.Cipher._mode_ofb import OfbMode
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Cipher._mode_openpgp import OpenPgpMode
from Crypto.Cipher._mode_eax import EaxMode

ARC2Mode = int

MODE_ECB: ARC2Mode
MODE_CBC: ARC2Mode
MODE_CFB: ARC2Mode
MODE_OFB: ARC2Mode
MODE_CTR: ARC2Mode
MODE_OPENPGP: ARC2Mode
MODE_EAX: ARC2Mode

def new(key: bytes | bytearray,
        mode: ARC2Mode,
        iv : bytes | bytearray | None = ...,
        IV : bytes | bytearray | None = ...,
        nonce : bytes | bytearray | None = ...,
        segment_size : int = ...,
        mac_len : int = ...,
        initial_value : int | bytes | bytearray = ...,
        counter : Dict = ...) -> \
        Union[EcbMode, CbcMode, CfbMode, OfbMode, CtrMode, OpenPgpMode]: ...

block_size: int
key_size: Iterable[int]
