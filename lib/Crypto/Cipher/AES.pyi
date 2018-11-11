from typing import Any, Union, Tuple, Optional, Dict, overload

from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher._mode_cfb import CfbMode
from Crypto.Cipher._mode_ofb import OfbMode
from Crypto.Cipher._mode_ctr import CtrMode
from Crypto.Cipher._mode_openpgp import OpenPgpMode
from Crypto.Cipher._mode_ccm import CcmMode
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Cipher._mode_gcm import GcmMode
from Crypto.Cipher._mode_siv import SivMode
from Crypto.Cipher._mode_ocb import OcbMode

AESMode = int

MODE_ECB: AESMode
MODE_CBC: AESMode
MODE_CFB: AESMode
MODE_OFB: AESMode
MODE_CTR: AESMode
MODE_OPENPGP: AESMode
MODE_CCM: AESMode
MODE_EAX: AESMode
MODE_GCM: AESMode
MODE_SIV: AESMode
MODE_OCB: AESMode

Buffer = Union[bytes, bytearray, memoryview]

@overload
def new(__key: Buffer,
        __mode: AESMode,
        use_aesni : Optional[bool]) -> EcbMode: ...

@overload
def new(__key: Buffer,
        __mode: AESMode,
        __iv : Optional[Buffer],
        segment_size : Optional[int],
        use_aesni : Optional[bool]) -> \
        Union[CbcMode, CfbMode, OfbMode, OpenPgpMode]: ...

@overload
def new(__key: Buffer,
        __mode: AESMode,
        iv : Optional[Buffer],
        segment_size : Optional[int],
        use_aesni : Optional[bool]) -> \
        Union[CbcMode, CfbMode, OfbMode, OpenPgpMode]: ...

@overload
def new(__key: Buffer,
        __mode: AESMode,
        IV : Optional[Buffer],
        segment_size : Optional[int],
        use_aesni : Optional[bool]) -> \
        Union[CbcMode, CfbMode, OfbMode, OpenPgpMode]: ...

@overload
def new(__key: Buffer,
        __mode: AESMode,
        nonce : Optional[Buffer],
        initial_value : Optional[Union[int, Buffer]],
        use_aesni : Optional[bool]) -> CtrMode: ...

@overload
def new(__key: Buffer,
        __mode: AESMode,
	counter : Dict,
        use_aesni : Optional[bool]) -> CtrMode: ...

@overload
def new(__key: Buffer,
        __mode: AESMode,
        nonce : Optional[Buffer],
        mac_len : Optional[int],
        msg_len : Optional[int],
        assoc_len : Optional[int],
        use_aesni : Optional[bool]) -> \
        Union[CcmMode]: ...

@overload
def new(__key: Buffer,
        __mode: AESMode,
        nonce : Optional[Buffer],
        mac_len : Optional[int],
        use_aesni : Optional[bool]) -> \
        Union[EaxMode, GcmMode, SivMode]: ...

block_size: int
key_size: Tuple[int, int, int]
