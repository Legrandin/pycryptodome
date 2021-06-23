import sys
from typing import Union, Tuple, Optional, Dict, overload

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

if sys.version_info >= (3, 8):
    MODE_ECB: Literal[1]
    MODE_CBC: Literal[2]
    MODE_CFB: Literal[3]
    MODE_OFB: Literal[5]
    MODE_CTR: Literal[6]
    MODE_OPENPGP: Literal[7]
    MODE_CCM: Literal[8]
    MODE_EAX: Literal[9]
    MODE_SIV: Literal[10]
    MODE_GCM: Literal[11]
    MODE_OCB: Literal[12]

    AESMode = Union[
        MODE_ECB,
        MODE_CBC,
        MODE_CFB,
        MODE_OFB,
        MODE_CTR,
        MODE_OPENPGP,
        MODE_CCM,
        MODE_EAX,
        MODE_GCM,
        MODE_SIV,
        MODE_OCB,
    ]

    @overload
    def new(key: Buffer,
            mode: MODE_ECB,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            EcbMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_CBC,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            CbcMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_CFB,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            CfbMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_OFB,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            OfbMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_CTR,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            CtrMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_OPENPGP,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            OpenPgpMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_CCM,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            CcmMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_EAX,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            EaxMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_SIV,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            SivMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_GCM,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            GcmMode: ...

    @overload
    def new(key: Buffer,
            mode: MODE_OCB,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            OcbMode: ...

else:   
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

    def new(key: Buffer,
            mode: AESMode,
            iv : Buffer = ...,
            IV : Buffer = ...,
            nonce : Buffer = ...,
            segment_size : int = ...,
            mac_len : int = ...,
            assoc_len : int = ...,
            initial_value : Union[int, Buffer] = ...,
            counter : Dict = ...,
            use_aesni : bool = ...) -> \
            Union[EcbMode, CbcMode, CfbMode, OfbMode, CtrMode,
                  OpenPgpMode, CcmMode, EaxMode, GcmMode,
                  SivMode, OcbMode]: ...

Buffer = Union[bytes, bytearray, memoryview]
block_size: int
key_size: Tuple[int, int, int]
