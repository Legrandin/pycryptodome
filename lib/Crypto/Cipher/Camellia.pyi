from typing import Tuple, Dict, Optional, Union, overload
from typing_extensions import Literal

Buffer = bytes|bytearray|memoryview

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
from Crypto.Cipher._mode_kw import KWMode
from Crypto.Cipher._mode_kwp import KWPMode

MODE_ECB: Literal[1]
MODE_CBC: Literal[2]
MODE_CFB: Literal[3]
MODE_OFB: Literal[4]
MODE_CTR: Literal[5]
MODE_OPENPGP: Literal[6]
MODE_CCM: Literal[7]
MODE_EAX: Literal[8]
MODE_SIV: Literal[9]
MODE_GCM: Literal[10]
MODE_OCB: Literal[11]
MODE_KW: Literal[12]
MODE_KWP: Literal[13]

# MODE_ECB
@overload
def new(key: Buffer,
        mode: Literal[1],
        iv: Optional[Buffer] = ...) -> EcbMode: ...

# MODE_CBC
@overload
def new(key: Buffer,
        mode: Literal[2],
        iv: Optional[Buffer] = ...) -> CbcMode: ...

# MODE_CFB
@overload
def new(key: Buffer,
        mode: Literal[3],
        iv: Optional[Buffer] = ...,
        segment_size: int = ...) -> CfbMode: ...

# MODE_OFB
@overload
def new(key: Buffer,
        mode: Literal[4],
        iv: Optional[Buffer] = ...) -> OfbMode: ...

# MODE_CTR
@overload
def new(key: Buffer,
        mode: Literal[5],
        nonce: Optional[Buffer] = ...,
        initial_value: Union[int, Buffer] = ...,
        counter : Dict = ...) -> CtrMode: ...

# MODE_GCM
@overload
def new(key: Buffer,
        mode: Literal[10],
        nonce: Optional[Buffer] = ...,
        mac_len: int = ...) -> GcmMode: ...


block_size: int
key_size: Tuple[int, int, int]