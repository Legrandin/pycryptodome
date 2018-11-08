from typing import Optional, Union, Dict

from Crypto.Util.py3compat import b

def new(nbits: int, prefix: Optional[bytes]=b(""), suffix: Optional[bytes]=b(""), initial_value: Optional[int]=1,
        little_endian: Optional[bool]=False, allow_wraparound: Optional[bool]=False) -> \
        Dict[str, Union[int, bytes, bool]]: ...
