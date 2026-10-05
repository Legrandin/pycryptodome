from __future__ import annotations

from typing import Tuple, Union

__all__ = ["Cipher", "Hash", "Protocol", "PublicKey", "Util", "Signature", "IO", "Math"]

version_info: Tuple[int, int, Union[int, str]] = (4, 0, "0b0")

__version__: str = ".".join([str(x) for x in version_info])
