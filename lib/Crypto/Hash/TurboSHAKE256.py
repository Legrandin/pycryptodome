from __future__ import annotations

from typing import Optional, Union

from .TurboSHAKE128 import TurboSHAKE

Buffer = Union[bytes, bytearray, memoryview]


def new(*, domain: int = 0x1F, data: Optional[Buffer] = None) -> TurboSHAKE:
    """Create a new TurboSHAKE256 object.

    Args:
       domain (integer):
         Optional - A domain separation byte, between 0x01 and 0x7F.
         The default value is 0x1F.
       data (bytes/bytearray/memoryview):
        Optional - The very first chunk of the message to hash.
        It is equivalent to an early call to :meth:`update`.

    :Return: A :class:`TurboSHAKE` object
    """

    domain_separation = domain
    if not (0x01 <= domain_separation <= 0x7F):
        raise ValueError("Incorrect domain separation value (%d)" % domain_separation)
    return TurboSHAKE(64, domain_separation, data=data)
