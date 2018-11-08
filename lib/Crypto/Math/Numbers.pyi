from typing import Union, Callable

__all__ = ["Integer"]

from Crypto.Math._Numbers_gmp import Integer as IntegerGmp
from Crypto.Math._Numbers_custom import Integer as IntegerCustom
from Crypto.Math._Numbers_int import Integer as IntegerInt

Integer = Union[IntegerGmp, IntegerCustom, IntegerInt]

def _random(**kwargs: Union[int, Callable]) -> Integer: ...
def _random_range(**kwargs: Union[int, Callable]) -> int: ...