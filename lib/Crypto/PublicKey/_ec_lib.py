# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""The C module with the elliptic curves on the constant-time big integer
library: the NIST curves, Ed448 and X448 (src/ec_nat.c, src/ed448.c and
src/curve448.c)."""

import os
from typing import Any

from Crypto.Util import _cpu_features
from Crypto.Util._raw_api import load_pycryptodome_raw_lib


def use_bmi2_adx() -> bool:
    """True if the build for x86-64 CPUs with BMI2 and ADX can be used:
    the CPU supports both, and the environment variable
    PYCRYPTODOME_DISABLE_BMI2_ADX is not set (to test the portable build).
    See Crypto.Math._IntegerNat."""

    if os.getenv("PYCRYPTODOME_DISABLE_BMI2_ADX"):
        return False
    return bool(_cpu_features.have_bmi2() and _cpu_features.have_adx())


def load_ec_lib(cdecl: str) -> tuple[Any, bool]:
    """Load the module with the C declarations cdecl: the build for BMI2
    and ADX if it can be used (and was compiled in), the portable one
    otherwise. Return the library, and True if it is the BMI2/ADX build."""

    if use_bmi2_adx():
        try:
            return load_pycryptodome_raw_lib("Crypto.PublicKey._ec_nat_bmi2_adx", cdecl), True
        except OSError:
            pass
    return load_pycryptodome_raw_lib("Crypto.PublicKey._ec_nat", cdecl), False
