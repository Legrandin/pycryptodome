#
#  SelfTest/Util/test_cpu_features.py: check that the builds for AVX2, BMI2 and ADX are used
#
# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import os
import platform
import struct

import pytest

from Crypto.Cipher import ChaCha20, Salsa20
from Crypto.Hash import KangarooTwelve, keccak
from Crypto.Math import _IntegerNat
from Crypto.PublicKey import _nist_ecc
from Crypto.Util import _cpu_features


def avx2_bmi2_required():
    """Return True if the builds for AVX2, BMI2 and ADX must be in use.

    This is the case if the environment variable PYCRYPTODOME_REQUIRE_AVX2_BMI2
    is set (in CI, for runners known to support them) and Python runs
    as a 64-bit x86 process (x86_64, also called AMD64): on Windows,
    the wheels must be built with clang-cl (PYCRYPTODOME_CLANG_CL).
    """

    if not os.environ.get("PYCRYPTODOME_REQUIRE_AVX2_BMI2"):
        return False
    is_64bit = struct.calcsize("P") == 8
    return is_64bit and platform.machine().lower() in ("x86_64", "amd64")


# Required in CI on x86_64 (AMD64) runners known to support AVX2, BMI2 and ADX,
# so that a fallback to the portable implementations is not silent
pytestmark = pytest.mark.skipif(
    not avx2_bmi2_required(), reason="AVX2/BMI2 not required (see avx2_bmi2_required)"
)


def test_cpu_features():
    assert _cpu_features.have_avx2(), "AVX2 not detected"
    assert _cpu_features.have_bmi1(), "BMI1 not detected"
    assert _cpu_features.have_bmi2(), "BMI2 not detected"
    assert _cpu_features.have_adx(), "ADX not detected"


@pytest.mark.parametrize(
    "module, fast, selected",
    [
        (keccak, "_raw_keccak_avx2_bmi2_lib", "_raw_keccak_lib"),
        (KangarooTwelve, "_raw_k12_avx2_bmi2_lib", "_raw_k12_lib"),
        (Salsa20, "_raw_salsa20_avx2_bmi2_lib", "_raw_salsa20_lib"),
        (ChaCha20, "_raw_chacha20_avx2_bmi2_lib", "_raw_chacha20_lib"),
    ],
    ids=["keccak", "KangarooTwelve", "Salsa20", "ChaCha20"],
)
def test_avx2_bmi2_module(module, fast, selected):
    assert getattr(module, fast) is not None, "AVX2/BMI2 module not built"
    assert getattr(module, selected) is getattr(module, fast), "AVX2/BMI2 module not selected"


def test_bmi2_adx_modules():
    if os.environ.get("PYCRYPTODOME_DISABLE_BMI2_ADX"):
        pytest.skip("PYCRYPTODOME_DISABLE_BMI2_ADX is set")
    assert _IntegerNat._bmi2_adx_lib is not None, "BMI2/ADX build of Crypto.Math._nat not loaded"
    assert _nist_ecc._bmi2_adx, "BMI2/ADX build of Crypto.PublicKey._ec_nat not loaded"
