# SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from Crypto.Random.random import getrandbits
from Crypto.Util._raw_api import (
    backend,
    c_size_t,
    c_ulonglong,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)
from Crypto.Util.number import bytes_to_long, long_to_bytes

from ._IntegerNative import IntegerNative

c_defs = """
int monty_pow(uint8_t       *out,
              const uint8_t *base,
              const uint8_t *exp,
              const uint8_t *modulus,
              size_t        len,
              uint64_t      seed);

int monty_multiply(uint8_t       *out,
                   const uint8_t *term1,
                   const uint8_t *term2,
                   const uint8_t *modulus,
                   size_t        len);
"""


_raw_montgomery = load_pycryptodome_raw_lib("Crypto.Math._modexp", c_defs)
implementation = {"library": "custom", "api": backend}


class IntegerCustom(IntegerNative):
    @staticmethod
    def from_bytes(byte_string, byteorder="big"):
        if byteorder == "big":
            pass
        elif byteorder == "little":
            byte_string = bytearray(byte_string)
            byte_string.reverse()
        else:
            raise ValueError("Incorrect byteorder")
        return IntegerCustom(bytes_to_long(byte_string))

    def inplace_pow(self, exponent, modulus=None):
        exp_value = int(exponent)
        if exp_value < 0:
            raise ValueError("Exponent must not be negative")

        # No modular reduction
        if modulus is None:
            self._value = pow(self._value, exp_value)
            return self

        # With modular reduction
        mod_value = int(modulus)
        if mod_value < 0:
            raise ValueError("Modulus must be positive")
        if mod_value == 0:
            raise ZeroDivisionError("Modulus cannot be zero")

        # C extension only works with odd moduli
        if (mod_value & 1) == 0:
            self._value = pow(self._value, exp_value, mod_value)
            return self

        # C extension only works with bases smaller than modulus
        if self._value >= mod_value:
            self._value %= mod_value

        max_len = len(long_to_bytes(max(self._value, exp_value, mod_value)))

        base_b = long_to_bytes(self._value, max_len)
        exp_b = long_to_bytes(exp_value, max_len)
        modulus_b = long_to_bytes(mod_value, max_len)

        out = create_string_buffer(max_len)

        error = _raw_montgomery.monty_pow(
            out, base_b, exp_b, modulus_b, c_size_t(max_len), c_ulonglong(getrandbits(64))
        )

        if error:
            raise ValueError("monty_pow failed with error: %d" % error)

        result = bytes_to_long(get_raw_buffer(out))
        self._value = result
        return self

    @staticmethod
    def _mult_modulo_bytes(term1, term2, modulus):
        # With modular reduction
        mod_value = int(modulus)
        if mod_value < 0:
            raise ValueError("Modulus must be positive")
        if mod_value == 0:
            raise ZeroDivisionError("Modulus cannot be zero")

        # C extension only works with odd moduli
        if (mod_value & 1) == 0:
            raise ValueError("Odd modulus is required")

        # C extension only works with non-negative terms smaller than modulus
        if term1 >= mod_value or term1 < 0:
            term1 %= mod_value
        if term2 >= mod_value or term2 < 0:
            term2 %= mod_value

        modulus_b = long_to_bytes(mod_value)
        numbers_len = len(modulus_b)
        term1_b = long_to_bytes(term1, numbers_len)
        term2_b = long_to_bytes(term2, numbers_len)
        out = create_string_buffer(numbers_len)

        error = _raw_montgomery.monty_multiply(out, term1_b, term2_b, modulus_b, c_size_t(numbers_len))
        if error:
            raise ValueError("monty_multiply failed with error: %d" % error)

        return get_raw_buffer(out)
