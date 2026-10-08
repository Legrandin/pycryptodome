#
#  SelfTest/Math/test_modmult.py: Self-test for custom modular multiplication
#
# SPDX-FileCopyrightText: 2023 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Self-test for the custom modular multiplication"""

from Crypto.Math._IntegerCustom import _raw_montgomery
from Crypto.Util._raw_api import c_size_t, create_string_buffer, get_raw_buffer
from Crypto.Util.number import bytes_to_long, long_to_bytes


class ExceptionModulus(ValueError):
    pass


def monty_mult(term1, term2, modulus):
    if term1 >= modulus:
        term1 %= modulus
    if term2 >= modulus:
        term2 %= modulus

    modulus_b = long_to_bytes(modulus)
    numbers_len = len(modulus_b)
    term1_b = long_to_bytes(term1, numbers_len)
    term2_b = long_to_bytes(term2, numbers_len)

    out = create_string_buffer(numbers_len)
    error = _raw_montgomery.monty_multiply(out, term1_b, term2_b, modulus_b, c_size_t(numbers_len))

    if error == 17:
        raise ExceptionModulus()
    if error:
        raise ValueError("monty_multiply() failed with error: %d" % error)

    return get_raw_buffer(out)


modulus1 = 0xD66691B20071BE4D66D4B71032B37FA007CFABF579FCB91E50BFC2753B3F0CE7BE74E216AEF7E26D4AE180BC20D7BD3EA88A6CBF6F87380E613C8979B5B043B200A8FF8856A3B12875E36E98A7569F3852D028E967551000B02C19E9FA52E83115B89309AABB1E1CF1E2CB6369D637D46775CE4523EA31F64AD2794CBC365DD8A35E007ED3B57695877FBF102DBEB8B3212491398E494314E93726926E1383F8ABB5889BEA954EB8C0CA1C62C8E9D83F41888095C5E645ED6D32515FE0C58C1368CAD84694E18DA43668C6F43E61D7C9BCA633DDCDA7AEF5B79BC396D4A9F48E2A9ABE0836CC455E435305357228E93D25AAED46B952DEFAE0F57339BF26F5A9


class TestModMultiply:
    def test_small(self):
        assert monty_mult(5, 6, 29) == b"\x01"

    def test_large(self):
        numbers_len = (modulus1.bit_length() + 7) // 8

        t1 = modulus1 // 2
        t2 = modulus1 - 90
        expect = b"\x00" * (numbers_len - 1) + b"\x2d"
        assert expect == monty_mult(t1, t2, modulus1)

    def test_zero_term(self):
        numbers_len = (modulus1.bit_length() + 7) // 8
        expect = b"\x00" * numbers_len
        assert expect == monty_mult(0x100, 0, modulus1)
        assert expect == monty_mult(0, 0x100, modulus1)

    def test_larger_term(self):
        t1 = 2**2047
        expect_int = 0x8EDF4071F78E3D7BA622CDBBBEF74612E301D69186776AE6BF87FF38C320D9AEBAA64889C2F67DE2324E6BCCD2B10AD89E91FD21BA4BB523904D033EFF5E70E62F01A84F41FA90A4F248EF249B82E1D2729253FDFC2A3B5B740198123DF8BFBF7057D03E15244AD5F26EB9A099763B5C5972121EC076B0BF899F59BD95F7CC129ABDDCCF24217BCE52CA0F3A44C9CCC504765DBB89734205F3AE6A8CC560494A60EA84B27D8E00FA24BDD5B4F1D4232EDB61E47D3D984C1FA50A3820A2E580FBC3FC8BC11E99DF53B9EFADF5A40AC75D384E400905AA6F1D88950CD53B1C54DC2222115AD84A27260FA4D978155C1434C551DE1EE7361A17A2F79D4388F78A5D
        res = bytes_to_long(monty_mult(t1, t1, modulus1))
        assert res == expect_int
