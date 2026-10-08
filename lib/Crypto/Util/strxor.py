# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

from typing import Any, Optional, Union, overload

from Crypto.Util._raw_api import (
    c_size_t,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    create_output_buffer,
    get_raw_buffer,
    is_writeable_buffer,
    load_pycryptodome_raw_lib,
)

Buffer = Union[bytes, bytearray, memoryview]

_raw_strxor = load_pycryptodome_raw_lib(
    "Crypto.Util._strxor",
    """
                    void strxor(const uint8_t *in1,
                                const uint8_t *in2,
                                uint8_t *out, size_t len);
                    void strxor_c(const uint8_t *in,
                                  uint8_t c,
                                  uint8_t *out,
                                  size_t len);
                    """,
)


@overload
def strxor(term1: Buffer, term2: Buffer) -> bytes: ...


@overload
def strxor(term1: Buffer, term2: Buffer, output: Union[bytearray, memoryview]) -> None: ...


def strxor(
    term1: Buffer, term2: Buffer, output: Optional[Union[bytearray, memoryview]] = None
) -> Optional[bytes]:
    """From two byte strings of equal length,
    create a third one which is the byte-by-byte XOR of the two.

    Args:
      term1 (bytes/bytearray/memoryview):
        The first byte string to XOR.
      term2 (bytes/bytearray/memoryview):
        The second byte string to XOR.
      output (bytearray/memoryview):
        The location where the result will be written to.
        It must have the same length as ``term1`` and ``term2``.
        If ``None``, the result is returned.
    :Return:
        If ``output`` is ``None``, a new byte string with the result.
        Otherwise ``None``.

    .. note::
        ``term1`` and ``term2`` must have the same length.
    """

    if len(term1) != len(term2):
        raise ValueError("Only byte strings of equal length can be xored")

    if output is None:
        result = create_output_buffer(len(term1))
    else:
        # Note: output may overlap with either input
        result = output

        if not is_writeable_buffer(output):
            raise TypeError("output must be a bytearray or a writeable memoryview")

        if len(term1) != len(output):
            raise ValueError("output must have the same length as the input  (%d bytes)" % len(term1))

    with c_uint8_ptr_out(result) as result_ptr:
        term1_ptr, term1_len = c_uint8_ptr_len(term1)
        term2_ptr, term2_len = c_uint8_ptr_len(term2)
        # Check the lengths of the buffers that C code gets
        if term2_len != term1_len:
            raise ValueError("Only byte strings of equal length can be xored")
        if len(result_ptr) != term1_len:
            raise ValueError("output must have the same length as the input  (%d bytes)" % term1_len)
        _raw_strxor.strxor(term1_ptr, term2_ptr, result_ptr, c_size_t(term1_len))

    if output is None:
        return get_raw_buffer(result)
    else:
        return None


@overload
def strxor_c(term: Buffer, c: int) -> bytes: ...


@overload
def strxor_c(term: Buffer, c: int, output: Union[bytearray, memoryview]) -> None: ...


def strxor_c(term: Buffer, c: int, output: Optional[Union[bytearray, memoryview]] = None) -> Optional[bytes]:
    """From a byte string, create a second one of equal length
    where each byte is XOR-red with the same value.

    Args:
      term(bytes/bytearray/memoryview):
        The byte string to XOR.
      c (int):
        Every byte in the string will be XOR-ed with this value.
        It must be between 0 and 255 (included).
      output (None or bytearray/memoryview):
        The location where the result will be written to.
        It must have the same length as ``term``.
        If ``None``, the result is returned.

    Return:
        If ``output`` is ``None``, a new ``bytes`` string with the result.
        Otherwise ``None``.
    """

    if not 0 <= c < 256:
        raise ValueError("c must be in range(256)")

    if output is None:
        result = create_output_buffer(len(term))
    else:
        # Note: output may overlap with either input
        result = output

        if not is_writeable_buffer(output):
            raise TypeError("output must be a bytearray or a writeable memoryview")

        if len(term) != len(output):
            raise ValueError("output must have the same length as the input  (%d bytes)" % len(term))

    with c_uint8_ptr_out(result) as result_ptr:
        term_ptr, term_len = c_uint8_ptr_len(term)
        # Check the lengths of the buffers that C code gets
        if len(result_ptr) != term_len:
            raise ValueError("output must have the same length as the input  (%d bytes)" % term_len)
        _raw_strxor.strxor_c(term_ptr, c, result_ptr, c_size_t(term_len))

    if output is None:
        return get_raw_buffer(result)
    else:
        return None


def _strxor_direct(term1: Any, term2: Any, result: Any) -> None:
    """Very fast XOR - check conditions!"""
    _raw_strxor.strxor(term1, term2, result, c_size_t(len(term1)))
