#
# Util/Padding.py :  Functions to manage padding
#
# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

from typing import Optional

__all__ = ["pad", "unpad"]


def pad(data_to_pad: bytes, block_size: int, style: Optional[str] = "pkcs7") -> bytes:
    """Apply standard padding.

    Args:
      data_to_pad (byte string):
        The data that needs to be padded.
      block_size (integer):
        The block boundary to use for padding. The output length is guaranteed
        to be a multiple of :data:`block_size`.
      style (string):
        Padding algorithm. It can be *'pkcs7'* (default), *'iso7816'* or *'x923'*.

    Return:
      byte string : the original data with the appropriate padding added at the end.
    """

    padding_len = block_size - len(data_to_pad) % block_size

    if style == "pkcs7":
        padding = bytes([padding_len]) * padding_len
    elif style == "x923":
        padding = bytes([0]) * (padding_len - 1) + bytes([padding_len])
    elif style == "iso7816":
        padding = bytes([128]) + bytes([0]) * (padding_len - 1)
    else:
        raise ValueError("Unknown padding style")

    return data_to_pad + padding


def unpad(padded_data: bytes, block_size: int, style: Optional[str] = "pkcs7") -> bytes:
    """Remove standard padding.

    Args:
      padded_data (byte string):
        A piece of data with padding that needs to be stripped.
      block_size (integer):
        The block boundary to use for padding. The input length
        must be a multiple of :data:`block_size`.
      style (string):
        Padding algorithm. It can be *'pkcs7'* (default), *'iso7816'* or *'x923'*.
    Return:
        byte string : data without padding.
    Raises:
      ValueError: if the padding is incorrect.
    """

    pdata_len = len(padded_data)

    if pdata_len == 0:
        raise ValueError("Zero-length input cannot be unpadded")

    if pdata_len % block_size:
        raise ValueError("Input data is not padded")

    if style in ("pkcs7", "x923"):
        padding_len = padded_data[-1]

        if padding_len < 1 or padding_len > min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")

        if style == "pkcs7":
            if padded_data[-padding_len:] != bytes([padding_len]) * padding_len:
                raise ValueError("PKCS#7 padding is incorrect.")
        else:
            if padded_data[-padding_len:-1] != bytes([0]) * (padding_len - 1):
                raise ValueError("ANSI X.923 padding is incorrect.")

    elif style == "iso7816":
        padding_len = pdata_len - padded_data.rfind(bytes([128]))

        if padding_len < 1 or padding_len > min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")

        if padding_len > 1 and padded_data[1 - padding_len :] != bytes([0]) * (padding_len - 1):
            raise ValueError("ISO 7816-4 padding is incorrect.")
    else:
        raise ValueError("Unknown padding style")

    return padded_data[:-padding_len]
