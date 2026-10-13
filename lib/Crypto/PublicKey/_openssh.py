# SPDX-FileCopyrightText: 2019 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

import struct
from typing import Optional

from Crypto import (
    _INCORRECT_PASSPHRASE,
    _PASSPHRASE_REQUIRED,
    IncorrectPassphraseError,
    PassphraseRequiredError,
)
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.IO._PBES import _BCRYPT_ROUNDS, _DEFAULT_MAX_BCRYPT_ROUNDS, PbesError, _check_iteration_count
from Crypto.Protocol.KDF import _bcrypt_hash2
from Crypto.Util.strxor import strxor


def read_int4(data: bytes) -> tuple[int, bytes]:
    if len(data) < 4:
        raise ValueError("Insufficient data")
    value = struct.unpack(">I", data[:4])[0]
    return value, data[4:]


def read_bytes(data: bytes) -> tuple[bytes, bytes]:
    size, data = read_int4(data)
    if len(data) < size:
        raise ValueError("Insufficient data (V)")
    return data[:size], data[size:]


def read_string(data: bytes) -> tuple[str, bytes]:
    s, d = read_bytes(data)
    return s.decode("latin-1"), d


def check_padding(pad: bytes) -> None:
    for v, x in enumerate(pad):
        if x != ((v + 1) & 0xFF):
            raise ValueError("Incorrect padding")


def _bcrypt_pbkdf(password: bytes, salt: bytes, rounds: int) -> bytes:
    """bcrypt_pbkdf of OpenSSH, for the 48 bytes of the AES-256 key and IV.

    The output comes from two independent stripes of 32 bytes each,
    computed together at each round (see :func:`_bcrypt_hash2`).
    """

    constant = b"OxychromaticBlowfishSwatDynamite"
    pwd_sha512 = SHA512.new(password).digest()

    def swap(out_le):
        return struct.pack("<IIIIIIII", *struct.unpack(">IIIIIIII", out_le))

    salts = [SHA512.new(salt + struct.pack(">I", count)).digest() for count in (1, 2)]
    outs = [swap(o) for o in _bcrypt_hash2(pwd_sha512, 6, salts[0], salts[1], constant, False)]
    accs = [bytearray(o) for o in outs]
    for _ in range(1, rounds):
        salts = [SHA512.new(o).digest() for o in outs]
        outs = [swap(o) for o in _bcrypt_hash2(pwd_sha512, 6, salts[0], salts[1], constant, False)]
        for acc, out in zip(accs, outs):
            strxor(acc, out, output=acc)

    stripes = [acc[:24] for acc in accs]
    return b"".join([bytes([a]) + bytes([b]) for (a, b) in zip(*stripes)])


def import_openssh_private_generic(
    data: bytes, password: bytes, max_iteration_count: Optional[int] = None
) -> tuple[str, bytes]:
    # https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
    # https://github.com/openssh/openssh-portable/blob/master/sshkey.c
    # https://coolaj86.com/articles/the-openssh-private-key-format/
    # https://coolaj86.com/articles/the-ssh-public-key-format/

    if not data.startswith(b"openssh-key-v1\x00"):
        raise ValueError("Incorrect magic value")
    data = data[15:]

    ciphername, data = read_string(data)
    kdfname, data = read_string(data)
    kdfoptions, data = read_bytes(data)
    number_of_keys, data = read_int4(data)

    if number_of_keys != 1:
        raise ValueError("We only handle 1 key at a time")

    _, data = read_string(data)  # Public key
    encrypted, data = read_bytes(data)
    if data:
        raise ValueError("Too much data")

    if len(encrypted) % 8 != 0:
        raise ValueError("Incorrect payload length")

    # Decrypt if necessary
    if ciphername == "none":
        decrypted = encrypted
    else:
        if (ciphername, kdfname) != ("aes256-ctr", "bcrypt"):
            raise ValueError("Unsupported encryption scheme %s/%s" % (ciphername, kdfname))
        # OpenSSH never encrypts a key with an empty passphrase
        if not password:
            raise PassphraseRequiredError(_PASSPHRASE_REQUIRED)

        salt, kdfoptions = read_bytes(kdfoptions)
        iterations, kdfoptions = read_int4(kdfoptions)

        if len(salt) != 16:
            raise ValueError("Incorrect salt length")
        if kdfoptions:
            raise ValueError("Too much data in kdfoptions")

        # Before any key derivation: the number of rounds comes from the key
        if iterations < 1:
            raise PbesError("Invalid bcrypt_pbkdf rounds count")
        _check_iteration_count(_BCRYPT_ROUNDS, iterations, max_iteration_count, _DEFAULT_MAX_BCRYPT_ROUNDS)

        # We need 32+16 = 48 bytes (AES-256 key and IV)
        result = _bcrypt_pbkdf(password, salt, iterations)

        cipher = AES.new(result[:32], AES.MODE_CTR, nonce=b"", initial_value=result[32 : 32 + 16])
        decrypted = cipher.decrypt(encrypted)

    # Two copies of the same random value: after decryption with
    # an incorrect passphrase, they match only once in 2^32 times
    checkint1, decrypted = read_int4(decrypted)
    checkint2, decrypted = read_int4(decrypted)
    if checkint1 != checkint2:
        if ciphername != "none":
            raise IncorrectPassphraseError(_INCORRECT_PASSPHRASE)
        raise ValueError("Incorrect checksum")
    ssh_name, decrypted = read_string(decrypted)

    return ssh_name, decrypted
