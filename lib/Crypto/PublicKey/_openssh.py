# SPDX-FileCopyrightText: 2019 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

import struct

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import _bcrypt_hash
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


def import_openssh_private_generic(data: bytes, password: bytes) -> tuple[str, bytes]:
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

        salt, kdfoptions = read_bytes(kdfoptions)
        iterations, kdfoptions = read_int4(kdfoptions)

        if len(salt) != 16:
            raise ValueError("Incorrect salt length")
        if kdfoptions:
            raise ValueError("Too much data in kdfoptions")

        pwd_sha512 = SHA512.new(password).digest()
        # We need 32+16 = 48 bytes, therefore 2 bcrypt outputs are sufficient
        stripes = []
        constant = b"OxychromaticBlowfishSwatDynamite"
        for count in range(1, 3):
            salt_sha512 = SHA512.new(salt + struct.pack(">I", count)).digest()
            out_le = _bcrypt_hash(pwd_sha512, 6, salt_sha512, constant, False)
            out = struct.pack("<IIIIIIII", *struct.unpack(">IIIIIIII", out_le))
            acc = bytearray(out)
            for _ in range(1, iterations):
                out_le = _bcrypt_hash(pwd_sha512, 6, SHA512.new(out).digest(), constant, False)
                out = struct.pack("<IIIIIIII", *struct.unpack(">IIIIIIII", out_le))
                strxor(acc, out, output=acc)
            stripes.append(acc[:24])

        result = b"".join([bytes([a]) + bytes([b]) for (a, b) in zip(*stripes)])

        cipher = AES.new(result[:32], AES.MODE_CTR, nonce=b"", initial_value=result[32 : 32 + 16])
        decrypted = cipher.decrypt(encrypted)

    checkint1, decrypted = read_int4(decrypted)
    checkint2, decrypted = read_int4(decrypted)
    if checkint1 != checkint2:
        raise ValueError("Incorrect checksum")
    ssh_name, decrypted = read_string(decrypted)

    return ssh_name, decrypted
