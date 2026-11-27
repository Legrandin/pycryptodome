# SPDX-FileCopyrightText: 2019 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

import binascii
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


# OpenSSH certificates (PROTOCOL.certkeys in the OpenSSH source):
# for each certificate type, the plain key type and the number of
# fields of the certified public key (after the nonce)
_CERT_TYPES = {
    b"ssh-rsa-cert-v01@openssh.com": (b"ssh-rsa", 2),  # e, n
    b"ssh-dss-cert-v01@openssh.com": (b"ssh-dss", 4),  # p, q, g, y
    b"ecdsa-sha2-nistp256-cert-v01@openssh.com": (b"ecdsa-sha2-nistp256", 2),  # curve, Q
    b"ecdsa-sha2-nistp384-cert-v01@openssh.com": (b"ecdsa-sha2-nistp384", 2),
    b"ecdsa-sha2-nistp521-cert-v01@openssh.com": (b"ecdsa-sha2-nistp521", 2),
    b"ssh-ed25519-cert-v01@openssh.com": (b"ssh-ed25519", 1),  # public key
}


def openssh_certificate_to_public_key(line: bytes) -> bytes:
    """Return the OpenSSH public key line of the key in an OpenSSH certificate.

    The certificate is **not** verified: neither its signature,
    nor its validity period or its principals.
    """

    parts = line.rstrip(b"\r\n").split(b" ", 2)
    if len(parts) < 2 or parts[0] not in _CERT_TYPES:
        raise ValueError("Not an OpenSSH certificate")
    key_type, nr_fields = _CERT_TYPES[parts[0]]

    try:
        blob = binascii.a2b_base64(parts[1])
    except binascii.Error:
        raise ValueError("Invalid base64 in the OpenSSH certificate")

    cert_type, data = read_bytes(blob)
    if cert_type != parts[0]:
        raise ValueError("Mismatch in the type of the OpenSSH certificate")
    _nonce, data = read_bytes(data)

    fields = []
    for _ in range(nr_fields):
        field, data = read_bytes(data)
        fields.append(field)

    # serial (uint64), type (uint32), key id, principals,
    # valid after and valid before (uint64), critical options, extensions,
    # reserved, signature key, signature
    if len(data) < 12:
        raise ValueError("Insufficient data")
    cert_kind = struct.unpack(">I", data[8:12])[0]
    if cert_kind not in (1, 2):  # user or host certificate
        raise ValueError("Invalid type of OpenSSH certificate")
    data = data[12:]
    for _ in range(2):
        _, data = read_bytes(data)
    if len(data) < 16:
        raise ValueError("Insufficient data")
    data = data[16:]
    for _ in range(5):
        _, data = read_bytes(data)
    if data:
        raise ValueError("Trailing data in the OpenSSH certificate")

    key_blob = b"".join(struct.pack(">I", len(x)) + x for x in [key_type] + fields)
    result = [key_type, binascii.b2a_base64(key_blob, newline=False)]
    return b" ".join(result + parts[2:])
