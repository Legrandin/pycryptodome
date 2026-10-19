# SPDX-FileCopyrightText: 2015 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import errno
import os
from binascii import unhexlify

import pytest

from Crypto import KdfIterationLimitError
from Crypto.Hash import SHAKE128
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import _import_rfc5915_der
from Crypto.SelfTest.loader import warn_skipped_tests
from Crypto.Util.asn1 import DerBitString, DerSequence
from Crypto.Util.number import bytes_to_long

try:
    import pycryptodome_test_vectors  # type: ignore

    test_vectors_available = True
except ImportError:
    test_vectors_available = False


def load_file(file_name, mode="rb"):
    results = None

    try:
        if not test_vectors_available:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_name)

        dir_comps = ("PublicKey", "ECC")
        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        full_file_name = os.path.join(os.path.join(init_dir, *dir_comps), file_name)
        with open(full_file_name, mode) as file_in:
            results = file_in.read()

    except FileNotFoundError:
        warn_skipped_tests("Skipping extended tests for ECC")

    if results is None:
        pytest.skip("Missing %s" % file_name)

    return results


def compact(lines):
    ext = b"".join(lines)
    return unhexlify(ext.decode("latin-1").replace(" ", "").replace(":", ""))


def create_ref_keys_p192():
    key_len = 24
    key_lines = load_file("ecc_p192.txt").splitlines()
    private_key_d = bytes_to_long(compact(key_lines[2:4]))
    public_key_xy = compact(key_lines[5:9])
    assert public_key_xy[0] == 4  # Uncompressed
    public_key_x = bytes_to_long(public_key_xy[1 : key_len + 1])
    public_key_y = bytes_to_long(public_key_xy[key_len + 1 :])

    return (
        ECC.construct(curve="P-192", d=private_key_d),
        ECC.construct(curve="P-192", point_x=public_key_x, point_y=public_key_y),
    )


def create_ref_keys_p224():
    key_len = 28
    key_lines = load_file("ecc_p224.txt").splitlines()
    private_key_d = bytes_to_long(compact(key_lines[2:4]))
    public_key_xy = compact(key_lines[5:9])
    assert public_key_xy[0] == 4  # Uncompressed
    public_key_x = bytes_to_long(public_key_xy[1 : key_len + 1])
    public_key_y = bytes_to_long(public_key_xy[key_len + 1 :])

    return (
        ECC.construct(curve="P-224", d=private_key_d),
        ECC.construct(curve="P-224", point_x=public_key_x, point_y=public_key_y),
    )


def create_ref_keys_p256():
    key_len = 32
    key_lines = load_file("ecc_p256.txt").splitlines()
    private_key_d = bytes_to_long(compact(key_lines[2:5]))
    public_key_xy = compact(key_lines[6:11])
    assert public_key_xy[0] == 4  # Uncompressed
    public_key_x = bytes_to_long(public_key_xy[1 : key_len + 1])
    public_key_y = bytes_to_long(public_key_xy[key_len + 1 :])

    return (
        ECC.construct(curve="P-256", d=private_key_d),
        ECC.construct(curve="P-256", point_x=public_key_x, point_y=public_key_y),
    )


def create_ref_keys_p384():
    key_len = 48
    key_lines = load_file("ecc_p384.txt").splitlines()
    private_key_d = bytes_to_long(compact(key_lines[2:6]))
    public_key_xy = compact(key_lines[7:14])
    assert public_key_xy[0] == 4  # Uncompressed
    public_key_x = bytes_to_long(public_key_xy[1 : key_len + 1])
    public_key_y = bytes_to_long(public_key_xy[key_len + 1 :])

    return (
        ECC.construct(curve="P-384", d=private_key_d),
        ECC.construct(curve="P-384", point_x=public_key_x, point_y=public_key_y),
    )


def create_ref_keys_p521():
    key_len = 66
    key_lines = load_file("ecc_p521.txt").splitlines()
    private_key_d = bytes_to_long(compact(key_lines[2:7]))
    public_key_xy = compact(key_lines[8:17])
    assert public_key_xy[0] == 4  # Uncompressed
    public_key_x = bytes_to_long(public_key_xy[1 : key_len + 1])
    public_key_y = bytes_to_long(public_key_xy[key_len + 1 :])

    return (
        ECC.construct(curve="P-521", d=private_key_d),
        ECC.construct(curve="P-521", point_x=public_key_x, point_y=public_key_y),
    )


def create_ref_keys_ed25519():
    key_lines = load_file("ecc_ed25519.txt").splitlines()
    seed = compact(key_lines[5:8])
    key = ECC.construct(curve="Ed25519", seed=seed)
    return (key, key.public_key())


def create_ref_keys_ed448():
    key_lines = load_file("ecc_ed448.txt").splitlines()
    seed = compact(key_lines[6:10])
    key = ECC.construct(curve="Ed448", seed=seed)
    return (key, key.public_key())


# Create reference key pair
# ref_private, ref_public = create_ref_keys_p521()


def get_fixed_prng():
    return SHAKE128.new().update(b"SEED").read


def extract_bitstring_from_spki(data):
    seq = DerSequence()
    seq.decode(data)
    bs = DerBitString()
    bs.decode(seq[1])
    return bs.value


class TestImport:
    def test_empty(self):
        with pytest.raises(ValueError):
            ECC.import_key(b"")

    def test_mismatch(self):
        # The private key does not match the public key
        mismatch = """-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJChZANiAAQarFRaqflo
I+d61SRvU8Za2EurxtW20eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinng
o4N+LZfQYcTxmdwlkWOrfzCjtHDix6EznPO/LlxTsV+zfTJ/ijTjeXk=
-----END PRIVATE KEY-----"""
        with pytest.raises(ValueError):
            ECC.import_key(mismatch)

    def test_import_private_rfc5915_none(self):
        # ECPrivateKey with a P256 private key, without [0] and [1]
        data_hex = "302502010104205c4e4320ef260f91ed9fc597aee98c8236b60e0ced692cc7a057d5e45798a052"
        key = _import_rfc5915_der(unhexlify(data_hex), None, "1.2.840.10045.3.1.7")
        assert key.d == 0x5C4E4320EF260F91ED9FC597AEE98C8236B60E0CED692CC7A057D5E45798A052

    def test_import_private_rfc5915_only_0(self):
        # ECPrivateKey with a P256 private key, with [0] only
        data_hex = "303102010104205c4e4320ef260f91ed9fc597aee98c8236b60e0ced692cc7a057d5e45798a052a00a06082a8648ce3d030107"
        key = _import_rfc5915_der(unhexlify(data_hex), None)
        assert key.d == 0x5C4E4320EF260F91ED9FC597AEE98C8236B60E0CED692CC7A057D5E45798A052

    def test_import_private_rfc5915_only_1(self):
        # ECPrivateKey with a P256 private key, with [1] only
        data_hex = "306b02010104205c4e4320ef260f91ed9fc597aee98c8236b60e0ced692cc7a057d5e45798a052a14403420004a40ad59a2050ebe92479bd5fb16bb2e45b6465eb3cb2b1effe423fabe6cb7424db8219ef0bab80acf26fd70595b61fe4760d33eed80dd03d2fd0dfb27b8ce75c"
        key = _import_rfc5915_der(unhexlify(data_hex), None, "1.2.840.10045.3.1.7")
        assert key.d == 0x5C4E4320EF260F91ED9FC597AEE98C8236B60E0CED692CC7A057D5E45798A052


class TestImport_P192:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p192()

    def test_import_public_der(self):
        key_file = load_file("ecc_p192_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        assert self.ref_public == key

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_sec1_uncompressed(self):
        key_file = load_file("ecc_p192_public.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P192")
        assert self.ref_public == key

    def test_import_sec1_compressed(self):
        key_file = load_file("ecc_p192_public_compressed.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P192")
        assert self.ref_public == key

    def test_import_rfc5915_der(self):
        key_file = load_file("ecc_p192_private.der")

        key = ECC._import_rfc5915_der(key_file, None)
        assert self.ref_private == key

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_clear(self):
        key_file = load_file("ecc_p192_private_p8_clear.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_in_pem_clear(self):
        key_file = load_file("ecc_p192_private_p8_clear.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_1(self):
        key_file = load_file("ecc_p192_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_2(self):
        key_file = load_file("ecc_p192_private_p8.pem")

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_x509_der(self):
        key_file = load_file("ecc_p192_x509.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_public_pem(self):
        key_file = load_file("ecc_p192_public.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_private_pem(self):
        key_file = load_file("ecc_p192_private.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pem_encrypted(self):
        for algo in "des3", "aes128", "aes192", "aes256", "aes256_gcm":
            key_file = load_file("ecc_p192_private_enc_%s.pem" % algo)

            key = ECC.import_key(key_file, "secret")
            assert self.ref_private == key

            key = ECC.import_key(key_file.decode("latin-1"), b"secret")
            assert self.ref_private == key

    def test_import_x509_pem(self):
        key_file = load_file("ecc_p192_x509.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key


class TestImport_P224:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p224()

    def test_import_public_der(self):
        key_file = load_file("ecc_p224_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        assert self.ref_public == key

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_sec1_uncompressed(self):
        key_file = load_file("ecc_p224_public.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P224")
        assert self.ref_public == key

    def test_import_sec1_compressed(self):
        key_file = load_file("ecc_p224_public_compressed.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P224")
        assert self.ref_public == key

    def test_import_rfc5915_der(self):
        key_file = load_file("ecc_p224_private.der")

        key = ECC._import_rfc5915_der(key_file, None)
        assert self.ref_private == key

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_clear(self):
        key_file = load_file("ecc_p224_private_p8_clear.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_in_pem_clear(self):
        key_file = load_file("ecc_p224_private_p8_clear.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_1(self):
        key_file = load_file("ecc_p224_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_2(self):
        key_file = load_file("ecc_p224_private_p8.pem")

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_3(self):
        key_file = load_file("ecc_p224_private_p8_2.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_x509_der(self):
        key_file = load_file("ecc_p224_x509.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_public_pem(self):
        key_file = load_file("ecc_p224_public.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_private_pem(self):
        key_file = load_file("ecc_p224_private.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pem_encrypted(self):
        for algo in "des3", "aes128", "aes192", "aes256", "aes256_gcm":
            key_file = load_file("ecc_p224_private_enc_%s.pem" % algo)

            key = ECC.import_key(key_file, "secret")
            assert self.ref_private == key

            key = ECC.import_key(key_file.decode("latin-1"), b"secret")
            assert self.ref_private == key

    def test_import_x509_pem(self):
        key_file = load_file("ecc_p224_x509.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key


class TestImport_P256:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p256()

    def test_import_public_der(self):
        key_file = load_file("ecc_p256_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        assert self.ref_public == key

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_sec1_uncompressed(self):
        key_file = load_file("ecc_p256_public.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P256")
        assert self.ref_public == key

    def test_import_sec1_compressed(self):
        key_file = load_file("ecc_p256_public_compressed.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P256")
        assert self.ref_public == key

    def test_import_rfc5915_der(self):
        key_file = load_file("ecc_p256_private.der")

        key = ECC._import_rfc5915_der(key_file, None)
        assert self.ref_private == key

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_clear(self):
        key_file = load_file("ecc_p256_private_p8_clear.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_in_pem_clear(self):
        key_file = load_file("ecc_p256_private_p8_clear.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_1(self):
        key_file = load_file("ecc_p256_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_2(self):
        key_file = load_file("ecc_p256_private_p8.pem")

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_3(self):
        key_file = load_file("ecc_p256_private_p8_2.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_x509_der(self):
        key_file = load_file("ecc_p256_x509.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_public_pem(self):
        key_file = load_file("ecc_p256_public.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_private_pem(self):
        key_file = load_file("ecc_p256_private.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pem_with_ecparams(self):
        key_file = load_file("ecc_p256_private_ecparams.pem")
        ECC.import_key(key_file)
        # We just check if the import succeeds

    def test_import_private_pem_encrypted(self):
        for algo in "des3", "aes128", "aes192", "aes256", "aes256_gcm":
            key_file = load_file("ecc_p256_private_enc_%s.pem" % algo)

            key = ECC.import_key(key_file, "secret")
            assert self.ref_private == key

            key = ECC.import_key(key_file.decode("latin-1"), b"secret")
            assert self.ref_private == key

    def test_import_x509_pem(self):
        key_file = load_file("ecc_p256_x509.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_openssh_public(self):
        key_file = load_file("ecc_p256_public_openssh.txt")

        key = ECC._import_openssh_public(key_file)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_openssh_private_clear(self):
        key_file = load_file("ecc_p256_private_openssh.pem")
        key_file_old = load_file("ecc_p256_private_openssh_old.pem")

        key = ECC.import_key(key_file)
        key_old = ECC.import_key(key_file_old)
        assert key == key_old

    def test_import_openssh_private_password(self):
        key_file = load_file("ecc_p256_private_openssh_pwd.pem")
        key_file_old = load_file("ecc_p256_private_openssh_pwd_old.pem")

        key = ECC.import_key(key_file, b"password")
        key_old = ECC.import_key(key_file_old)
        assert key == key_old


class TestImport_P384:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p384()

    def test_import_public_der(self):
        key_file = load_file("ecc_p384_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        assert self.ref_public == key

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_sec1_uncompressed(self):
        key_file = load_file("ecc_p384_public.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P384")
        assert self.ref_public == key

    def test_import_sec1_compressed(self):
        key_file = load_file("ecc_p384_public_compressed.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P384")
        assert self.ref_public == key

    def test_import_rfc5915_der(self):
        key_file = load_file("ecc_p384_private.der")

        key = ECC._import_rfc5915_der(key_file, None)
        assert self.ref_private == key

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_clear(self):
        key_file = load_file("ecc_p384_private_p8_clear.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_in_pem_clear(self):
        key_file = load_file("ecc_p384_private_p8_clear.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_1(self):
        key_file = load_file("ecc_p384_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_2(self):
        key_file = load_file("ecc_p384_private_p8.pem")

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_3(self):
        key_file = load_file("ecc_p384_private_p8_2.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_x509_der(self):
        key_file = load_file("ecc_p384_x509.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_public_pem(self):
        key_file = load_file("ecc_p384_public.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_private_pem(self):
        key_file = load_file("ecc_p384_private.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pem_encrypted(self):
        for algo in "des3", "aes128", "aes192", "aes256", "aes256_gcm":
            key_file = load_file("ecc_p384_private_enc_%s.pem" % algo)

            key = ECC.import_key(key_file, "secret")
            assert self.ref_private == key

            key = ECC.import_key(key_file.decode("latin-1"), b"secret")
            assert self.ref_private == key

    def test_import_x509_pem(self):
        key_file = load_file("ecc_p384_x509.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_openssh_public(self):
        key_file = load_file("ecc_p384_public_openssh.txt")

        key = ECC._import_openssh_public(key_file)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_openssh_private_clear(self):
        key_file = load_file("ecc_p384_private_openssh.pem")
        key_file_old = load_file("ecc_p384_private_openssh_old.pem")

        key = ECC.import_key(key_file)
        key_old = ECC.import_key(key_file_old)
        assert key == key_old

    def test_import_openssh_private_password(self):
        key_file = load_file("ecc_p384_private_openssh_pwd.pem")
        key_file_old = load_file("ecc_p384_private_openssh_pwd_old.pem")

        key = ECC.import_key(key_file, b"password")
        key_old = ECC.import_key(key_file_old)
        assert key == key_old


class TestImport_P521:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p521()

    def test_import_public_der(self):
        key_file = load_file("ecc_p521_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        assert self.ref_public == key

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_sec1_uncompressed(self):
        key_file = load_file("ecc_p521_public.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P521")
        assert self.ref_public == key

    def test_import_sec1_compressed(self):
        key_file = load_file("ecc_p521_public_compressed.der")
        extract_bitstring_from_spki(key_file)
        key = ECC.import_key(key_file, curve_name="P521")
        assert self.ref_public == key

    def test_import_rfc5915_der(self):
        key_file = load_file("ecc_p521_private.der")

        key = ECC._import_rfc5915_der(key_file, None)
        assert self.ref_private == key

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_clear(self):
        key_file = load_file("ecc_p521_private_p8_clear.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_in_pem_clear(self):
        key_file = load_file("ecc_p521_private_p8_clear.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_1(self):
        key_file = load_file("ecc_p521_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_2(self):
        key_file = load_file("ecc_p521_private_p8.pem")

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_3(self):
        key_file = load_file("ecc_p521_private_p8_2.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_x509_der(self):
        key_file = load_file("ecc_p521_x509.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_public_pem(self):
        key_file = load_file("ecc_p521_public.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_private_pem(self):
        key_file = load_file("ecc_p521_private.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pem_encrypted(self):
        for algo in "des3", "aes128", "aes192", "aes256", "aes256_gcm":
            key_file = load_file("ecc_p521_private_enc_%s.pem" % algo)

            key = ECC.import_key(key_file, "secret")
            assert self.ref_private == key

            key = ECC.import_key(key_file.decode("latin-1"), b"secret")
            assert self.ref_private == key

    def test_import_x509_pem(self):
        key_file = load_file("ecc_p521_x509.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_openssh_public(self):
        key_file = load_file("ecc_p521_public_openssh.txt")

        key = ECC._import_openssh_public(key_file)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_openssh_private_clear(self):
        key_file = load_file("ecc_p521_private_openssh.pem")
        key_file_old = load_file("ecc_p521_private_openssh_old.pem")

        key = ECC.import_key(key_file)
        key_old = ECC.import_key(key_file_old)
        assert key == key_old

    def test_import_openssh_private_password(self):
        key_file = load_file("ecc_p521_private_openssh_pwd.pem")
        key_file_old = load_file("ecc_p521_private_openssh_pwd_old.pem")

        key = ECC.import_key(key_file, b"password")
        key_old = ECC.import_key(key_file_old)
        assert key == key_old


class TestExport_P192:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p192()

    def test_export_public_der_uncompressed(self):
        key_file = load_file("ecc_p192_public.der")

        encoded = self.ref_public._export_subjectPublicKeyInfo(False)
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER", compress=False)
        assert key_file == encoded

    def test_export_public_der_compressed(self):
        key_file = load_file("ecc_p192_public.der")
        pub_key = ECC.import_key(key_file)
        key_file_compressed = pub_key.export_key(format="DER", compress=True)

        key_file_compressed_ref = load_file("ecc_p192_public_compressed.der")
        assert key_file_compressed == key_file_compressed_ref

    def test_export_public_sec1_uncompressed(self):
        key_file = load_file("ecc_p192_public.der")
        value = extract_bitstring_from_spki(key_file)

        encoded = self.ref_public.export_key(format="SEC1")
        assert value == encoded

    def test_export_public_sec1_compressed(self):
        load_file("ecc_p192_public.der")
        encoded = self.ref_public.export_key(format="SEC1", compress=True)

        key_file_compressed_ref = load_file("ecc_p192_public_compressed.der")
        value = extract_bitstring_from_spki(key_file_compressed_ref)
        assert value == encoded

    def test_export_rfc5915_private_der(self):
        key_file = load_file("ecc_p192_private.der")

        encoded = self.ref_private._export_rfc5915_private_der()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pkcs8_clear(self):
        key_file = load_file("ecc_p192_private_p8_clear.der")

        encoded = self.ref_private._export_pkcs8()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER")
        assert key_file == encoded

    def test_export_private_pkcs8_encrypted(self):
        encoded = self.ref_private._export_pkcs8(
            passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC._import_pkcs8(encoded, None)

        decoded = ECC._import_pkcs8(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA224AndAES192-CBC",
            prot_params={"iteration_count": 123},
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_public_pem_uncompressed(self):
        key_file = load_file("ecc_p192_public.pem", "rt").strip()

        encoded = self.ref_private._export_public_pem(False)
        assert key_file == encoded

        # ---

        encoded = self.ref_public.export_key(format="PEM")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="PEM", compress=False)
        assert key_file == encoded

    def test_export_public_pem_compressed(self):
        key_file = load_file("ecc_p192_public.pem", "rt").strip()
        pub_key = ECC.import_key(key_file)

        key_file_compressed = pub_key.export_key(format="PEM", compress=True)
        key_file_compressed_ref = load_file("ecc_p192_public_compressed.pem", "rt").strip()

        assert key_file_compressed == key_file_compressed_ref

    def test_export_private_pem_clear(self):
        key_file = load_file("ecc_p192_private.pem", "rt").strip()

        encoded = self.ref_private._export_private_pem(None)
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pem_encrypted(self):
        encoded = self.ref_private._export_private_pem(passphrase=b"secret")

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "EC PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_private_pkcs8_and_pem_1(self):
        # PKCS8 inside PEM with both unencrypted
        key_file = load_file("ecc_p192_private_p8_clear.pem", "rt").strip()

        encoded = self.ref_private._export_private_clear_pkcs8_in_clear_pem()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM")
        assert key_file == encoded

    def test_export_private_pkcs8_and_pem_2(self):
        # PKCS8 inside PEM with PKCS8 encryption
        encoded = self.ref_private._export_private_encrypted_pkcs8_in_clear_pem(
            "secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "ENCRYPTED PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="PEM", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_prng(self):
        # Test that password-protected containers use the provided PRNG
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

        # ---

        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_byte_or_string_passphrase(self):
        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase=b"secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_error_params1(self):
        # Unknown format
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="XXX")

        # Without 'protection', PKCS#8 uses the default scheme
        self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        encoded = self.ref_private.export_key(format="PEM", passphrase="secret")
        assert "BEGIN ENCRYPTED PRIVATE KEY" in encoded
        assert ECC.import_key(encoded, "secret") == self.ref_private

        # DER format but no PKCS#8
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="DER",
                passphrase="secret",
                use_pkcs8=False,
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # Incorrect parameters for public keys
        with pytest.raises(ValueError):
            self.ref_public.export_key(format="DER", use_pkcs8=False)

        # Empty password
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="PEM", passphrase="", use_pkcs8=False)
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="PEM",
                passphrase="",
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

    def test_compressed_curve(self):
        # Compressed P-192 curve (Y-point is even)
        pem1 = """-----BEGIN EC PRIVATE KEY-----
        MF8CAQEEGHvhXmIW95JxZYfd4AUPu9BwknjuvS36aqAKBggqhkjOPQMBAaE0AzIA
        BLJZCyTu35DQIlqvMlBynn3k1Ig+dWfg/brRhHecxptrbloqFSP8ITw0CwbGF+2X
        5g==
        -----END EC PRIVATE KEY-----"""

        # Compressed P-192 curve (Y-point is odd)
        pem2 = """-----BEGIN EC PRIVATE KEY-----
        MF8CAQEEGA3rAotUaWl7d47eX6tz9JmLzOMJwl13XaAKBggqhkjOPQMBAaE0AzIA
        BG4tHlTBBBGokcWmGm2xubVB0NvPC/Ou5AYwivs+3iCxmEjsymVAj6iiuX2Lxr6g
        /Q==
        -----END EC PRIVATE KEY-----"""

        key1 = ECC.import_key(pem1)
        low16 = int(key1.pointQ.y % 65536)
        assert low16 == 0x97E6

        key2 = ECC.import_key(pem2)
        low16 = int(key2.pointQ.y % 65536)
        assert low16 == 0xA0FD


class TestExport_P224:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p224()

    def test_export_public_der_uncompressed(self):
        key_file = load_file("ecc_p224_public.der")

        encoded = self.ref_public._export_subjectPublicKeyInfo(False)
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER", compress=False)
        assert key_file == encoded

    def test_export_public_der_compressed(self):
        key_file = load_file("ecc_p224_public.der")
        pub_key = ECC.import_key(key_file)
        key_file_compressed = pub_key.export_key(format="DER", compress=True)

        key_file_compressed_ref = load_file("ecc_p224_public_compressed.der")
        assert key_file_compressed == key_file_compressed_ref

    def test_export_public_sec1_uncompressed(self):
        key_file = load_file("ecc_p224_public.der")
        value = extract_bitstring_from_spki(key_file)

        encoded = self.ref_public.export_key(format="SEC1")
        assert value == encoded

    def test_export_public_sec1_compressed(self):
        load_file("ecc_p224_public.der")
        encoded = self.ref_public.export_key(format="SEC1", compress=True)

        key_file_compressed_ref = load_file("ecc_p224_public_compressed.der")
        value = extract_bitstring_from_spki(key_file_compressed_ref)
        assert value == encoded

    def test_export_rfc5915_private_der(self):
        key_file = load_file("ecc_p224_private.der")

        encoded = self.ref_private._export_rfc5915_private_der()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pkcs8_clear(self):
        key_file = load_file("ecc_p224_private_p8_clear.der")

        encoded = self.ref_private._export_pkcs8()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER")
        assert key_file == encoded

    def test_export_private_pkcs8_encrypted(self):
        encoded = self.ref_private._export_pkcs8(
            passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC._import_pkcs8(encoded, None)

        decoded = ECC._import_pkcs8(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA512-224AndAES128-CBC",
            prot_params={"iteration_count": 123},
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_public_pem_uncompressed(self):
        key_file = load_file("ecc_p224_public.pem", "rt").strip()

        encoded = self.ref_private._export_public_pem(False)
        assert key_file == encoded

        # ---

        encoded = self.ref_public.export_key(format="PEM")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="PEM", compress=False)
        assert key_file == encoded

    def test_export_public_pem_compressed(self):
        key_file = load_file("ecc_p224_public.pem", "rt").strip()
        pub_key = ECC.import_key(key_file)

        key_file_compressed = pub_key.export_key(format="PEM", compress=True)
        key_file_compressed_ref = load_file("ecc_p224_public_compressed.pem", "rt").strip()

        assert key_file_compressed == key_file_compressed_ref

    def test_export_private_pem_clear(self):
        key_file = load_file("ecc_p224_private.pem", "rt").strip()

        encoded = self.ref_private._export_private_pem(None)
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pem_encrypted(self):
        encoded = self.ref_private._export_private_pem(passphrase=b"secret")

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "EC PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_private_pkcs8_and_pem_1(self):
        # PKCS8 inside PEM with both unencrypted
        key_file = load_file("ecc_p224_private_p8_clear.pem", "rt").strip()

        encoded = self.ref_private._export_private_clear_pkcs8_in_clear_pem()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM")
        assert key_file == encoded

    def test_export_private_pkcs8_and_pem_2(self):
        # PKCS8 inside PEM with PKCS8 encryption
        encoded = self.ref_private._export_private_encrypted_pkcs8_in_clear_pem(
            "secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "ENCRYPTED PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="PEM", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_prng(self):
        # Test that password-protected containers use the provided PRNG
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

        # ---

        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_byte_or_string_passphrase(self):
        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase=b"secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_error_params1(self):
        # Unknown format
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="XXX")

        # Without 'protection', PKCS#8 uses the default scheme
        self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        encoded = self.ref_private.export_key(format="PEM", passphrase="secret")
        assert "BEGIN ENCRYPTED PRIVATE KEY" in encoded
        assert ECC.import_key(encoded, "secret") == self.ref_private

        # DER format but no PKCS#8
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="DER",
                passphrase="secret",
                use_pkcs8=False,
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # Incorrect parameters for public keys
        with pytest.raises(ValueError):
            self.ref_public.export_key(format="DER", use_pkcs8=False)

        # Empty password
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="PEM", passphrase="", use_pkcs8=False)
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="PEM",
                passphrase="",
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

    def test_compressed_curve(self):
        # Compressed P-224 curve (Y-point is even)
        pem1 = """-----BEGIN EC PRIVATE KEY-----
        MGgCAQEEHPYicBNI9nd6wDKAX2l+f3A0Q+KWUQeMqSt5GoOgBwYFK4EEACGhPAM6
        AATCL6rUIDT14zXKoS5GQUMDP/tpc+1iI/FyEZikt2roKDkhU5q08srmqaysbfJN
        eUr7Xf1lnCVGag==
        -----END EC PRIVATE KEY-----"""

        # Compressed P-224 curve (Y-point is odd)
        pem2 = """-----BEGIN EC PRIVATE KEY-----
        MGgCAQEEHEFjbaVPLJ3ngZyCibCvT0RLUqSlHjC5Z3e0FtugBwYFK4EEACGhPAM6
        AAT5IvL2V6m48y1JLMGr6ZbnOqNKP9hMf9mxyVkk6/SaRoBoJVkXrNIpYL0P7DS7
        QF8E/OGeZRwvow==
        -----END EC PRIVATE KEY-----"""

        key1 = ECC.import_key(pem1)
        low16 = int(key1.pointQ.y % 65536)
        assert low16 == 0x466A

        key2 = ECC.import_key(pem2)
        low16 = int(key2.pointQ.y % 65536)
        assert low16 == 0x2FA3


class TestExport_P256:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p256()

    def test_export_public_der_uncompressed(self):
        key_file = load_file("ecc_p256_public.der")

        encoded = self.ref_public._export_subjectPublicKeyInfo(False)
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER", compress=False)
        assert key_file == encoded

    def test_export_public_der_compressed(self):
        key_file = load_file("ecc_p256_public.der")
        pub_key = ECC.import_key(key_file)
        key_file_compressed = pub_key.export_key(format="DER", compress=True)

        key_file_compressed_ref = load_file("ecc_p256_public_compressed.der")
        assert key_file_compressed == key_file_compressed_ref

    def test_export_public_sec1_uncompressed(self):
        key_file = load_file("ecc_p256_public.der")
        value = extract_bitstring_from_spki(key_file)

        encoded = self.ref_public.export_key(format="SEC1")
        assert value == encoded

    def test_export_public_sec1_compressed(self):
        load_file("ecc_p256_public.der")
        encoded = self.ref_public.export_key(format="SEC1", compress=True)

        key_file_compressed_ref = load_file("ecc_p256_public_compressed.der")
        value = extract_bitstring_from_spki(key_file_compressed_ref)
        assert value == encoded

    def test_export_rfc5915_private_der(self):
        key_file = load_file("ecc_p256_private.der")

        encoded = self.ref_private._export_rfc5915_private_der()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pkcs8_clear(self):
        key_file = load_file("ecc_p256_private_p8_clear.der")

        encoded = self.ref_private._export_pkcs8()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER")
        assert key_file == encoded

    def test_export_private_pkcs8_encrypted(self):
        encoded = self.ref_private._export_pkcs8(
            passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC._import_pkcs8(encoded, None)

        decoded = ECC._import_pkcs8(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA512-256AndAES128-CBC",
            prot_params={"iteration_count": 123},
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_public_pem_uncompressed(self):
        key_file = load_file("ecc_p256_public.pem", "rt").strip()

        encoded = self.ref_private._export_public_pem(False)
        assert key_file == encoded

        # ---

        encoded = self.ref_public.export_key(format="PEM")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="PEM", compress=False)
        assert key_file == encoded

    def test_export_public_pem_compressed(self):
        key_file = load_file("ecc_p256_public.pem", "rt").strip()
        pub_key = ECC.import_key(key_file)

        key_file_compressed = pub_key.export_key(format="PEM", compress=True)
        key_file_compressed_ref = load_file("ecc_p256_public_compressed.pem", "rt").strip()

        assert key_file_compressed == key_file_compressed_ref

    def test_export_private_pem_clear(self):
        key_file = load_file("ecc_p256_private.pem", "rt").strip()

        encoded = self.ref_private._export_private_pem(None)
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pem_encrypted(self):
        encoded = self.ref_private._export_private_pem(passphrase=b"secret")

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "EC PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_private_pkcs8_and_pem_1(self):
        # PKCS8 inside PEM with both unencrypted
        key_file = load_file("ecc_p256_private_p8_clear.pem", "rt").strip()

        encoded = self.ref_private._export_private_clear_pkcs8_in_clear_pem()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM")
        assert key_file == encoded

    def test_export_private_pkcs8_and_pem_2(self):
        # PKCS8 inside PEM with PKCS8 encryption
        encoded = self.ref_private._export_private_encrypted_pkcs8_in_clear_pem(
            "secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "ENCRYPTED PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="PEM", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_openssh_uncompressed(self):
        key_file = load_file("ecc_p256_public_openssh.txt", "rt")

        encoded = self.ref_public._export_openssh(False)
        assert key_file == encoded

        # ---

        encoded = self.ref_public.export_key(format="OpenSSH")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="OpenSSH", compress=False)
        assert key_file == encoded

    def test_export_openssh_compressed(self):
        key_file = load_file("ecc_p256_public_openssh.txt", "rt")
        pub_key = ECC.import_key(key_file)

        key_file_compressed = pub_key.export_key(format="OpenSSH", compress=True)
        assert len(key_file) > len(key_file_compressed)
        assert pub_key == ECC.import_key(key_file_compressed)

    def test_prng(self):
        # Test that password-protected containers use the provided PRNG
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

        # ---

        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_byte_or_string_passphrase(self):
        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase=b"secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_error_params1(self):
        # Unknown format
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="XXX")

        # Without 'protection', PKCS#8 uses the default scheme
        self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        encoded = self.ref_private.export_key(format="PEM", passphrase="secret")
        assert "BEGIN ENCRYPTED PRIVATE KEY" in encoded
        assert ECC.import_key(encoded, "secret") == self.ref_private

        # DER format but no PKCS#8
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="DER",
                passphrase="secret",
                use_pkcs8=False,
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # Incorrect parameters for public keys
        with pytest.raises(ValueError):
            self.ref_public.export_key(format="DER", use_pkcs8=False)

        # Empty password
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="PEM", passphrase="", use_pkcs8=False)
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="PEM",
                passphrase="",
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # No private keys with OpenSSH
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="OpenSSH", passphrase="secret")

    def test_compressed_curve(self):
        # Compressed P-256 curve (Y-point is even)
        pem1 = """-----BEGIN EC PRIVATE KEY-----
        MFcCAQEEIHTuc09jC51xXomV6MVCDN+DpAAvSmaJWZPTEHM6D5H1oAoGCCqGSM49
        AwEHoSQDIgACWFuGbHe8yJ43rir7PMTE9w8vHz0BSpXHq90Xi7/s+a0=
        -----END EC PRIVATE KEY-----"""

        # Compressed P-256 curve (Y-point is odd)
        pem2 = """-----BEGIN EC PRIVATE KEY-----
        MFcCAQEEIFggiPN9SQP+FAPTCPp08fRUz7rHp2qNBRcBJ1DXhb3ZoAoGCCqGSM49
        AwEHoSQDIgADLpph1trTIlVfa8NJvlMUPyWvL+wP+pW3BJITUL/wj9A=
        -----END EC PRIVATE KEY-----"""

        key1 = ECC.import_key(pem1)
        low16 = int(key1.pointQ.y % 65536)
        assert low16 == 0xA6FC

        key2 = ECC.import_key(pem2)
        low16 = int(key2.pointQ.y % 65536)
        assert low16 == 0x6E57


class TestExport_P384:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p384()

    def test_export_public_der_uncompressed(self):
        key_file = load_file("ecc_p384_public.der")

        encoded = self.ref_public._export_subjectPublicKeyInfo(False)
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER", compress=False)
        assert key_file == encoded

    def test_export_public_der_compressed(self):
        key_file = load_file("ecc_p384_public.der")
        pub_key = ECC.import_key(key_file)
        key_file_compressed = pub_key.export_key(format="DER", compress=True)

        key_file_compressed_ref = load_file("ecc_p384_public_compressed.der")
        assert key_file_compressed == key_file_compressed_ref

    def test_export_public_sec1_uncompressed(self):
        key_file = load_file("ecc_p384_public.der")
        value = extract_bitstring_from_spki(key_file)

        encoded = self.ref_public.export_key(format="SEC1")
        assert value == encoded

    def test_export_public_sec1_compressed(self):
        load_file("ecc_p384_public.der")
        encoded = self.ref_public.export_key(format="SEC1", compress=True)

        key_file_compressed_ref = load_file("ecc_p384_public_compressed.der")
        value = extract_bitstring_from_spki(key_file_compressed_ref)
        assert value == encoded

    def test_export_rfc5915_private_der(self):
        key_file = load_file("ecc_p384_private.der")

        encoded = self.ref_private._export_rfc5915_private_der()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pkcs8_clear(self):
        key_file = load_file("ecc_p384_private_p8_clear.der")

        encoded = self.ref_private._export_pkcs8()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER")
        assert key_file == encoded

    def test_export_private_pkcs8_encrypted(self):
        encoded = self.ref_private._export_pkcs8(
            passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC._import_pkcs8(encoded, None)

        decoded = ECC._import_pkcs8(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA384AndAES128-CBC",
            prot_params={"iteration_count": 123},
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_public_pem_uncompressed(self):
        key_file = load_file("ecc_p384_public.pem", "rt").strip()

        encoded = self.ref_private._export_public_pem(False)
        assert key_file == encoded

        # ---

        encoded = self.ref_public.export_key(format="PEM")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="PEM", compress=False)
        assert key_file == encoded

    def test_export_public_pem_compressed(self):
        key_file = load_file("ecc_p384_public.pem", "rt").strip()
        pub_key = ECC.import_key(key_file)

        key_file_compressed = pub_key.export_key(format="PEM", compress=True)
        key_file_compressed_ref = load_file("ecc_p384_public_compressed.pem", "rt").strip()

        assert key_file_compressed == key_file_compressed_ref

    def test_export_private_pem_clear(self):
        key_file = load_file("ecc_p384_private.pem", "rt").strip()

        encoded = self.ref_private._export_private_pem(None)
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pem_encrypted(self):
        encoded = self.ref_private._export_private_pem(passphrase=b"secret")

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "EC PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_private_pkcs8_and_pem_1(self):
        # PKCS8 inside PEM with both unencrypted
        key_file = load_file("ecc_p384_private_p8_clear.pem", "rt").strip()

        encoded = self.ref_private._export_private_clear_pkcs8_in_clear_pem()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM")
        assert key_file == encoded

    def test_export_private_pkcs8_and_pem_2(self):
        # PKCS8 inside PEM with PKCS8 encryption
        encoded = self.ref_private._export_private_encrypted_pkcs8_in_clear_pem(
            "secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "ENCRYPTED PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="PEM", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_openssh_uncompressed(self):
        key_file = load_file("ecc_p384_public_openssh.txt", "rt")

        encoded = self.ref_public._export_openssh(False)
        assert key_file == encoded

        # ---

        encoded = self.ref_public.export_key(format="OpenSSH")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="OpenSSH", compress=False)
        assert key_file == encoded

    def test_export_openssh_compressed(self):
        key_file = load_file("ecc_p384_public_openssh.txt", "rt")
        pub_key = ECC.import_key(key_file)

        key_file_compressed = pub_key.export_key(format="OpenSSH", compress=True)
        assert len(key_file) > len(key_file_compressed)
        assert pub_key == ECC.import_key(key_file_compressed)

    def test_prng(self):
        # Test that password-protected containers use the provided PRNG
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

        # ---

        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_byte_or_string_passphrase(self):
        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase=b"secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_error_params1(self):
        # Unknown format
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="XXX")

        # Without 'protection', PKCS#8 uses the default scheme
        self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        encoded = self.ref_private.export_key(format="PEM", passphrase="secret")
        assert "BEGIN ENCRYPTED PRIVATE KEY" in encoded
        assert ECC.import_key(encoded, "secret") == self.ref_private

        # DER format but no PKCS#8
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="DER",
                passphrase="secret",
                use_pkcs8=False,
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # Incorrect parameters for public keys
        with pytest.raises(ValueError):
            self.ref_public.export_key(format="DER", use_pkcs8=False)

        # Empty password
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="PEM", passphrase="", use_pkcs8=False)
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="PEM",
                passphrase="",
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # No private keys with OpenSSH
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="OpenSSH", passphrase="secret")

    def test_compressed_curve(self):
        # Compressed P-384 curve (Y-point is even)
        # openssl ecparam -name secp384p1 -genkey -noout -conv_form compressed -out /tmp/a.pem
        # openssl ec -in /tmp/a.pem -text -noout
        pem1 = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAM0lEIhvXuekK2SWtdbgOcZtBaxa9TxfpO/GcDFZLCJ3JVXaTgwken
QT+C+XLtD6WgBwYFK4EEACKhZANiAATs0kZMhFDu8DoBC21jrSDPyAUn4aXZ/DM4
ylhDfWmb4LEbeszXceIzfhIUaaGs5y1xXaqf5KXTiAAYx2pKUzAAM9lcGUHCGKJG
k4AgUmVJON29XoUilcFrzjDmuye3B6Q=
-----END EC PRIVATE KEY-----"""

        # Compressed P-384 curve (Y-point is odd)
        pem2 = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDHPFTslYLltE16fHdSDTtE/2HTmd3M8mqy5MttAm4wZ833KXiGS9oe
kFdx9sNV0KygBwYFK4EEACKhZANiAASLIE5RqVMtNhtBH/u/p/ifqOAlKnK/+RrQ
YC46ZRsnKNayw3wATdPjgja7L/DSII3nZK0G6KOOVwJBznT/e+zudUJYhZKaBLRx
/bgXyxUtYClOXxb1Y/5N7txLstYRyP0=
-----END EC PRIVATE KEY-----"""

        key1 = ECC.import_key(pem1)
        low16 = int(key1.pointQ.y % 65536)
        assert low16 == 0x07A4

        key2 = ECC.import_key(pem2)
        low16 = int(key2.pointQ.y % 65536)
        assert low16 == 0xC8FD


class TestExport_P521:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_p521()

    def test_export_public_der_uncompressed(self):
        key_file = load_file("ecc_p521_public.der")

        encoded = self.ref_public._export_subjectPublicKeyInfo(False)
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER", compress=False)
        assert key_file == encoded

    def test_export_public_der_compressed(self):
        key_file = load_file("ecc_p521_public.der")
        pub_key = ECC.import_key(key_file)
        key_file_compressed = pub_key.export_key(format="DER", compress=True)

        key_file_compressed_ref = load_file("ecc_p521_public_compressed.der")
        assert key_file_compressed == key_file_compressed_ref

    def test_export_public_sec1_uncompressed(self):
        key_file = load_file("ecc_p521_public.der")
        value = extract_bitstring_from_spki(key_file)

        encoded = self.ref_public.export_key(format="SEC1")
        assert value == encoded

        encoded = self.ref_public.export_key(format="raw")
        assert value == encoded

    def test_export_public_sec1_compressed(self):
        load_file("ecc_p521_public.der")
        encoded = self.ref_public.export_key(format="SEC1", compress=True)

        key_file_compressed_ref = load_file("ecc_p521_public_compressed.der")
        value = extract_bitstring_from_spki(key_file_compressed_ref)
        assert value == encoded

        encoded = self.ref_public.export_key(format="raw", compress=True)
        assert value == encoded

    def test_export_rfc5915_private_der(self):
        key_file = load_file("ecc_p521_private.der")

        encoded = self.ref_private._export_rfc5915_private_der()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pkcs8_clear(self):
        key_file = load_file("ecc_p521_private_p8_clear.der")

        encoded = self.ref_private._export_pkcs8()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER")
        assert key_file == encoded

    def test_export_private_pkcs8_encrypted(self):
        encoded = self.ref_private._export_pkcs8(
            passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC._import_pkcs8(encoded, None)

        decoded = ECC._import_pkcs8(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            prot_params={"iteration_count": 123},
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_public_pem_uncompressed(self):
        key_file = load_file("ecc_p521_public.pem", "rt").strip()

        encoded = self.ref_private._export_public_pem(False)
        assert key_file == encoded

        # ---

        encoded = self.ref_public.export_key(format="PEM")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="PEM", compress=False)
        assert key_file == encoded

    def test_export_public_pem_compressed(self):
        key_file = load_file("ecc_p521_public.pem", "rt").strip()
        pub_key = ECC.import_key(key_file)

        key_file_compressed = pub_key.export_key(format="PEM", compress=True)
        key_file_compressed_ref = load_file("ecc_p521_public_compressed.pem", "rt").strip()

        assert key_file_compressed == key_file_compressed_ref

    def test_export_private_pem_clear(self):
        key_file = load_file("ecc_p521_private.pem", "rt").strip()

        encoded = self.ref_private._export_private_pem(None)
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", use_pkcs8=False)
        assert key_file == encoded

    def test_export_private_pem_encrypted(self):
        encoded = self.ref_private._export_private_pem(passphrase=b"secret")

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "EC PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_private_pkcs8_and_pem_1(self):
        # PKCS8 inside PEM with both unencrypted
        key_file = load_file("ecc_p521_private_p8_clear.pem", "rt").strip()

        encoded = self.ref_private._export_private_clear_pkcs8_in_clear_pem()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="PEM")
        assert key_file == encoded

    def test_export_private_pkcs8_and_pem_2(self):
        # PKCS8 inside PEM with PKCS8 encryption
        encoded = self.ref_private._export_private_encrypted_pkcs8_in_clear_pem(
            "secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "ENCRYPTED PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="PEM", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_openssh_uncompressed(self):
        key_file = load_file("ecc_p521_public_openssh.txt", "rt")

        encoded = self.ref_public._export_openssh(False)
        assert key_file == encoded

        # ---

        encoded = self.ref_public.export_key(format="OpenSSH")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="OpenSSH", compress=False)
        assert key_file == encoded

    def test_export_openssh_compressed(self):
        key_file = load_file("ecc_p521_public_openssh.txt", "rt")
        pub_key = ECC.import_key(key_file)

        key_file_compressed = pub_key.export_key(format="OpenSSH", compress=True)
        assert len(key_file) > len(key_file_compressed)
        assert pub_key == ECC.import_key(key_file_compressed)

    def test_prng(self):
        # Test that password-protected containers use the provided PRNG
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

        # ---

        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_byte_or_string_passphrase(self):
        encoded1 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase="secret", randfunc=get_fixed_prng()
        )
        encoded2 = self.ref_private.export_key(
            format="PEM", use_pkcs8=False, passphrase=b"secret", randfunc=get_fixed_prng()
        )
        assert encoded1 == encoded2

    def test_error_params1(self):
        # Unknown format
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="XXX")

        # Without 'protection', PKCS#8 uses the default scheme
        self.ref_private.export_key(format="PEM", passphrase="secret", use_pkcs8=False)
        encoded = self.ref_private.export_key(format="PEM", passphrase="secret")
        assert "BEGIN ENCRYPTED PRIVATE KEY" in encoded
        assert ECC.import_key(encoded, "secret") == self.ref_private

        # DER format but no PKCS#8
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="DER",
                passphrase="secret",
                use_pkcs8=False,
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # Incorrect parameters for public keys
        with pytest.raises(ValueError):
            self.ref_public.export_key(format="DER", use_pkcs8=False)

        # Empty password
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="PEM", passphrase="", use_pkcs8=False)
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="PEM",
                passphrase="",
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # No private keys with OpenSSH
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="OpenSSH", passphrase="secret")

    def test_compressed_curve(self):
        # Compressed P-521 curve (Y-point is even)
        # openssl ecparam -name secp521r1 -genkey -noout -conv_form compressed -out /tmp/a.pem
        # openssl ec -in /tmp/a.pem -text -noout
        pem1 = """-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAnm1CEjVjvNfXEN730p+D6su5l+mOztdc5XmTEoti+s2R4GQ4mAv3
0zYLvyklvOHw0+yy8d0cyGEJGb8T3ZVKmg2gBwYFK4EEACOhgYkDgYYABAHzjTI1
ckxQ3Togi0LAxiG0PucdBBBs5oIy3df95xv6SInp70z+4qQ2EltEmdNMssH8eOrl
M5CYdZ6nbcHMVaJUvQEzTrYxvFjOgJiOd+E9eBWbLkbMNqsh1UKVO6HbMbW0ohCI
uGxO8tM6r3w89/qzpG2SvFM/fvv3mIR30wSZDD84qA==
-----END EC PRIVATE KEY-----"""

        # Compressed P-521 curve (Y-point is odd)
        pem2 = """-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB84OfhJluLBRLn3+cC/RQ37C2SfQVP/t0gQK2tCsTf5avRcWYRrOJ
PmX9lNnkC0Hobd75QFRmdxrB0Wd1/M4jZOWgBwYFK4EEACOhgYkDgYYABAAMZcdJ
1YLCGHt3bHCEzdidVy6+brlJIbv1aQ9fPQLF7WKNv4c8w3H8d5a2+SDZilBOsk5c
6cNJDMz2ExWQvxl4CwDJtJGt1+LHVKFGy73NANqVxMbRu+2F8lOxkNp/ziFTbVyV
vv6oYkMIIi7r5oQWAiQDrR2mlrrFDL9V7GH/r8SWQw==
-----END EC PRIVATE KEY-----"""

        key1 = ECC.import_key(pem1)
        low16 = int(key1.pointQ.y % 65536)
        assert low16 == 0x38A8

        key2 = ECC.import_key(pem2)
        low16 = int(key2.pointQ.y % 65536)
        assert low16 == 0x9643


def _patch_openssh_rounds(pem, rounds):
    """Return the encrypted OpenSSH private key ``pem``, with another
    number of rounds for bcrypt_pbkdf."""
    import base64
    import struct

    lines = pem.decode().strip().splitlines()
    body = base64.b64decode("".join(lines[1:-1]))
    prefix = b"openssh-key-v1\x00"
    pos = len(prefix)
    for _ in range(2):  # ciphername, kdfname
        pos += 4 + struct.unpack(">I", body[pos : pos + 4])[0]
    salt_len = struct.unpack(">I", body[pos + 4 : pos + 8])[0]
    rounds_pos = pos + 8 + salt_len
    body = body[:rounds_pos] + struct.pack(">I", rounds) + body[rounds_pos + 4 :]
    b64 = base64.b64encode(body).decode()
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    return (
        "%s\n%s\n%s\n"
        % (pem.decode().splitlines()[0], "\n".join(lines), pem.decode().strip().splitlines()[-1])
    ).encode()


class TestImportOpenSSHLimits:
    """The number of rounds of bcrypt_pbkdf in an encrypted OpenSSH key
    is limited by max_iteration_count (the vector has 16 rounds)."""

    def setup_method(self):
        self.pem = load_file("ecc_ed25519_private_openssh_pwd.pem")
        self.ref = ECC.import_key(self.pem, b"password")

    def test_rounds_of_the_vector(self):
        assert _patch_openssh_rounds(self.pem, 16).strip() == self.pem.strip().replace(b"\r", b"")

    def test_explicit_limit(self):
        for limit in (16, 17, 0, None):
            assert ECC.import_key(self.pem, b"password", max_iteration_count=limit) == self.ref
        with pytest.raises(KdfIterationLimitError, match="bcrypt_pbkdf rounds count of 16"):
            ECC.import_key(self.pem, b"password", max_iteration_count=15)

    def test_default_limit(self):
        from Crypto.IO._PBES import _DEFAULT_LIMIT, _DEFAULT_MAX_BCRYPT_ROUNDS

        rounds = _DEFAULT_MAX_BCRYPT_ROUNDS + 1
        with pytest.raises(KdfIterationLimitError) as ctx:
            ECC.import_key(_patch_openssh_rounds(self.pem, rounds), b"password")
        assert "of %d," % rounds in str(ctx.value)
        assert _DEFAULT_LIMIT.format(_DEFAULT_MAX_BCRYPT_ROUNDS) in str(ctx.value)

    @pytest.mark.parametrize("rounds", [2**31, 2**32 - 1])
    def test_huge_rounds(self, rounds):
        # Rejected before any key derivation, even with a high explicit limit
        with pytest.raises(KdfIterationLimitError):
            ECC.import_key(_patch_openssh_rounds(self.pem, rounds), b"password")
        with pytest.raises(KdfIterationLimitError):
            ECC.import_key(_patch_openssh_rounds(self.pem, rounds), b"password", max_iteration_count=10**6)

    def test_zero_rounds(self):
        with pytest.raises(ValueError, match="Invalid bcrypt_pbkdf rounds count"):
            ECC.import_key(_patch_openssh_rounds(self.pem, 0), b"password", max_iteration_count=0)


class TestImport_Ed25519:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_ed25519()

    def test_import_public_der(self):
        key_file = load_file("ecc_ed25519_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        assert self.ref_public == key

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_pkcs8_der(self):
        key_file = load_file("ecc_ed25519_private.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_1(self):
        key_file = load_file("ecc_ed25519_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_2(self):
        key_file = load_file("ecc_ed25519_private_p8.pem")

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_3(self):
        key_file = load_file("ecc_ed25519_private_p8_2.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_x509_der(self):
        key_file = load_file("ecc_ed25519_x509.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_public_pem(self):
        key_file = load_file("ecc_ed25519_public.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_private_pem(self):
        key_file = load_file("ecc_ed25519_private.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pem_encrypted(self):
        for algo in "des3", "aes128", "aes192", "aes256":
            key_file = load_file("ecc_ed25519_private_enc_%s.pem" % algo)

            key = ECC.import_key(key_file, "secret")
            assert self.ref_private == key

            key = ECC.import_key(key_file.decode("latin-1"), b"secret")
            assert self.ref_private == key

    def test_import_x509_pem(self):
        key_file = load_file("ecc_ed25519_x509.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_openssh_public(self):
        key_file = load_file("ecc_ed25519_public_openssh.txt")
        key = ECC._import_openssh_public(key_file)
        assert not key.has_private()
        key = ECC.import_key(key_file)
        assert not key.has_private()

    def test_import_openssh_private_clear(self):
        key_file = load_file("ecc_ed25519_private_openssh.pem")
        ECC.import_key(key_file)

    def test_import_openssh_private_password(self):
        key_file = load_file("ecc_ed25519_private_openssh_pwd.pem")
        ECC.import_key(key_file, b"password")


class TestExport_Ed25519:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_ed25519()

    def test_export_public_der(self):
        key_file = load_file("ecc_ed25519_public.der")

        encoded = self.ref_public._export_subjectPublicKeyInfo(True)
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER", compress=False)
        assert key_file == encoded

    def test_export_public_sec1(self):
        with pytest.raises(ValueError):
            self.ref_public.export_key(format="SEC1")

    def test_export_private_pkcs8_clear(self):
        key_file = load_file("ecc_ed25519_private.der")

        encoded = self.ref_private._export_pkcs8()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER")
        assert key_file == encoded

        with pytest.raises(ValueError):
            self.ref_private.export_key(format="DER", use_pkcs8=False)

    def test_export_private_pkcs8_encrypted(self):
        encoded = self.ref_private._export_pkcs8(
            passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC._import_pkcs8(encoded, None)

        decoded = ECC._import_pkcs8(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA256AndAES128-CBC",
            prot_params={"iteration_count": 123},
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_public_pem(self):
        key_file_ref = load_file("ecc_ed25519_public.pem", "rt").strip()
        key_file = self.ref_public.export_key(format="PEM").strip()
        assert key_file_ref == key_file

    def test_export_private_pem_clear(self):
        key_file = load_file("ecc_ed25519_private.pem", "rt").strip()
        encoded = self.ref_private.export_key(format="PEM").strip()
        assert key_file == encoded

    def test_export_private_pem_encrypted(self):
        encoded = self.ref_private.export_key(
            format="PEM", passphrase=b"secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "ENCRYPTED PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_openssh(self):
        key_file = load_file("ecc_ed25519_public_openssh.txt", "rt")
        public_key = ECC.import_key(key_file)
        key_file = " ".join(key_file.split(" ")[:2])  # remove comment

        encoded = public_key._export_openssh(False)
        assert key_file == encoded.strip()

        encoded = public_key.export_key(format="OpenSSH")
        assert key_file == encoded.strip()

    def test_export_raw(self):
        encoded = self.ref_public.export_key(format="raw")
        assert encoded == unhexlify(b"bc85b8cf585d20a4de47e84d1cb6183f63d9ba96223fcbc886e363ffdea20cff")

    def test_prng(self):
        # Test that password-protected containers use the provided PRNG
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

    def test_byte_or_string_passphrase(self):
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase=b"secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

    def test_error_params1(self):
        # Unknown format
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="XXX")

        # Without 'protection', PKCS#8 uses the default scheme
        encoded = self.ref_private.export_key(format="PEM", passphrase="secret")
        assert "BEGIN ENCRYPTED PRIVATE KEY" in encoded
        assert ECC.import_key(encoded, "secret") == self.ref_private

        # Empty password
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="PEM", passphrase="", use_pkcs8=False)
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="PEM",
                passphrase="",
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # No private keys with OpenSSH
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="OpenSSH", passphrase="secret")


class TestImport_Ed448:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_ed448()

    def test_import_public_der(self):
        key_file = load_file("ecc_ed448_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        assert self.ref_public == key

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_pkcs8_der(self):
        key_file = load_file("ecc_ed448_private.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_1(self):
        key_file = load_file("ecc_ed448_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_2(self):
        key_file = load_file("ecc_ed448_private_p8.pem")

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_3(self):
        key_file = load_file("ecc_ed448_private_p8_2.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_x509_der(self):
        key_file = load_file("ecc_ed448_x509.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_public_pem(self):
        key_file = load_file("ecc_ed448_public.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_private_pem(self):
        key_file = load_file("ecc_ed448_private.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pem_encrypted(self):
        for algo in "des3", "aes128", "aes192", "aes256":
            key_file = load_file("ecc_ed448_private_enc_%s.pem" % algo)

            key = ECC.import_key(key_file, "secret")
            assert self.ref_private == key

            key = ECC.import_key(key_file.decode("latin-1"), b"secret")
            assert self.ref_private == key

    def test_import_x509_pem(self):
        key_file = load_file("ecc_ed448_x509.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key


class TestExport_Ed448:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_ed448()

    def test_export_public_der(self):
        key_file = load_file("ecc_ed448_public.der")

        encoded = self.ref_public._export_subjectPublicKeyInfo(True)
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER", compress=False)
        assert key_file == encoded

    def test_export_public_sec1(self):
        with pytest.raises(ValueError):
            self.ref_public.export_key(format="SEC1")

    def test_export_private_pkcs8_clear(self):
        key_file = load_file("ecc_ed448_private.der")

        encoded = self.ref_private._export_pkcs8()
        assert key_file == encoded

        # ---

        encoded = self.ref_private.export_key(format="DER")
        assert key_file == encoded

        with pytest.raises(ValueError):
            self.ref_private.export_key(format="DER", use_pkcs8=False)

    def test_export_private_pkcs8_encrypted(self):
        encoded = self.ref_private._export_pkcs8(
            passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC._import_pkcs8(encoded, None)

        decoded = ECC._import_pkcs8(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER", passphrase="secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

        # ---

        encoded = self.ref_private.export_key(
            format="DER",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA384AndAES128-CBC",
            prot_params={"iteration_count": 123},
        )
        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_public_pem(self):
        key_file_ref = load_file("ecc_ed448_public.pem", "rt").strip()
        key_file = self.ref_public.export_key(format="PEM").strip()
        assert key_file_ref == key_file

    def test_export_private_pem_clear(self):
        key_file = load_file("ecc_ed448_private.pem", "rt").strip()
        encoded = self.ref_private.export_key(format="PEM").strip()
        assert key_file == encoded

    def test_export_private_pem_encrypted(self):
        encoded = self.ref_private.export_key(
            format="PEM", passphrase=b"secret", protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
        )

        # This should prove that the output is password-protected
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

        assert "ENCRYPTED PRIVATE KEY" in encoded

        decoded = ECC.import_key(encoded, "secret")
        assert self.ref_private == decoded

    def test_export_openssh(self):
        # Not supported
        with pytest.raises(ValueError):
            self.ref_public.export_key(format="OpenSSH")

    def test_export_raw(self):
        encoded = self.ref_public.export_key(format="raw")
        assert encoded == unhexlify(
            b"899014ddc0a0e1260cfc1085afdf952019e9fd63372e3e366e26dad32b176624884330a14617237e3081febd9d1a15069e7499433d2f55dd80"
        )

    def test_prng(self):
        # Test that password-protected containers use the provided PRNG
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

    def test_byte_or_string_passphrase(self):
        encoded1 = self.ref_private.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        encoded2 = self.ref_private.export_key(
            format="PEM",
            passphrase=b"secret",
            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            randfunc=get_fixed_prng(),
        )
        assert encoded1 == encoded2

    def test_error_params1(self):
        # Unknown format
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="XXX")

        # Without 'protection', PKCS#8 uses the default scheme
        encoded = self.ref_private.export_key(format="PEM", passphrase="secret")
        assert "BEGIN ENCRYPTED PRIVATE KEY" in encoded
        assert ECC.import_key(encoded, "secret") == self.ref_private

        # Empty password
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="PEM", passphrase="", use_pkcs8=False)
        with pytest.raises(ValueError):
            self.ref_private.export_key(
                format="PEM",
                passphrase="",
                protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
            )

        # No private keys with OpenSSH
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="OpenSSH", passphrase="secret")


@pytest.mark.parametrize("curve", ["p256", "ed25519", "curve25519"])
class TestExportPassphrase:
    def test_empty_passphrase(self, curve):
        key = ECC.generate(curve=curve)
        for fmt in ("PEM", "DER"):
            for pwd in ("", b"", bytearray()):
                with pytest.raises(ValueError, match="Empty passphrase"):
                    key.export_key(format=fmt, passphrase=pwd)

    def test_protection_without_passphrase(self, curve):
        key = ECC.generate(curve=curve)
        for fmt in ("PEM", "DER"):
            with pytest.raises(ValueError, match="require a passphrase"):
                key.export_key(format=fmt, protection="PBKDF2WithHMAC-SHA256AndAES256-CBC")
            with pytest.raises(ValueError, match="require a passphrase"):
                key.export_key(format=fmt, prot_params={"iteration_count": 2000})


ALL_CURVES = ["p192", "p224", "p256", "p384", "p521", "ed25519", "ed448", "curve25519", "curve448"]


def _pkcs8_v2(key, public_key):
    """Wrap again a private ECC key as a OneAsymmetricKey v2 (RFC 5958),
    with the given publicKey"""

    from Crypto.IO import PKCS8
    from Crypto.Util.asn1 import DerObject

    oid, private_key, params = PKCS8.unwrap(key.export_key(format="DER"))
    key_params = DerObject().decode(params) if params else None
    return PKCS8.wrap(private_key, oid, key_params=key_params, public_key=public_key)


def _public_key_bytes(key):
    """The public key as in the subjectPublicKeyInfo"""

    from Crypto.PublicKey import _expand_subject_public_key_info

    return _expand_subject_public_key_info(key.public_key().export_key(format="DER"))[1]


@pytest.mark.parametrize("curve", ALL_CURVES)
class TestImportPKCS8PublicKey:
    """The publicKey of a OneAsymmetricKey v2 (RFC 5958) must match the private key"""

    def test_match(self, curve):
        key = ECC.generate(curve=curve)
        encoded = _pkcs8_v2(key, _public_key_bytes(key))
        assert ECC.import_key(encoded) == key

    def test_mismatch(self, curve):
        key = ECC.generate(curve=curve)
        other = ECC.generate(curve=curve)
        encoded = _pkcs8_v2(key, _public_key_bytes(other))
        with pytest.raises(ValueError, match="do not match"):
            ECC._import_pkcs8(encoded, None)
        with pytest.raises(ValueError):
            ECC.import_key(encoded)

    def test_invalid(self, curve):
        key = ECC.generate(curve=curve)
        encoded = _pkcs8_v2(key, _public_key_bytes(key)[:-1])
        with pytest.raises(ValueError):
            ECC._import_pkcs8(encoded, None)


@pytest.mark.parametrize("curve", ["p192", "p256", "p521"])
def test_import_pkcs8_compressed_public_key(curve):
    # The publicKey of a NIST curve can be a compressed ECPoint too
    key = ECC.generate(curve=curve)
    compressed = key.public_key().export_key(format="SEC1", compress=True)
    assert ECC.import_key(_pkcs8_v2(key, compressed)) == key


def test_import_pkcs8_v2_rfc8410():
    # RFC 8410, Section 10.3 (with attributes and publicKey)
    encoded = """-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----"""
    key = ECC.import_key(encoded)
    assert key.seed == unhexlify("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
    assert _public_key_bytes(key) == unhexlify(
        "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )


@pytest.mark.parametrize("curve", ["p256", "ed25519", "curve25519"])
class TestExportKeyParameters:
    """The keyword parameters of EccKey.export_key()"""

    def test_randfunc(self, curve):
        # randfunc reaches the PKCS#8 encryption (salt and IV)
        key = ECC.generate(curve=curve)
        prot = {"passphrase": "pw", "prot_params": {"iteration_count": 1000}}
        for fmt in ("PEM", "DER"):
            out1 = key.export_key(format=fmt, randfunc=lambda n: b"\x01" * n, **prot)
            out2 = key.export_key(format=fmt, randfunc=lambda n: b"\x01" * n, **prot)
            assert out1 == out2
            assert ECC.import_key(out1, "pw") == key

    def test_public_key_defaults(self, curve):
        # Private-only parameters with their default values are accepted for a public key
        key = ECC.generate(curve=curve).public_key()
        out = key.export_key(format="DER", passphrase=None, use_pkcs8=True, protection=None, threads=1)
        assert out == key.export_key(format="DER")
        with pytest.raises(ValueError, match="Unexpected parameters"):
            key.export_key(format="DER", passphrase="pw")
        with pytest.raises(ValueError, match="Unexpected parameters"):
            key.export_key(format="DER", randfunc=lambda n: b"\x01" * n)

    def test_unknown_parameter(self, curve):
        key = ECC.generate(curve=curve)
        for k in (key, key.public_key()):
            with pytest.raises(TypeError):
                k.export_key(format="PEM", unknown=1)
            with pytest.raises(TypeError):
                k.export_key()
