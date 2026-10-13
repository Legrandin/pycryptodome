#
#  SelfTest/PublicKey/test_import_passphrase.py: Self-test for the
#  exceptions raised when importing encrypted private keys
#
# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import errno
import os

import pytest

from Crypto import IncorrectPassphraseError, KdfIterationLimitError, PassphraseRequiredError
from Crypto.IO import PEM, PKCS8
from Crypto.PublicKey import DSA, ECC, RSA
from Crypto.SelfTest.loader import warn_skipped_tests

try:
    import pycryptodome_test_vectors

    test_vectors_available = True
except ImportError:
    test_vectors_available = False


def load_file(sub_dir, file_name):
    try:
        if not test_vectors_available:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_name)
        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        with open(os.path.join(init_dir, "PublicKey", sub_dir, file_name), "rb") as file_in:
            return file_in.read()
    except FileNotFoundError:
        warn_skipped_tests("Skipping tests for encrypted OpenSSH keys")
        pytest.skip("Missing %s" % file_name)


# A fast key derivation, for the tests that try many passphrases
FAST = {"iteration_count": 1}
CBC = "PBKDF2WithHMAC-SHA256AndAES128-CBC"
GCM = "PBKDF2WithHMAC-SHA256AndAES256-GCM"
SCRYPT = "scryptAndAES256-CBC"


@pytest.fixture(scope="module")
def keys():
    return {
        "RSA": RSA.generate(1024),
        "DSA": DSA.generate(1024),
        "ECC": ECC.generate(curve="p256"),
        "Ed25519": ECC.generate(curve="Ed25519"),
    }


# Each item: (description, module to import with, function that takes
# the keys and returns the key encrypted with the passphrase "pw")
ENCRYPTED = [
    ("RSA PEM PKCS#1", RSA, lambda k: k["RSA"].export_key("PEM", passphrase="pw", pkcs=1)),
    (
        "RSA PEM PKCS#8 CBC",
        RSA,
        lambda k: k["RSA"].export_key("PEM", passphrase="pw", pkcs=8, protection=CBC),
    ),
    (
        "RSA DER PKCS#8 CBC",
        RSA,
        lambda k: k["RSA"].export_key("DER", passphrase="pw", pkcs=8, protection=CBC),
    ),
    (
        "RSA DER PKCS#8 GCM",
        RSA,
        lambda k: k["RSA"].export_key("DER", passphrase="pw", pkcs=8, protection=GCM),
    ),
    (
        "RSA DER PKCS#8 scrypt",
        RSA,
        lambda k: k["RSA"].export_key(
            "DER", passphrase="pw", pkcs=8, protection=SCRYPT, prot_params={"iteration_count": 1024}
        ),
    ),
    ("DSA PEM", DSA, lambda k: k["DSA"].export_key("PEM", passphrase="pw", pkcs8=False)),
    ("DSA PEM PKCS#8", DSA, lambda k: k["DSA"].export_key("PEM", passphrase="pw", protection=CBC)),
    ("DSA DER PKCS#8", DSA, lambda k: k["DSA"].export_key("DER", passphrase="pw", protection=CBC)),
    ("ECC PEM SEC1", ECC, lambda k: k["ECC"].export_key(format="PEM", passphrase="pw", use_pkcs8=False)),
    ("ECC PEM PKCS#8", ECC, lambda k: k["ECC"].export_key(format="PEM", passphrase="pw", protection=CBC)),
    ("ECC DER PKCS#8", ECC, lambda k: k["ECC"].export_key(format="DER", passphrase="pw", protection=CBC)),
    (
        "Ed25519 DER PKCS#8",
        ECC,
        lambda k: k["Ed25519"].export_key(format="DER", passphrase="pw", protection=GCM),
    ),
]


@pytest.mark.parametrize(
    "module, make", [(m, f) for (_, m, f) in ENCRYPTED], ids=[d for (d, _, _) in ENCRYPTED]
)
class TestEncryptedKey:
    def test_no_passphrase(self, keys, module, make):
        with pytest.raises(PassphraseRequiredError):
            module.import_key(make(keys))

    def test_incorrect_passphrase(self, keys, module, make):
        with pytest.raises(IncorrectPassphraseError):
            module.import_key(make(keys), passphrase="wrong")

    def test_correct_passphrase(self, keys, module, make):
        assert module.import_key(make(keys), passphrase="pw").has_private()

    def test_value_error(self, keys, module, make):
        # Both are still a ValueError, as before
        with pytest.raises(ValueError):
            module.import_key(make(keys))
        with pytest.raises(ValueError):
            module.import_key(make(keys), passphrase="wrong")


OPENSSH = [
    ("RSA", RSA, "rsa2048_private_openssh_pwd.pem"),
    ("ECC", ECC, "ecc_p256_private_openssh_pwd.pem"),
    ("ECC", ECC, "ecc_p384_private_openssh_pwd.pem"),
    ("ECC", ECC, "ecc_ed25519_private_openssh_pwd.pem"),
]


@pytest.mark.parametrize("sub_dir, module, file_name", OPENSSH, ids=[f for (_, _, f) in OPENSSH])
class TestEncryptedOpenSSH:
    def test_no_passphrase(self, sub_dir, module, file_name):
        with pytest.raises(PassphraseRequiredError):
            module.import_key(load_file(sub_dir, file_name))

    def test_incorrect_passphrase(self, sub_dir, module, file_name):
        with pytest.raises(IncorrectPassphraseError):
            module.import_key(load_file(sub_dir, file_name), passphrase="wrong")

    def test_correct_passphrase(self, sub_dir, module, file_name):
        assert module.import_key(load_file(sub_dir, file_name), passphrase="password").has_private()


class TestManyIncorrectPassphrases:
    """With CBC, an incorrect passphrase gives a correct padding about once
    in 256 times: the error must be the same then."""

    def test_pkcs8(self, keys):
        encrypted = keys["ECC"].export_key(format="DER", passphrase="pw", protection=CBC, prot_params=FAST)
        for i in range(1000):
            with pytest.raises(IncorrectPassphraseError):
                ECC.import_key(encrypted, passphrase="wrong%d" % i)

    def test_pem(self, keys):
        encrypted = keys["ECC"].export_key(format="PEM", passphrase="pw", use_pkcs8=False)
        for i in range(1000):
            with pytest.raises(IncorrectPassphraseError):
                ECC.import_key(encrypted, passphrase="wrong%d" % i)


class TestOtherErrors:
    """The errors not about the passphrase remain a plain ValueError."""

    @staticmethod
    def assert_plain_value_error(func):
        with pytest.raises(ValueError) as excinfo:
            func()
        assert not isinstance(excinfo.value, (PassphraseRequiredError, IncorrectPassphraseError))

    @pytest.mark.parametrize("module", [RSA, DSA, ECC], ids=["RSA", "DSA", "ECC"])
    def test_garbage(self, module):
        self.assert_plain_value_error(lambda: module.import_key(b"hello world"))
        self.assert_plain_value_error(lambda: module.import_key(b"hello world", passphrase="pw"))

    def test_other_key_type(self, keys):
        # A public key has the same outer structure as an encrypted PKCS#8 key
        ecc_public = keys["ECC"].public_key().export_key(format="DER")
        self.assert_plain_value_error(lambda: RSA.import_key(ecc_public))
        self.assert_plain_value_error(lambda: DSA.import_key(ecc_public))

    def test_other_key_type_encrypted(self, keys):
        # Decrypted with the correct passphrase, but not an RSA key
        encrypted = keys["ECC"].export_key(format="DER", passphrase="pw", protection=CBC, prot_params=FAST)
        self.assert_plain_value_error(lambda: RSA.import_key(encrypted, passphrase="pw"))

    def test_corrupted_clear_pem(self, keys):
        pem = keys["RSA"].export_key("PEM").decode()
        corrupted = pem[:200] + "AAAA" + pem[204:]
        self.assert_plain_value_error(lambda: RSA.import_key(corrupted))

    def test_unsupported_encryption(self, keys):
        encrypted = keys["ECC"].export_key(format="DER", passphrase="pw", protection=CBC, prot_params=FAST)
        # Change the PBES2 OID (1.2.840.113549.1.5.13) into an unknown one
        pbes2_oid = bytes.fromhex("06092a864886f70d01050d")
        assert pbes2_oid in encrypted
        unknown = encrypted.replace(pbes2_oid, pbes2_oid[:-1] + b"\x7f")
        self.assert_plain_value_error(lambda: ECC.import_key(unknown, passphrase="pw"))

    def test_kdf_limit(self, keys):
        # The limit on the key derivation is checked first, whatever the passphrase
        encrypted = keys["ECC"].export_key(
            format="DER", passphrase="pw", protection=CBC, prot_params={"iteration_count": 2}
        )
        for passphrase in ("pw", "wrong"):
            with pytest.raises(KdfIterationLimitError):
                ECC.import_key(encrypted, passphrase=passphrase, max_iteration_count=1)


class TestClearKey:
    def test_passphrase_is_ignored(self, keys):
        for data in (
            keys["RSA"].export_key("DER", pkcs=8),
            keys["RSA"].export_key("PEM"),
        ):
            assert RSA.import_key(data, passphrase="pw").has_private()
        for data in (
            keys["ECC"].export_key(format="DER"),
            keys["ECC"].export_key(format="PEM"),
        ):
            assert ECC.import_key(data, passphrase="pw").has_private()


class TestIO:
    """Crypto.IO.PKCS8.unwrap and Crypto.IO.PEM.decode raise the same exceptions."""

    def test_pkcs8_unwrap(self, keys):
        # The private key inside the (clear) PKCS#8 encoding of the ECC key
        private_key = PKCS8.unwrap(keys["ECC"].export_key(format="DER"))[1]
        encrypted = PKCS8.wrap(
            private_key, "1.2.840.10045.2.1", passphrase="pw", protection=CBC, prot_params=FAST
        )
        with pytest.raises(PassphraseRequiredError):
            PKCS8.unwrap(encrypted)
        with pytest.raises(IncorrectPassphraseError):
            PKCS8.unwrap(encrypted, "wrong")
        assert PKCS8.unwrap(encrypted, "pw")[0] == "1.2.840.10045.2.1"

    def test_pem_decode(self):
        encrypted = PEM.encode(b"\x30\x03\x02\x01\x00", "PRIVATE KEY", passphrase=b"pw")
        with pytest.raises(PassphraseRequiredError):
            PEM.decode(encrypted)
        assert PEM.decode(encrypted, b"pw")[0] == b"\x30\x03\x02\x01\x00"

    def test_pem_decode_incorrect_passphrase(self):
        # The padding is correct by chance about once in 256 times:
        # the content must then be DER
        encrypted = PEM.encode(b"\x30\x03\x02\x01\x00", "PRIVATE KEY", passphrase=b"pw")
        for i in range(1000):
            with pytest.raises(IncorrectPassphraseError):
                PEM.decode(encrypted, b"wrong%d" % i)
