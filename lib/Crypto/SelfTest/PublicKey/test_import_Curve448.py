# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

import errno
import os
import warnings
from binascii import unhexlify

import pytest

from Crypto.Hash import SHAKE128
from Crypto.PublicKey import ECC
from Crypto.Util.asn1 import DerBitString, DerSequence

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
        warnings.warn("Warning: skipping extended tests for ECC", UserWarning, stacklevel=2)

    if results is None:
        pytest.skip("Missing %s" % file_name)

    return results


def compact(lines):
    ext = b"".join(lines)
    return unhexlify(ext.decode("latin-1").replace(" ", "").replace(":", ""))


def create_ref_keys_x448():
    key_lines = load_file("ecc_x448.txt").splitlines()
    seed = compact(key_lines[6:10])
    key = ECC.construct(curve="Curve448", seed=seed)
    return (key, key.public_key())


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
        # Private key with X448 Object ID but X448 key
        mismatch_hex = (
            "302e020100300506032b656f042204207009906b64ec727d5cb5c23007bf0425b3fd79014c6cd62ca3dddfcf0f278f79"
        )
        mismatch = unhexlify(mismatch_hex)
        with pytest.raises(ValueError):
            ECC.import_key(mismatch)


class TestImport_Curve448:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_x448()

    def test_import_public_der(self):
        key_file = load_file("ecc_x448_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        assert self.ref_public == key

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_pkcs8_der(self):
        key_file = load_file("ecc_x448_private.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_private == key

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_1(self):
        key_file = load_file("ecc_x448_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_2(self):
        key_file = load_file("ecc_x448_private_p8.pem")

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_private_pkcs8_encrypted_3(self):
        key_file = load_file("ecc_x448_private_p8_2.der")

        key = ECC._import_der(key_file, "secret")
        assert self.ref_private == key

        key = ECC.import_key(key_file, "secret")
        assert self.ref_private == key

    def test_import_x509_der(self):
        key_file = load_file("ecc_x448_x509.der")

        key = ECC._import_der(key_file, None)
        assert self.ref_public == key

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_public_pem(self):
        key_file = load_file("ecc_x448_public.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key

    def test_import_private_pem(self):
        key_file = load_file("ecc_x448_private.pem")

        key = ECC.import_key(key_file)
        assert self.ref_private == key

    def test_import_private_pem_encrypted(self):
        for algo in "des3", "aes128", "aes192", "aes256":
            key_file = load_file("ecc_x448_private_enc_%s.pem" % algo)

            key = ECC.import_key(key_file, "secret")
            assert self.ref_private == key

            key = ECC.import_key(key_file.decode("latin-1"), b"secret")
            assert self.ref_private == key

    def test_import_x509_pem(self):
        key_file = load_file("ecc_x448_x509.pem")

        key = ECC.import_key(key_file)
        assert self.ref_public == key


class TestExport_Curve448:
    def setup_method(self):
        self.ref_private, self.ref_public = create_ref_keys_x448()

    def test_export_public_der(self):
        key_file = load_file("ecc_x448_public.der")

        encoded = self.ref_public._export_subjectPublicKeyInfo(True)
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER")
        assert key_file == encoded

        encoded = self.ref_public.export_key(format="DER", compress=False)
        assert key_file == encoded

    def test_export_private_pkcs8_clear(self):
        key_file = load_file("ecc_x448_private.der")

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
        key_file_ref = load_file("ecc_x448_public.pem", "rt").strip()
        key_file = self.ref_public.export_key(format="PEM").strip()
        assert key_file_ref == key_file

    def test_export_private_pem_clear(self):
        key_file = load_file("ecc_x448_private.pem", "rt").strip()
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

    def test_export_raw(self):
        encoded = self.ref_public.export_key(format="raw")
        assert len(encoded) == 56
        assert encoded == unhexlify(
            b"e2abae24ab8f65b01969e61f84fee615b525f413a90e3d727f71d0ffe60fb1d0a1a0285f2a7fd88789206e0aa4f3e9fcb9e4ba5d644e691e"
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

        # Missing 'protection' parameter when PKCS#8 is used
        with pytest.raises(ValueError):
            self.ref_private.export_key(format="PEM", passphrase="secret")

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


class TestImport_Curve448_Weak:
    def test_weak_pem(self):

        p = 2**448 - 2**224 - 1
        weak_x = (0, 1, p - 1, p, p + 1)

        for x in weak_x:
            low_order_point = ECC.EccXPoint(x, "curve448")
            weak_key = ECC.EccKey(point=low_order_point, curve="curve448")
            encoded = weak_key.export_key(format="PEM")

            with pytest.raises(ValueError):
                ECC.import_key(encoded)
