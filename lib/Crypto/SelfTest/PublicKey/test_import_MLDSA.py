# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import errno
import os

import pytest

from Crypto import IncorrectPassphraseError, PassphraseRequiredError
from Crypto.IO import PEM, PKCS8
from Crypto.PublicKey import ECC, MLDSA
from Crypto.SelfTest.loader import warn_skipped_tests
from Crypto.Util.asn1 import DerBitString, DerNull, DerObjectId, DerOctetString, DerSequence

try:
    import pycryptodome_test_vectors  # type: ignore

    test_vectors_available = True
except ImportError:
    test_vectors_available = False


PARAM_SETS = [MLDSA.ML_DSA_44, MLDSA.ML_DSA_65, MLDSA.ML_DSA_87]

# id-ml-dsa-* (RFC 9881)
OIDS = {
    MLDSA.ML_DSA_44: "2.16.840.1.101.3.4.3.17",
    MLDSA.ML_DSA_65: "2.16.840.1.101.3.4.3.18",
    MLDSA.ML_DSA_87: "2.16.840.1.101.3.4.3.19",
}


# Fast key derivation for the tests
FAST = {"iteration_count": 1000}


def load_file(file_name, mode="rb"):
    results = None

    try:
        if not test_vectors_available:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_name)

        dir_comps = ("PublicKey", "MLDSA")
        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        full_file_name = os.path.join(os.path.join(init_dir, *dir_comps), file_name)
        with open(full_file_name, mode) as file_in:
            results = file_in.read()

    except FileNotFoundError:
        warn_skipped_tests("Skipping extended tests for ML-DSA (%s)" % file_name)

    if results is None:
        pytest.skip("Missing %s" % file_name)

    return results


def load_pem(file_name):
    return PEM.decode(load_file(file_name, "r"))[0]


def rfc9881_name(param_set, kind):
    return "rfc9881_%s_%s.pem" % (param_set.value.lower().replace("-", "_"), kind)


def one_asymmetric_key(oid, private_key, version=0, params=None, extra=()):
    """A OneAsymmetricKey, built by hand"""
    algo = [DerObjectId(oid)] if params is None else [DerObjectId(oid), params]
    return DerSequence([version, DerSequence(algo), DerOctetString(private_key), *extra]).encode()


def spki(oid, pk, params=None):
    """A SubjectPublicKeyInfo, built by hand"""
    algo = [DerObjectId(oid)] if params is None else [DerObjectId(oid), params]
    return DerSequence([DerSequence(algo), DerBitString(pk)]).encode()


def seed_choice(seed):
    return DerOctetString(seed, implicit=0).encode()


def expanded_choice(sk):
    return DerOctetString(sk).encode()


def both_choice(seed, sk):
    return DerSequence([DerOctetString(seed), DerOctetString(sk)]).encode()


def public_key_field(pk):
    return DerBitString(pk, implicit=1)


class TestExport:
    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_public(self, param_set):
        key = MLDSA.generate(param_set=param_set).public_key()
        der = key.export_key()
        # No parameters in the AlgorithmIdentifier
        assert der == spki(OIDS[param_set], key.pk)

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_private(self, param_set):
        key = MLDSA.generate(param_set=param_set)
        oid = OIDS[param_set]

        # The seed, if it is known
        assert key.export_key() == one_asymmetric_key(oid, seed_choice(key.seed))
        # Seed format: 0x80 0x20 + seed (RFC 9881, Section 6)
        assert seed_choice(key.seed) == b"\x80\x20" + key.seed

        # Otherwise, the expanded key
        key_sk = MLDSA.construct(param_set=param_set, sk=key.sk)
        assert key_sk.export_key() == one_asymmetric_key(oid, expanded_choice(key.sk))

    def test_version(self):
        # OneAsymmetricKey version 1 (PrivateKeyInfo), without the public key
        der = MLDSA.generate(param_set=MLDSA.ML_DSA_44).export_key()
        assert DerSequence().decode(der)[0] == 0
        assert len(DerSequence().decode(der)) == 3
        with pytest.raises(TypeError):
            MLDSA.generate(param_set=MLDSA.ML_DSA_44).export_key(include_public_key=True)

    @pytest.mark.parametrize(
        "protection",
        [
            "PBKDF2WithHMAC-SHA256AndAES256-CBC",
            "PBKDF2WithHMAC-SHA512AndAES128-GCM",
            "scryptAndAES256-GCM",
        ],
    )
    def test_encrypted(self, protection):
        key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
        der = key.export_key(passphrase="secret", protection=protection)
        clear = PKCS8.wrap(seed_choice(key.seed), OIDS[MLDSA.ML_DSA_44], key_params=None)
        assert PKCS8.unwrap(der, "secret") == (OIDS[MLDSA.ML_DSA_44], seed_choice(key.seed), None)
        assert der != clear

        # Fresh salt and IV each time
        assert key.export_key(passphrase="secret", protection=protection) != der

    def test_encrypted_randfunc(self):
        key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
        der1 = key.export_key(passphrase=b"secret", prot_params=FAST, randfunc=lambda n: b"\x01" * n)
        der2 = key.export_key(passphrase=b"secret", prot_params=FAST, randfunc=lambda n: b"\x01" * n)
        assert der1 == der2

    def test_errors(self):
        key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
        pub_key = key.public_key()

        for kwargs in (
            {"passphrase": "secret"},
            {"protection": "scryptAndAES256-GCM"},
            {"prot_params": FAST},
            {"randfunc": lambda n: b"\x00" * n},
            {"threads": 2},
        ):
            with pytest.raises(ValueError):
                pub_key.export_key(**kwargs)

        # There is no choice of the format of the private key
        with pytest.raises(TypeError):
            key.export_key(private_format="both")
        with pytest.raises(ValueError):
            key.export_key(passphrase="")
        with pytest.raises(ValueError):
            key.export_key(protection="scryptAndAES256-GCM")
        with pytest.raises(ValueError):
            key.export_key(prot_params=FAST)
        with pytest.raises(ValueError):
            key.export_key(passphrase="secret", protection="unknown")
        with pytest.raises(ValueError):
            key.export_key(threads=-1)
        with pytest.raises(TypeError):
            key.export_key("DER")


class TestImportExport:
    @pytest.mark.parametrize("param_set", PARAM_SETS)
    @pytest.mark.parametrize("seed_known", [True, False])
    @pytest.mark.parametrize("passphrase", [None, "secret"])
    def test_roundtrip(self, param_set, seed_known, passphrase):
        key = MLDSA.generate(param_set=param_set)
        if not seed_known:
            key = MLDSA.construct(param_set=param_set, sk=key.sk)
        kwargs = {}
        if passphrase:
            kwargs = {"passphrase": passphrase, "prot_params": FAST}
        der = key.export_key(**kwargs)

        key2 = MLDSA.import_key(der, passphrase)
        assert key2 == key
        assert key2.param_set is param_set
        assert key2.sk == key.sk
        if seed_known:
            assert key2.seed == key.seed
        else:
            with pytest.raises(ValueError):
                _ = key2.seed

        # The other types of buffers
        assert MLDSA.import_key(bytearray(der), passphrase) == key
        assert MLDSA.import_key(memoryview(der), passphrase) == key

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    @pytest.mark.parametrize("passphrase", [None, "secret"])
    def test_import_both(self, param_set, passphrase):
        # We never write the form 'both', but we read it (like OpenSSL writes it)
        key = MLDSA.generate(param_set=param_set)
        both = both_choice(key.seed, key.sk)
        kwargs = {"passphrase": passphrase, "prot_params": FAST} if passphrase else {}
        for public_key in (None, key.pk):
            der = PKCS8.wrap(both, OIDS[param_set], key_params=None, public_key=public_key, **kwargs)
            key2 = MLDSA.import_key(der, passphrase)
            assert key2 == key
            assert key2.seed == key.seed
            # Exported again with the seed only
            assert key2.export_key() == key.export_key()

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_roundtrip_public(self, param_set):
        pub_key = MLDSA.generate(param_set=param_set).public_key()
        key2 = MLDSA.import_key(pub_key.export_key())
        assert key2 == pub_key
        assert not key2.has_private()

    def test_passphrase(self):
        key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
        der = key.export_key(passphrase="secret", prot_params=FAST)

        assert MLDSA.import_key(der, b"secret") == key
        with pytest.raises(PassphraseRequiredError):
            MLDSA.import_key(der)
        with pytest.raises(IncorrectPassphraseError):
            MLDSA.import_key(der, "wrong")

        # The passphrase is ignored for keys in the clear
        assert MLDSA.import_key(key.export_key(), "secret") == key
        assert MLDSA.import_key(key.public_key().export_key(), "secret") == key.public_key()

    def test_kdf_limits(self):
        key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
        der = key.export_key(passphrase="secret", prot_params={"iteration_count": 5000})
        with pytest.raises(ValueError):
            MLDSA.import_key(der, "secret", max_iteration_count=1000)
        assert MLDSA.import_key(der, "secret", max_iteration_count=5000) == key

        with pytest.raises(ValueError):
            MLDSA.import_key(key.export_key(), threads=-1)


class TestImportErrors:
    key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
    oid = OIDS[MLDSA.ML_DSA_44]

    def test_not_der(self):
        # A string must be PEM
        with pytest.raises(ValueError):
            MLDSA.import_key(self.key.export_key().hex())
        for data in (b"", b"\x30\x00", b"\x00" * 10, self.key.export_key() + b"\x00"):
            with pytest.raises(ValueError):
                MLDSA.import_key(data)

    def test_other_algorithms(self):
        ecc_key = ECC.generate(curve="P-256")
        with pytest.raises(ValueError):
            MLDSA.import_key(ecc_key.export_key(format="DER"))
        with pytest.raises(ValueError):
            MLDSA.import_key(ecc_key.public_key().export_key(format="DER"))

        # The OID of ML-KEM-768, or HashML-DSA-65 with SHA-512 (not allowed by RFC 9881)
        for oid in ("2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.3.33"):
            with pytest.raises(ValueError):
                MLDSA.import_key(one_asymmetric_key(oid, seed_choice(self.key.seed)))
            with pytest.raises(ValueError):
                MLDSA.import_key(spki(oid, self.key.pk))

        # The OID of another parameter set
        with pytest.raises(ValueError):
            MLDSA.import_key(spki(OIDS[MLDSA.ML_DSA_65], self.key.pk))
        with pytest.raises(ValueError):
            MLDSA.import_key(one_asymmetric_key(OIDS[MLDSA.ML_DSA_65], expanded_choice(self.key.sk)))

    def test_parameters(self):
        # The parameters MUST be absent (RFC 9881, Section 2)
        params = DerObjectId("1.2.3")
        with pytest.raises(ValueError):
            MLDSA.import_key(spki(self.oid, self.key.pk, params))
        with pytest.raises(ValueError):
            MLDSA.import_key(one_asymmetric_key(self.oid, seed_choice(self.key.seed), params=params))

    def test_null_parameters(self):
        # NULL parameters are tolerated (they carry no information)
        params = DerNull()
        assert MLDSA.import_key(spki(self.oid, self.key.pk, params)) == self.key.public_key()
        encoded = one_asymmetric_key(self.oid, seed_choice(self.key.seed), params=params)
        assert MLDSA.import_key(encoded) == self.key

    def test_public_key(self):
        pk = self.key.pk
        for bad_pk in (pk[:-1], pk + b"\x00", b""):
            with pytest.raises(ValueError):
                MLDSA.import_key(spki(self.oid, bad_pk))

        # BIT STRING with unused bits
        der = bytearray(spki(self.oid, pk))
        pos = der.index(b"\x03\x82\x05\x21\x00") + 4
        der[pos] = 1
        with pytest.raises(ValueError):
            MLDSA.import_key(bytes(der))

    def test_private_key_choice(self):
        seed, sk = self.key.seed, self.key.sk

        # Unknown tag
        for choice in (
            DerOctetString(seed, implicit=1).encode(),
            b"\xa0\x22" + DerOctetString(seed).encode(),
            DerBitString(seed).encode(),
        ):
            with pytest.raises(ValueError):
                MLDSA.import_key(one_asymmetric_key(self.oid, choice))

        # Wrong lengths
        for choice in (
            seed_choice(seed[:-1]),
            seed_choice(seed + b"\x00"),
            expanded_choice(sk[:-1]),
            expanded_choice(sk + b"\x00"),
            both_choice(seed[:-1], sk),
            both_choice(seed, sk[:-1]),
        ):
            with pytest.raises(ValueError):
                MLDSA.import_key(one_asymmetric_key(self.oid, choice))

        # Malformed 'both'
        for choice in (
            DerSequence([DerOctetString(seed)]).encode(),
            DerSequence([DerOctetString(seed), DerOctetString(sk), DerOctetString(seed)]).encode(),
            DerSequence([DerOctetString(sk), DerOctetString(seed)]).encode(),
            seed_choice(seed) + b"\x00",
        ):
            with pytest.raises(ValueError):
                MLDSA.import_key(one_asymmetric_key(self.oid, choice))

    def test_inconsistent(self):
        other = MLDSA.generate(param_set=MLDSA.ML_DSA_44)

        # The seed and the expanded key don't match (RFC 9881, Section 8.2)
        with pytest.raises(ValueError):
            MLDSA.import_key(one_asymmetric_key(self.oid, both_choice(self.key.seed, other.sk)))

        # The public key does not match
        for choice in (
            seed_choice(self.key.seed),
            expanded_choice(self.key.sk),
            both_choice(self.key.seed, self.key.sk),
        ):
            der = one_asymmetric_key(self.oid, choice, version=1, extra=[public_key_field(other.pk)])
            with pytest.raises(ValueError):
                MLDSA.import_key(der)
            der = one_asymmetric_key(self.oid, choice, version=1, extra=[public_key_field(self.key.pk[:-1])])
            with pytest.raises(ValueError):
                MLDSA.import_key(der)
            der = one_asymmetric_key(self.oid, choice, version=1, extra=[public_key_field(self.key.pk)])
            assert MLDSA.import_key(der) == self.key

        # Corrupted expanded key
        sk = bytearray(self.key.sk)
        sk[200] ^= 1
        with pytest.raises(ValueError):
            MLDSA.import_key(one_asymmetric_key(self.oid, expanded_choice(bytes(sk))))

    def test_attributes(self):
        # Attributes [0] are ignored
        attributes = b"\xa0\x1f" + bytes.fromhex(
            "301d060a2a864886f70d01090914310f0c0d437572646c6520436861697273"
        )
        der = one_asymmetric_key(self.oid, seed_choice(self.key.seed), extra=[RawDer(attributes)])
        assert MLDSA.import_key(der) == self.key
        der = one_asymmetric_key(
            self.oid,
            seed_choice(self.key.seed),
            version=1,
            extra=[RawDer(attributes), public_key_field(self.key.pk)],
        )
        assert MLDSA.import_key(der) == self.key


class RawDer:
    """An already encoded DER object, as an item of a DerSequence"""

    def __init__(self, encoded):
        self._encoded = encoded

    def encode(self):
        return self._encoded


class TestRFC9881:
    """The examples in Appendix C of RFC 9881"""

    seed = bytes(range(32))

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_private_keys(self, param_set):
        der_seed = load_pem(rfc9881_name(param_set, "seed"))
        der_expanded = load_pem(rfc9881_name(param_set, "expanded"))
        der_both = load_pem(rfc9881_name(param_set, "both"))

        key = MLDSA.import_key(der_seed)
        assert key.param_set is param_set
        assert key.seed == self.seed

        key_expanded = MLDSA.import_key(der_expanded)
        assert key_expanded == key
        with pytest.raises(ValueError):
            _ = key_expanded.seed

        key_both = MLDSA.import_key(der_both)
        assert key_both == key
        assert key_both.seed == self.seed

        # Our encodings are the same (the seed, if known)
        assert key.export_key() == der_seed
        assert key_both.export_key() == der_seed
        assert key_expanded.export_key() == der_expanded

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_public_key(self, param_set):
        der = load_pem(rfc9881_name(param_set, "public"))
        key = MLDSA.import_key(der)
        assert not key.has_private()
        assert key == MLDSA.construct(param_set=param_set, seed=self.seed).public_key()
        assert key.export_key() == der

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_certificate(self, param_set):
        key = MLDSA.import_key(load_pem(rfc9881_name(param_set, "cert")))
        assert not key.has_private()
        assert key == MLDSA.construct(param_set=param_set, seed=self.seed).public_key()

    @pytest.mark.parametrize("index", [1, 2, 3])
    def test_inconsistent(self, index):
        # 1: seed and expanded key don't match; 2: wrong tr; 3: wrong t0
        der = load_pem("rfc9881_ml_dsa_44_inconsistent_%d.pem" % index)
        with pytest.raises(ValueError):
            MLDSA.import_key(der)


class TestOpenSSL:
    """Keys generated by OpenSSL 4.0.3"""

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_import(self, param_set):
        base = "openssl_ml_dsa_%s_" % param_set.value[-2:]

        der_private = load_file(base + "private.der")
        key = MLDSA.import_key(der_private)
        assert key.param_set is param_set
        assert key.seed.hex() == load_file(base + "seed.hex", "r").strip()

        key_enc = MLDSA.import_key(load_file(base + "private_enc.der"), "password")
        assert key_enc == key
        with pytest.raises(IncorrectPassphraseError):
            MLDSA.import_key(load_file(base + "private_enc.der"), "wrong")

        der_public = load_file(base + "public.der")
        pub_key = MLDSA.import_key(der_public)
        assert pub_key == key.public_key()

        # Our encodings are the same
        assert key.export_key() == der_private
        assert pub_key.export_key() == der_public

        # Pure ML-DSA, empty context
        signature = bytes.fromhex(load_file(base + "sig_message.hex", "r").strip())
        assert pub_key._verify(b"message", signature, prefix=b"\x00\x00")


class TestPEM:
    key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)

    def test_export_labels(self):
        key = self.key
        cases = [
            (key.public_key().export_key(format="PEM"), "PUBLIC KEY", key.public_key().export_key()),
            (key.export_key(format="PEM"), "PRIVATE KEY", key.export_key()),
        ]
        for pem, label, der in cases:
            assert isinstance(pem, str)
            assert pem.startswith("-----BEGIN %s-----\n" % label)
            assert pem.endswith("\n-----END %s-----\n" % label)
            # Lines of 64 characters (RFC 7468, Section 2)
            body = pem.splitlines()[1:-1]
            assert all(len(line) == 64 for line in body[:-1])
            assert 0 < len(body[-1]) <= 64
            assert PEM.decode(pem) == (der, label, False)

        pem = key.export_key(format="PEM", passphrase="secret", prot_params=FAST)
        assert pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
        assert pem.endswith("\n-----END ENCRYPTED PRIVATE KEY-----\n")
        der = PEM.decode(pem)[0]
        assert MLDSA.import_key(der, "secret") == key

        # DER is the default
        assert key.export_key(format="DER") == key.export_key()

        with pytest.raises(ValueError):
            key.export_key(format="raw")
        with pytest.raises(ValueError):
            key.public_key().export_key(format="PEM", passphrase="secret")

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    @pytest.mark.parametrize("seed_known", [True, False])
    @pytest.mark.parametrize("passphrase", [None, "secret"])
    def test_roundtrip(self, param_set, seed_known, passphrase):
        key = MLDSA.generate(param_set=param_set)
        if not seed_known:
            key = MLDSA.construct(param_set=param_set, sk=key.sk)
        kwargs = {"passphrase": passphrase, "prot_params": FAST} if passphrase else {}
        pem = key.export_key(format="PEM", **kwargs)

        assert MLDSA.import_key(pem, passphrase) == key
        assert MLDSA.import_key(pem.encode("ascii"), passphrase) == key
        assert MLDSA.import_key(bytearray(pem.encode("ascii")), passphrase) == key

        pub_pem = key.public_key().export_key(format="PEM")
        assert MLDSA.import_key(pub_pem) == key.public_key()

    def test_passphrase(self):
        pem = self.key.export_key(format="PEM", passphrase="secret", prot_params=FAST)
        with pytest.raises(PassphraseRequiredError):
            MLDSA.import_key(pem)
        with pytest.raises(IncorrectPassphraseError):
            MLDSA.import_key(pem, "wrong")

    def test_whitespace(self):
        pem = self.key.export_key(format="PEM")
        assert MLDSA.import_key("\n  " + pem.replace("\n", "\r\n") + "\n\n") == self.key

    def test_label_mismatch(self):
        key = self.key
        encrypted = key.export_key(passphrase="secret", prot_params=FAST)
        for der, label in (
            (key.export_key(), "PUBLIC KEY"),
            (key.export_key(), "ENCRYPTED PRIVATE KEY"),
            (key.export_key(), "CERTIFICATE"),
            (encrypted, "PRIVATE KEY"),
            (encrypted, "PUBLIC KEY"),
            (key.public_key().export_key(), "PRIVATE KEY"),
            (key.public_key().export_key(), "CERTIFICATE"),
        ):
            with pytest.raises(ValueError):
                MLDSA.import_key(PEM.encode(der, label), "secret")

    def test_unknown_label(self):
        for label in ("RSA PRIVATE KEY", "EC PRIVATE KEY", "ML-DSA PRIVATE KEY", "PKCS7"):
            with pytest.raises(ValueError):
                MLDSA.import_key(PEM.encode(self.key.export_key(), label))

    def test_legacy_encryption(self):
        # RFC 7468 has no Proc-Type header: the key must be encrypted with PKCS#8
        pem = PEM.encode(self.key.export_key(), "PRIVATE KEY", passphrase=b"secret")
        assert "Proc-Type: 4,ENCRYPTED" in pem
        with pytest.raises(ValueError):
            MLDSA.import_key(pem, "secret")

    def test_invalid(self):
        pem = self.key.export_key(format="PEM")
        for bad in (
            pem.replace("-----END PRIVATE KEY-----", "-----END PUBLIC KEY-----"),
            pem.replace("-----END PRIVATE KEY-----\n", ""),
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
        ):
            with pytest.raises(ValueError):
                MLDSA.import_key(bad)
        with pytest.raises(ValueError):
            MLDSA.import_key(b"-----BEGIN PRIVATE KEY-----\n\xff\xff\n-----END PRIVATE KEY-----\n")

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_rfc9881(self, param_set):
        # The examples of RFC 9881 are in PEM
        pem_seed = load_file(rfc9881_name(param_set, "seed"), "r")
        key = MLDSA.import_key(pem_seed)
        assert key.export_key(format="PEM") == pem_seed
        pem_expanded = load_file(rfc9881_name(param_set, "expanded"), "r")
        key_expanded = MLDSA.import_key(pem_expanded)
        assert key_expanded == key
        assert key_expanded.export_key(format="PEM") == pem_expanded
        pem_both = load_file(rfc9881_name(param_set, "both"), "r")
        assert MLDSA.import_key(pem_both) == key
        pem = load_file(rfc9881_name(param_set, "public"), "r")
        assert MLDSA.import_key(pem) == key.public_key()
        assert key.public_key().export_key(format="PEM") == pem

        # Certificate, also with the labels that RFC 7468 (Section 5.1) tolerates
        pem = load_file(rfc9881_name(param_set, "cert"), "r")
        assert MLDSA.import_key(pem) == key.public_key()
        for label in ("X509 CERTIFICATE", "X.509 CERTIFICATE"):
            assert MLDSA.import_key(pem.replace("CERTIFICATE", label)) == key.public_key()
