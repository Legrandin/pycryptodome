# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import errno
import os

import pytest

from Crypto import IncorrectPassphraseError, PassphraseRequiredError
from Crypto.IO import PEM, PKCS8
from Crypto.PublicKey import ECC, MLDSA, SLHDSA
from Crypto.PublicKey.SLHDSA import ParamSet
from Crypto.SelfTest.loader import warn_skipped_tests
from Crypto.Util.asn1 import DerBitString, DerNull, DerObjectId, DerOctetString, DerSequence

try:
    import pycryptodome_test_vectors  # type: ignore

    test_vectors_available = True
except ImportError:
    test_vectors_available = False


# id-slh-dsa-* (RFC 9909, Section 3)
OIDS = {
    ParamSet.SLH_DSA_SHA2_128s: "2.16.840.1.101.3.4.3.20",
    ParamSet.SLH_DSA_SHA2_128f: "2.16.840.1.101.3.4.3.21",
    ParamSet.SLH_DSA_SHA2_192s: "2.16.840.1.101.3.4.3.22",
    ParamSet.SLH_DSA_SHA2_192f: "2.16.840.1.101.3.4.3.23",
    ParamSet.SLH_DSA_SHA2_256s: "2.16.840.1.101.3.4.3.24",
    ParamSet.SLH_DSA_SHA2_256f: "2.16.840.1.101.3.4.3.25",
    ParamSet.SLH_DSA_SHAKE_128s: "2.16.840.1.101.3.4.3.26",
    ParamSet.SLH_DSA_SHAKE_128f: "2.16.840.1.101.3.4.3.27",
    ParamSet.SLH_DSA_SHAKE_192s: "2.16.840.1.101.3.4.3.28",
    ParamSet.SLH_DSA_SHAKE_192f: "2.16.840.1.101.3.4.3.29",
    ParamSet.SLH_DSA_SHAKE_256s: "2.16.840.1.101.3.4.3.30",
    ParamSet.SLH_DSA_SHAKE_256f: "2.16.840.1.101.3.4.3.31",
}

# All the parameter sets with an OID, and the "f" ones (quick key generation)
PARAM_SETS = list(OIDS)
FAST_PARAM_SETS = [ps for ps in PARAM_SETS if ps.value.endswith("f")]

# The parameter sets of SP 800-230: no OID yet
SP800230_PARAM_SETS = [ps for ps in ParamSet if ps.value.endswith("-24")]

# Fast key derivation for the tests
FAST = {"iteration_count": 1000}


def load_file(file_name, mode="rb"):
    results = None

    try:
        if not test_vectors_available:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_name)

        dir_comps = ("PublicKey", "SLHDSA")
        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        full_file_name = os.path.join(os.path.join(init_dir, *dir_comps), file_name)
        with open(full_file_name, mode) as file_in:
            results = file_in.read()

    except FileNotFoundError:
        warn_skipped_tests("Skipping extended tests for SLH-DSA (%s)" % file_name)

    if results is None:
        pytest.skip("Missing %s" % file_name)

    return results


def load_pem(file_name):
    return PEM.decode(load_file(file_name, "r"))[0]


def one_asymmetric_key(oid, private_key, version=0, params=None, extra=()):
    """A OneAsymmetricKey, built by hand"""
    algo = [DerObjectId(oid)] if params is None else [DerObjectId(oid), params]
    return DerSequence([version, DerSequence(algo), DerOctetString(private_key), *extra]).encode()


def spki(oid, pk, params=None):
    """A SubjectPublicKeyInfo, built by hand"""
    algo = [DerObjectId(oid)] if params is None else [DerObjectId(oid), params]
    return DerSequence([DerSequence(algo), DerBitString(pk)]).encode()


def public_key_field(pk):
    return DerBitString(pk, implicit=1)


class RawDer:
    """An already encoded DER object, as an item of a DerSequence"""

    def __init__(self, encoded):
        self._encoded = encoded

    def encode(self):
        return self._encoded


# One key per parameter set, generated once (the "s" sets take a moment)
_keys: dict[ParamSet, SLHDSA.SLHDSAKey] = {}


def get_key(param_set):
    if param_set not in _keys:
        _keys[param_set] = SLHDSA.generate(param_set=param_set)
    return _keys[param_set]


class TestExport:
    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_public(self, param_set):
        key = get_key(param_set).public_key()
        # No parameters in the AlgorithmIdentifier, and PK.seed || PK.root in the BIT STRING
        assert key.export_key() == spki(OIDS[param_set], key.pk)

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_private(self, param_set):
        key = get_key(param_set)
        # SK.seed || SK.prf || PK.seed || PK.root, directly in the OCTET STRING
        assert key.export_key() == one_asymmetric_key(OIDS[param_set], key.sk)

    def test_version(self):
        # OneAsymmetricKey version 1 (PrivateKeyInfo), without the public key
        der = get_key(ParamSet.SLH_DSA_SHA2_128f).export_key()
        assert DerSequence().decode(der)[0] == 0
        assert len(DerSequence().decode(der)) == 3

    @pytest.mark.parametrize(
        "protection",
        [
            "PBKDF2WithHMAC-SHA256AndAES256-CBC",
            "PBKDF2WithHMAC-SHA512AndAES128-GCM",
            "scryptAndAES256-GCM",
        ],
    )
    def test_encrypted(self, protection):
        ps = ParamSet.SLH_DSA_SHAKE_128f
        key = get_key(ps)
        der = key.export_key(passphrase="secret", protection=protection)
        assert PKCS8.unwrap(der, "secret") == (OIDS[ps], key.sk, None)
        assert der != key.export_key()

        # Fresh salt and IV each time
        assert key.export_key(passphrase="secret", protection=protection) != der

    def test_encrypted_randfunc(self):
        key = get_key(ParamSet.SLH_DSA_SHA2_128f)
        der1 = key.export_key(passphrase=b"secret", prot_params=FAST, randfunc=lambda n: b"\x01" * n)
        der2 = key.export_key(passphrase=b"secret", prot_params=FAST, randfunc=lambda n: b"\x01" * n)
        assert der1 == der2

    def test_errors(self):
        key = get_key(ParamSet.SLH_DSA_SHA2_128f)
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

    @pytest.mark.parametrize("param_set", SP800230_PARAM_SETS)
    def test_sp800230(self, param_set):
        # No OID: the keys cannot be exported (building a private key takes minutes,
        # but a public key is enough to check)
        n = SLHDSA._params[param_set].n
        pub_key = SLHDSA.construct(param_set=param_set, pk=b"\x01" * (2 * n))
        for fmt in ("DER", "PEM"):
            with pytest.raises(ValueError, match="no OID"):
                pub_key.export_key(format=fmt)


class TestImportExport:
    @pytest.mark.parametrize("param_set", PARAM_SETS)
    @pytest.mark.parametrize("passphrase", [None, "secret"])
    def test_roundtrip(self, param_set, passphrase):
        key = get_key(param_set)
        kwargs = {"passphrase": passphrase, "prot_params": FAST} if passphrase else {}
        der = key.export_key(**kwargs)

        key2 = SLHDSA.import_key(der, passphrase)
        assert key2 == key
        assert key2.param_set is param_set
        assert key2.sk == key.sk

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_roundtrip_public(self, param_set):
        pub_key = get_key(param_set).public_key()
        key2 = SLHDSA.import_key(pub_key.export_key())
        assert key2 == pub_key
        assert not key2.has_private()

    def test_buffers(self):
        key = get_key(ParamSet.SLH_DSA_SHA2_128f)
        der = key.export_key()
        assert SLHDSA.import_key(bytearray(der)) == key
        assert SLHDSA.import_key(memoryview(der)) == key

    @pytest.mark.parametrize("passphrase", [None, "secret"])
    def test_public_key_field(self, passphrase):
        # OneAsymmetricKey version 2, with the public key
        ps = ParamSet.SLH_DSA_SHAKE_128f
        key = get_key(ps)
        kwargs = {"passphrase": passphrase, "prot_params": FAST} if passphrase else {}
        der = PKCS8.wrap(key.sk, OIDS[ps], key_params=None, public_key=key.pk, **kwargs)
        key2 = SLHDSA.import_key(der, passphrase)
        assert key2 == key
        # Exported again without the public key
        assert key2.export_key() == key.export_key()

    def test_passphrase(self):
        key = get_key(ParamSet.SLH_DSA_SHA2_128f)
        der = key.export_key(passphrase="secret", prot_params=FAST)

        assert SLHDSA.import_key(der, b"secret") == key
        with pytest.raises(PassphraseRequiredError):
            SLHDSA.import_key(der)
        with pytest.raises(IncorrectPassphraseError):
            SLHDSA.import_key(der, "wrong")

        # The passphrase is ignored for keys in the clear
        assert SLHDSA.import_key(key.export_key(), "secret") == key
        assert SLHDSA.import_key(key.public_key().export_key(), "secret") == key.public_key()

    def test_kdf_limits(self):
        key = get_key(ParamSet.SLH_DSA_SHA2_128f)
        der = key.export_key(passphrase="secret", prot_params={"iteration_count": 5000})
        with pytest.raises(ValueError):
            SLHDSA.import_key(der, "secret", max_iteration_count=1000)
        assert SLHDSA.import_key(der, "secret", max_iteration_count=5000) == key

        with pytest.raises(ValueError):
            SLHDSA.import_key(key.export_key(), threads=-1)

    def test_threads(self):
        # The threads also check the private key
        key = get_key(ParamSet.SLH_DSA_SHA2_128s)
        assert SLHDSA.import_key(key.export_key(), threads=4) == key
        assert SLHDSA.import_key(key.export_key(), threads=0) == key


class TestImportErrors:
    ps = ParamSet.SLH_DSA_SHA2_128f
    oid = OIDS[ps]

    @property
    def key(self):
        return get_key(self.ps)

    def test_not_der(self):
        # A string must be PEM
        with pytest.raises(ValueError):
            SLHDSA.import_key(self.key.export_key().hex())
        for data in (b"", b"\x30\x00", b"\x00" * 10, self.key.export_key() + b"\x00"):
            with pytest.raises(ValueError):
                SLHDSA.import_key(data)

    def test_other_algorithms(self):
        ecc_key = ECC.generate(curve="P-256")
        with pytest.raises(ValueError):
            SLHDSA.import_key(ecc_key.export_key(format="DER"))
        with pytest.raises(ValueError):
            SLHDSA.import_key(ecc_key.public_key().export_key(format="DER"))

        # An ML-DSA key
        mldsa_key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
        for der in (mldsa_key.export_key(), mldsa_key.public_key().export_key()):
            with pytest.raises(ValueError, match="Not an SLH-DSA key"):
                SLHDSA.import_key(der)

        # The OID of another parameter set (with the same n, or not)
        for ps in (ParamSet.SLH_DSA_SHAKE_128f, ParamSet.SLH_DSA_SHA2_128s, ParamSet.SLH_DSA_SHA2_192f):
            with pytest.raises(ValueError):
                SLHDSA.import_key(one_asymmetric_key(OIDS[ps], self.key.sk))
        with pytest.raises(ValueError):
            SLHDSA.import_key(spki(OIDS[ParamSet.SLH_DSA_SHA2_192f], self.key.pk))

    def test_hash_slh_dsa(self):
        # id-hash-slh-dsa-sha2-128f-with-sha256 (RFC 9909): not supported
        oid = "2.16.840.1.101.3.4.3.36"
        with pytest.raises(ValueError, match="HashSLH-DSA"):
            SLHDSA.import_key(spki(oid, self.key.pk))
        with pytest.raises(ValueError, match="HashSLH-DSA"):
            SLHDSA.import_key(one_asymmetric_key(oid, self.key.sk))

    def test_parameters(self):
        # The parameters MUST be absent (RFC 9909, Section 3)
        params = DerObjectId("1.2.3")
        with pytest.raises(ValueError):
            SLHDSA.import_key(spki(self.oid, self.key.pk, params))
        with pytest.raises(ValueError):
            SLHDSA.import_key(one_asymmetric_key(self.oid, self.key.sk, params=params))

    def test_null_parameters(self):
        # NULL parameters are tolerated (they carry no information)
        params = DerNull()
        assert SLHDSA.import_key(spki(self.oid, self.key.pk, params)) == self.key.public_key()
        assert SLHDSA.import_key(one_asymmetric_key(self.oid, self.key.sk, params=params)) == self.key

    def test_public_key(self):
        pk = self.key.pk
        for bad_pk in (pk[:-1], pk + b"\x00", b""):
            with pytest.raises(ValueError):
                SLHDSA.import_key(spki(self.oid, bad_pk))

        # BIT STRING with unused bits
        der = bytearray(spki(self.oid, pk))
        pos = der.index(b"\x03\x21\x00") + 2
        der[pos] = 1
        with pytest.raises(ValueError):
            SLHDSA.import_key(bytes(der))

    def test_private_key(self):
        sk = self.key.sk

        # Wrong lengths, or an extra ASN.1 wrapping (as in RFC 9814)
        for bad_sk in (sk[:-1], sk + b"\x00", b"", DerOctetString(sk).encode()):
            with pytest.raises(ValueError):
                SLHDSA.import_key(one_asymmetric_key(self.oid, bad_sk))

        # PK.root does not match SK.seed and PK.seed
        for pos in (0, 32, 48, 63):
            bad_sk = bytearray(sk)
            bad_sk[pos] ^= 1
            with pytest.raises(ValueError, match="PK\\.root"):
                SLHDSA.import_key(one_asymmetric_key(self.oid, bytes(bad_sk)))

    def test_inconsistent(self):
        other = SLHDSA.generate(param_set=self.ps)

        # The public key field does not match
        for bad_pk in (other.pk, self.key.pk[:-1]):
            der = one_asymmetric_key(self.oid, self.key.sk, version=1, extra=[public_key_field(bad_pk)])
            with pytest.raises(ValueError):
                SLHDSA.import_key(der)
        der = one_asymmetric_key(self.oid, self.key.sk, version=1, extra=[public_key_field(self.key.pk)])
        assert SLHDSA.import_key(der) == self.key

    def test_attributes(self):
        # Attributes [0] are ignored
        attributes = b"\xa0\x1f" + bytes.fromhex(
            "301d060a2a864886f70d01090914310f0c0d437572646c6520436861697273"
        )
        der = one_asymmetric_key(self.oid, self.key.sk, extra=[RawDer(attributes)])
        assert SLHDSA.import_key(der) == self.key
        der = one_asymmetric_key(
            self.oid,
            self.key.sk,
            version=1,
            extra=[RawDer(attributes), public_key_field(self.key.pk)],
        )
        assert SLHDSA.import_key(der) == self.key


class TestRFC9909:
    """The examples in Appendix C of RFC 9909 (SLH-DSA-SHA2-128s)"""

    ps = ParamSet.SLH_DSA_SHA2_128s

    def test_public_key(self):
        der = load_pem("rfc9909_slh_dsa_sha2_128s_public.pem")
        key = SLHDSA.import_key(der)
        assert not key.has_private()
        assert key.param_set is self.ps
        assert key.pk.hex().upper() == ("2B8109EC777CAA4E1F024CCFCF9497D99180509280F4256AF2B07AF80289B494")
        assert key.export_key() == der

    def test_private_key(self):
        der = load_pem("rfc9909_slh_dsa_sha2_128s_private.pem")
        key = SLHDSA.import_key(der)
        assert key.has_private()
        assert key.param_set is self.ps
        assert key.public_key() == SLHDSA.import_key(load_pem("rfc9909_slh_dsa_sha2_128s_public.pem"))
        assert key.export_key() == der

    def test_certificate(self):
        der = load_pem("rfc9909_slh_dsa_sha2_128s_cert.pem")
        key = SLHDSA.import_key(der)
        assert not key.has_private()
        assert key == SLHDSA.import_key(load_pem("rfc9909_slh_dsa_sha2_128s_public.pem"))

        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        cert = DerSequence().decode(der, nr_elements=3)
        tbs_certificate = cert[0]
        signature = DerBitString().decode(cert[2]).value

        # Pure SLH-DSA, empty context (FIPS 205, Algorithm 22)
        prefix = b"\x00\x00"
        assert key._verify((prefix, tbs_certificate), signature)
        assert not key._verify((prefix, tbs_certificate + b"\x00"), signature)

    def test_pem(self):
        for name in ("public", "private", "cert"):
            pem = load_file("rfc9909_slh_dsa_sha2_128s_%s.pem" % name, "r")
            key = SLHDSA.import_key(pem)
            if name != "cert":
                assert key.export_key(format="PEM") == pem

        # Certificate, also with the labels that RFC 7468 (Section 5.1) tolerates
        pem = load_file("rfc9909_slh_dsa_sha2_128s_cert.pem", "r")
        for label in ("X509 CERTIFICATE", "X.509 CERTIFICATE"):
            assert SLHDSA.import_key(pem.replace("CERTIFICATE", label)) == key.public_key()


class TestOpenSSL:
    """Keys and certificates made by OpenSSL (its S/MIME test files): a PKCS#8
    private key, and a certificate for the same key (issued by another key)"""

    @pytest.mark.parametrize(
        "name, ps",
        [
            ("sha2_128s", ParamSet.SLH_DSA_SHA2_128s),
            ("shake_128s", ParamSet.SLH_DSA_SHAKE_128s),
            ("shake_256s", ParamSet.SLH_DSA_SHAKE_256s),
        ],
    )
    def test_key_and_certificate(self, name, ps):
        pem = load_file("openssl_slh_dsa_%s_key_cert.pem" % name, "r")
        end = "-----END PRIVATE KEY-----\n"
        private_pem = pem[: pem.index(end) + len(end)]
        cert_pem = pem[pem.index("-----BEGIN CERTIFICATE-----") :]

        key = SLHDSA.import_key(private_pem)
        assert key.has_private()
        assert key.param_set is ps
        assert key.export_key(format="PEM").strip() == private_pem.strip()

        cert_key = SLHDSA.import_key(cert_pem)
        assert not cert_key.has_private()
        assert cert_key == key.public_key()


class TestPEM:
    ps = ParamSet.SLH_DSA_SHA2_128f

    @property
    def key(self):
        return get_key(self.ps)

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
        assert SLHDSA.import_key(PEM.decode(pem)[0], "secret") == key

        # DER is the default
        assert key.export_key(format="DER") == key.export_key()

        with pytest.raises(ValueError):
            key.export_key(format="raw")
        with pytest.raises(ValueError):
            key.public_key().export_key(format="PEM", passphrase="secret")

    @pytest.mark.parametrize("param_set", FAST_PARAM_SETS)
    @pytest.mark.parametrize("passphrase", [None, "secret"])
    def test_roundtrip(self, param_set, passphrase):
        key = get_key(param_set)
        kwargs = {"passphrase": passphrase, "prot_params": FAST} if passphrase else {}
        pem = key.export_key(format="PEM", **kwargs)

        assert SLHDSA.import_key(pem, passphrase) == key
        assert SLHDSA.import_key(pem.encode("ascii"), passphrase) == key
        assert SLHDSA.import_key(bytearray(pem.encode("ascii")), passphrase) == key

        pub_pem = key.public_key().export_key(format="PEM")
        assert SLHDSA.import_key(pub_pem) == key.public_key()

    def test_passphrase(self):
        pem = self.key.export_key(format="PEM", passphrase="secret", prot_params=FAST)
        with pytest.raises(PassphraseRequiredError):
            SLHDSA.import_key(pem)
        with pytest.raises(IncorrectPassphraseError):
            SLHDSA.import_key(pem, "wrong")

    def test_whitespace(self):
        pem = self.key.export_key(format="PEM")
        assert SLHDSA.import_key("\n  " + pem.replace("\n", "\r\n") + "\n\n") == self.key

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
                SLHDSA.import_key(PEM.encode(der, label), "secret")

    def test_unknown_label(self):
        for label in ("RSA PRIVATE KEY", "EC PRIVATE KEY", "SLH-DSA PRIVATE KEY", "PKCS7"):
            with pytest.raises(ValueError):
                SLHDSA.import_key(PEM.encode(self.key.export_key(), label))

    def test_legacy_encryption(self):
        # RFC 7468 has no Proc-Type header: the key must be encrypted with PKCS#8
        pem = PEM.encode(self.key.export_key(), "PRIVATE KEY", passphrase=b"secret")
        assert "Proc-Type: 4,ENCRYPTED" in pem
        with pytest.raises(ValueError):
            SLHDSA.import_key(pem, "secret")

    def test_invalid(self):
        pem = self.key.export_key(format="PEM")
        for bad in (
            pem.replace("-----END PRIVATE KEY-----", "-----END PUBLIC KEY-----"),
            pem.replace("-----END PRIVATE KEY-----\n", ""),
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
        ):
            with pytest.raises(ValueError):
                SLHDSA.import_key(bad)
        with pytest.raises(ValueError):
            SLHDSA.import_key(b"-----BEGIN PRIVATE KEY-----\n\xff\xff\n-----END PRIVATE KEY-----\n")
