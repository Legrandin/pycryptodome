# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import copy
import errno
import json
import os
import pickle
import random
from binascii import unhexlify

import pytest

from Crypto.Hash import SHAKE128, SHAKE256
from Crypto.IO import PEM, PKCS8
from Crypto.PublicKey import MLDSA, _expand_subject_public_key_info
from Crypto.PublicKey.MLDSA import MLDSAKey, ParamSet
from Crypto.SelfTest.loader import warn_skipped_tests
from Crypto.Util.asn1 import DerBitString, DerOctetString, DerSequence

try:
    import pycryptodome_test_vectors  # type: ignore

    test_vectors_available = True
except ImportError:
    test_vectors_available = False


PARAM_SETS = list(ParamSet)

# Run every test with each C implementation available on this machine
_implementations = [pytest.param(MLDSA._raw_mldsa_portable_lib, id="portable")]
if MLDSA._raw_mldsa_avx2_bmi2_lib is not None:
    _implementations.append(pytest.param(MLDSA._raw_mldsa_avx2_bmi2_lib, id="avx2_bmi2"))


@pytest.fixture(autouse=True, params=_implementations)
def mldsa_implementation(request, monkeypatch):
    monkeypatch.setattr(MLDSA, "_raw_mldsa_lib", request.param)


# Sizes of the public key, of the expanded private key and of the signature
SIZES = {
    ParamSet.ML_DSA_44: (1312, 2560, 2420),
    ParamSet.ML_DSA_65: (1952, 4032, 3309),
    ParamSet.ML_DSA_87: (2592, 4896, 4627),
}

# id-ml-dsa-* (RFC 9881)
OIDS = {
    ParamSet.ML_DSA_44: "2.16.840.1.101.3.4.3.17",
    ParamSet.ML_DSA_65: "2.16.840.1.101.3.4.3.18",
    ParamSet.ML_DSA_87: "2.16.840.1.101.3.4.3.19",
}

ZERO_RND = b"\x00" * 32


def pure_prefix(context=b""):
    """The prefix of M' for pure ML-DSA (FIPS 204, Algorithm 2)"""
    return b"\x00" + bytes([len(context)]) + context


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


class TestMLDSAKey:
    @pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle(self, protocol):
        key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
        key_sk = MLDSA.construct(param_set=MLDSA.ML_DSA_44, sk=key.sk)

        # Private keys cannot be pickled (nor copied)
        for private_key in (key, key_sk):
            with pytest.raises(pickle.PicklingError):
                pickle.dumps(private_key, protocol)
            with pytest.raises(pickle.PicklingError):
                copy.deepcopy(private_key)

        # Public keys can
        pub_key = key.public_key()
        pub_key2 = pickle.loads(pickle.dumps(pub_key, protocol))
        assert pub_key2 == pub_key
        assert not pub_key2.has_private()
        assert pub_key2.param_set is MLDSA.ML_DSA_44
        assert pub_key2._verify(b"msg", key._sign(b"msg", bytes(32)))

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_generate(self, param_set):
        key = MLDSA.generate(param_set=param_set)
        pk_len, sk_len, _ = SIZES[param_set]

        assert isinstance(key, MLDSAKey)
        assert key.param_set == param_set
        assert key.has_private()
        assert len(key.seed) == 32
        assert len(key.sk) == sk_len
        assert len(key.pk) == pk_len

        key2 = MLDSA.generate(param_set=param_set)
        assert key2.seed != key.seed
        assert key2.pk != key.pk

    def test_generate_randfunc(self):
        seeds = []

        def randfunc(n):
            seeds.append(b"\xaa" * n)
            return seeds[-1]

        key = MLDSA.generate(param_set=ParamSet.ML_DSA_44, randfunc=randfunc)
        assert seeds == [b"\xaa" * 32]
        assert key.seed == seeds[0]
        assert key == MLDSA.construct(param_set=ParamSet.ML_DSA_44, seed=seeds[0])

    def test_param_set_enum(self):
        assert [ps.value for ps in ParamSet] == ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
        assert ParamSet("ML-DSA-65") is ParamSet.ML_DSA_65

        key = MLDSA.generate(param_set=ParamSet.ML_DSA_65)
        assert key.param_set is ParamSet.ML_DSA_65

        # The members are also at the module level
        assert MLDSA.ML_DSA_44 is ParamSet.ML_DSA_44
        assert MLDSA.ML_DSA_65 is ParamSet.ML_DSA_65
        assert MLDSA.ML_DSA_87 is ParamSet.ML_DSA_87
        key = MLDSA.generate(param_set=MLDSA.ML_DSA_87)
        assert key.param_set is ParamSet.ML_DSA_87
        assert MLDSA.construct(param_set=MLDSA.ML_DSA_87, sk=key.sk) == key
        key = MLDSA.generate(param_set=ParamSet.ML_DSA_65)

        # Only members of the enum
        for bad in ("ML-DSA-65", "mldsa65", 65, None):
            with pytest.raises(TypeError):
                MLDSA.generate(param_set=bad)
            with pytest.raises(TypeError):
                MLDSA.construct(param_set=bad, pk=key.pk)
            with pytest.raises(TypeError):
                MLDSAKey(param_set=bad, pk=key.pk)

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_construct(self, param_set):
        key = MLDSA.generate(param_set=param_set)

        key_seed = MLDSA.construct(param_set=param_set, seed=key.seed)
        assert key_seed.sk == key.sk
        assert key_seed.pk == key.pk
        assert key_seed == key

        key_sk = MLDSA.construct(param_set=param_set, sk=key.sk)
        assert key_sk.has_private()
        assert key_sk.pk == key.pk
        assert key_sk == key
        with pytest.raises(ValueError):
            _ = key_sk.seed

        key_pk = MLDSA.construct(param_set=param_set, pk=key.pk)
        assert not key_pk.has_private()
        assert key_pk.pk == key.pk
        assert key_pk == key.public_key()
        assert key_pk != key
        with pytest.raises(ValueError):
            _ = key_pk.seed
        with pytest.raises(ValueError):
            _ = key_pk.sk

        key_all = MLDSA.construct(param_set=param_set, seed=key.seed, sk=key.sk, pk=key.pk)
        assert key_all == key
        key_all = MLDSA.construct(param_set=param_set, sk=key.sk, pk=key.pk)
        assert key_all == key

        # Other types of buffers
        for conv in (bytearray, memoryview):
            assert MLDSA.construct(param_set=param_set, seed=conv(key.seed)) == key
            assert MLDSA.construct(param_set=param_set, sk=conv(key.sk)) == key
            assert MLDSA.construct(param_set=param_set, pk=conv(key.pk)) == key.public_key()

    def test_construct_errors(self):
        key = MLDSA.generate(param_set=ParamSet.ML_DSA_44)
        other = MLDSA.generate(param_set=ParamSet.ML_DSA_44)

        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44)

        # Wrong lengths
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44, seed=key.seed[:-1])
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44, seed=key.seed + b"\x00")
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44, sk=key.sk[:-1])
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44, pk=key.pk[:-1])
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_65, sk=key.sk)
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_65, pk=key.pk)

        # Mismatches
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44, seed=key.seed, sk=other.sk)
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44, seed=key.seed, pk=other.pk)
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44, sk=key.sk, pk=other.pk)

        # Corrupted expanded private key (in s1)
        sk = bytearray(key.sk)
        sk[128 + 10] ^= 0xFF
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ParamSet.ML_DSA_44, sk=sk)

    def test_eq_repr(self):
        key = MLDSA.generate(param_set=ParamSet.ML_DSA_44)
        assert key == MLDSA.construct(param_set=ParamSet.ML_DSA_44, seed=key.seed)
        assert key != MLDSA.generate(param_set=ParamSet.ML_DSA_44)
        assert key != MLDSA.construct(param_set=ParamSet.ML_DSA_65, seed=key.seed)
        assert key != key.seed
        assert key.public_key() == key.public_key()

        assert repr(key) == "MLDSAKey(param_set=ParamSet.ML_DSA_44, private=True)"
        assert repr(key.public_key()) == "MLDSAKey(param_set=ParamSet.ML_DSA_44, private=False)"
        assert key.seed.hex() not in repr(key)

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_sign_verify(self, param_set):
        key = MLDSA.generate(param_set=param_set)
        pub_key = key.public_key()
        sig_len = SIZES[param_set][2]

        msg = b"Test message"
        prefix = pure_prefix(b"context")
        sig = key._sign(msg, ZERO_RND, prefix=prefix)
        assert len(sig) == sig_len
        assert pub_key._verify(msg, sig, prefix=prefix)
        assert key._verify(msg, sig, prefix=prefix)

        # Deterministic
        assert key._sign(msg, ZERO_RND, prefix=prefix) == sig

        # M' is the concatenation of prefix and message
        assert key._sign(prefix + msg, ZERO_RND) == sig
        assert key._sign(msg[3:], ZERO_RND, prefix=prefix + msg[:3]) == sig
        assert pub_key._verify(prefix + msg, sig)

        # Randomized
        sig2 = key._sign(msg, b"\x01" * 32, prefix=prefix)
        assert sig2 != sig
        assert pub_key._verify(msg, sig2, prefix=prefix)

        # Wrong message, prefix or signature
        assert not pub_key._verify(msg + b"\x00", sig, prefix=prefix)
        assert not pub_key._verify(msg, sig, prefix=pure_prefix(b"contexT"))
        assert not pub_key._verify(msg, sig)
        for pos in (0, sig_len // 2, sig_len - 1):
            sig_bad = bytearray(sig)
            sig_bad[pos] ^= 0x01
            assert not pub_key._verify(msg, sig_bad, prefix=prefix)
        assert not pub_key._verify(msg, sig[:-1], prefix=prefix)
        assert not pub_key._verify(msg, sig + b"\x00", prefix=prefix)
        assert not pub_key._verify(msg, b"", prefix=prefix)

        # Wrong key
        other = MLDSA.generate(param_set=param_set)
        assert not other._verify(msg, sig, prefix=prefix)

        # Empty message, other types of buffers
        sig = key._sign(b"", ZERO_RND)
        assert pub_key._verify(b"", sig)
        assert pub_key._verify(bytearray(), bytearray(sig))
        assert key._sign(memoryview(b""), bytearray(ZERO_RND), prefix=memoryview(b"")) == sig

    def test_sign_errors(self):
        key = MLDSA.generate(param_set=ParamSet.ML_DSA_44)

        with pytest.raises(TypeError):
            key.public_key()._sign(b"msg", ZERO_RND)

        with pytest.raises(ValueError):
            key._sign(b"msg", ZERO_RND[:-1])
        with pytest.raises(ValueError):
            key._sign(b"msg", ZERO_RND + b"\x00")

        with pytest.raises(TypeError):
            key._sign("msg", ZERO_RND)

    def test_external_mu(self):
        key = MLDSA.generate(param_set=ParamSet.ML_DSA_65)

        # mu = SHAKE256(tr || M', 64), with tr = SHAKE256(pk, 64)
        tr = SHAKE256.new(key.pk).read(64)
        msg = b"Test message"
        prefix = pure_prefix()
        mu = SHAKE256.new(tr + prefix + msg).read(64)

        sig = key._sign(mu, ZERO_RND, external_mu=True)
        assert sig == key._sign(msg, ZERO_RND, prefix=prefix)
        assert key._verify(mu, sig, external_mu=True)
        assert key._verify(msg, sig, prefix=prefix)

        # The prefix is ignored
        assert key._sign(mu, ZERO_RND, prefix=b"xyz", external_mu=True) == sig
        assert key._verify(mu, sig, prefix=b"xyz", external_mu=True)

        for bad_mu in (mu[:-1], mu + b"\x00", b""):
            with pytest.raises(ValueError):
                key._sign(bad_mu, ZERO_RND, external_mu=True)
            with pytest.raises(ValueError):
                key._verify(bad_mu, sig, external_mu=True)


class TestCCTVAccumulated:
    """Accumulated tests of C2SP/CCTV:

    https://github.com/C2SP/CCTV/tree/main/ML-DSA/accumulated

    The seeds come from a SHAKE128 stream; the public keys and the deterministic
    signatures of the empty message (with empty context) go into another SHAKE128.
    """

    results = {
        (ParamSet.ML_DSA_44, 100): "d51148e1f9f4fa1a723a6cf42e25f2a99eb5c1b378b3d2dbbd561b1203beeae4",
        (ParamSet.ML_DSA_65, 100): "8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199",
        (ParamSet.ML_DSA_87, 100): "8c3ad714777622b8f21ce31bb35f71394f23bc0fcf3c78ace5d608990f3b061b",
        (ParamSet.ML_DSA_44, 10000): "e7fd21f6a59bcba60d65adc44404bb29a7c00e5d8d3ec06a732c00a306a7d143",
        (ParamSet.ML_DSA_65, 10000): "5ff5e196f0b830c3b10a9eb5358e7c98a3a20136cb677f3ae3b90175c3ace329",
        (ParamSet.ML_DSA_87, 10000): "80a8cf39317f7d0be0e24972c51ac152bd2a3e09bc0c32ce29dd82c4e7385e60",
    }

    def accumulate(self, param_set, iterations):
        source = SHAKE128.new()
        acc = SHAKE128.new()
        prefix = pure_prefix()
        for _ in range(iterations):
            key = MLDSA.construct(param_set=param_set, seed=source.read(32))
            acc.update(key.pk)
            sig = key._sign(b"", ZERO_RND, prefix=prefix)
            acc.update(sig)
            assert key._verify(b"", sig, prefix=prefix)
        return acc.read(32).hex()

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_100(self, param_set):
        assert self.accumulate(param_set, 100) == self.results[(param_set, 100)]

    @pytest.mark.slow
    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_10000(self, param_set):
        assert self.accumulate(param_set, 10000) == self.results[(param_set, 10000)]


def _rfc9881_private_key(file_name):
    """Parse a OneAsymmetricKey from RFC 9881, Appendix C.

    Return the parameter set, the seed (or None) and the expanded key (or None)."""

    der, marker, _ = PEM.decode(load_file(file_name, "r"))
    assert marker == "PRIVATE KEY"
    oid, private_key, _ = PKCS8.unwrap(der)
    param_set = {v: k for k, v in OIDS.items()}[oid]

    # ML-DSA-PrivateKey ::= CHOICE {
    #   seed [0] OCTET STRING (SIZE (32)),
    #   expandedKey OCTET STRING,
    #   both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }
    if private_key[0] == 0x80:
        assert private_key[1] == 32
        return param_set, private_key[2:], None
    if private_key[0] == 0x04:
        return param_set, None, DerOctetString().decode(private_key).payload
    both = DerSequence().decode(private_key, nr_elements=2)
    seed = DerOctetString().decode(both[0]).payload
    expanded_key = DerOctetString().decode(both[1]).payload
    return param_set, seed, expanded_key


class TestRFC9881:
    """The examples in Appendix C of RFC 9881"""

    seed = bytes(range(32))

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_private_keys(self, param_set):
        base = "rfc9881_" + param_set.value.lower().replace("-", "_")

        ps, seed, expanded_key = _rfc9881_private_key(base + "_seed.pem")
        assert ps == param_set
        assert seed == self.seed
        assert expanded_key is None
        key = MLDSA.construct(param_set=param_set, seed=seed)

        ps, seed, expanded_key = _rfc9881_private_key(base + "_expanded.pem")
        assert ps == param_set
        assert seed is None
        assert key.sk == expanded_key
        assert MLDSA.construct(param_set=param_set, sk=expanded_key) == key

        ps, seed, expanded_key = _rfc9881_private_key(base + "_both.pem")
        assert ps == param_set
        assert seed == self.seed
        assert key.sk == expanded_key
        assert MLDSA.construct(param_set=param_set, seed=seed, sk=expanded_key) == key

        der, marker, _ = PEM.decode(load_file(base + "_public.pem", "r"))
        assert marker == "PUBLIC KEY"
        oid, pk, params = _expand_subject_public_key_info(der)
        assert oid == OIDS[param_set]
        assert params is None
        assert key.pk == pk

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_certificate(self, param_set):
        base = "rfc9881_" + param_set.value.lower().replace("-", "_")

        der, marker, _ = PEM.decode(load_file(base + "_cert.pem", "r"))
        assert marker == "CERTIFICATE"

        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        cert = DerSequence().decode(der, nr_elements=3)
        tbs_certificate = cert[0]
        signature = DerBitString().decode(cert[2]).value

        # The subjectPublicKeyInfo is the 7th item of the TBSCertificate (with version)
        tbs = DerSequence().decode(tbs_certificate)
        oid, pk, _ = _expand_subject_public_key_info(tbs[6])
        assert oid == OIDS[param_set]

        key = MLDSA.construct(param_set=param_set, seed=self.seed)
        assert key.pk == pk

        # Pure ML-DSA, empty context
        prefix = pure_prefix()
        assert key._verify(tbs_certificate, signature, prefix=prefix)
        assert not key._verify(tbs_certificate + b"\x00", signature, prefix=prefix)

    def test_inconsistent_1(self):
        # The seed and the expanded key don't match
        ps, seed, expanded_key = _rfc9881_private_key("rfc9881_ml_dsa_44_inconsistent_1.pem")
        assert ps == ParamSet.ML_DSA_44
        assert seed is not None and expanded_key is not None
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ps, seed=seed, sk=expanded_key)
        MLDSA.construct(param_set=ps, seed=seed)

    @pytest.mark.parametrize("index", [2, 3])
    def test_inconsistent_2_3(self, index):
        # Wrong tr (2) or wrong t0 (3)
        ps, seed, expanded_key = _rfc9881_private_key("rfc9881_ml_dsa_44_inconsistent_%d.pem" % index)
        assert ps == ParamSet.ML_DSA_44
        assert seed is None
        with pytest.raises(ValueError):
            MLDSA.construct(param_set=ps, sk=expanded_key)


def _load_acvp(name):
    """Load the test vectors of the given ACVP file, as a list of pytest parameters"""

    # The test vectors are loaded when pytest collects the tests:
    # a missing file is only reported when the test runs
    try:
        if not test_vectors_available:
            raise FileNotFoundError
        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        with open(os.path.join(init_dir, "PublicKey", "MLDSA", name)) as file_in:
            tv_tree = json.load(file_in)
    except FileNotFoundError:
        return [pytest.param(None, None, id="missing", marks=pytest.mark.skip(reason="Missing " + name))]

    result = []
    for group in tv_tree["testGroups"]:
        for test in group["tests"]:
            result.append(pytest.param(group, test, id="tcId%d" % test["tcId"]))
    return result


def _acvp_message(group, test):
    """The message and the prefix for _sign() and _verify(), and whether the message is mu"""

    if group.get("externalMu"):
        return unhexlify(test["mu"]), b"", True
    msg = unhexlify(test["message"])
    if group["signatureInterface"] == "internal":
        return msg, b"", False
    assert group["preHash"] == "pure"
    return msg, pure_prefix(unhexlify(test["context"])), False


class TestACVP:
    """A subset of the NIST ACVP test vectors (internal projection)"""

    @pytest.mark.parametrize("group,test", _load_acvp("ML-DSA-keyGen-FIPS204.json"))
    def test_keygen(self, group, test):
        key = MLDSA.construct(param_set=ParamSet(group["parameterSet"]), seed=unhexlify(test["seed"]))
        assert key.pk == unhexlify(test["pk"])
        assert key.sk == unhexlify(test["sk"])

    @pytest.mark.parametrize("group,test", _load_acvp("ML-DSA-sigGen-FIPS204.json"))
    def test_siggen(self, group, test):
        key = MLDSA.construct(param_set=ParamSet(group["parameterSet"]), sk=unhexlify(test["sk"]))
        assert key.pk == unhexlify(test["pk"])

        msg, prefix, external_mu = _acvp_message(group, test)
        rnd = ZERO_RND if group["deterministic"] else unhexlify(test["rnd"])
        sig = key._sign(msg, rnd, prefix=prefix, external_mu=external_mu)
        assert sig == unhexlify(test["signature"])

    @pytest.mark.parametrize("group,test", _load_acvp("ML-DSA-sigVer-FIPS204.json"))
    def test_sigver(self, group, test):
        key = MLDSA.construct(param_set=ParamSet(group["parameterSet"]), pk=unhexlify(test["pk"]))

        msg, prefix, external_mu = _acvp_message(group, test)
        signature = unhexlify(test["signature"])
        result = key._verify(msg, signature, prefix=prefix, external_mu=external_mu)
        assert result == test["testPassed"], test["reason"]


@pytest.mark.skipif(MLDSA._raw_mldsa_avx2_bmi2_lib is None, reason="AVX2 and BMI2 not available")
class TestImplementations:
    """The test vectors exercise the implementations one at a time.
    Check that both (portable C, and AVX2/BMI2) return the same output on random inputs."""

    def _run(self, param_set, seed):
        rng = random.Random(seed)

        def rand(n):
            return bytes(rng.getrandbits(8) for _ in range(n))

        out = []
        for i in range(10):
            key = MLDSA.construct(param_set=param_set, seed=rand(32))
            out += [key.pk, key.sk, MLDSA.construct(param_set=param_set, sk=key.sk).pk]
            msg = rand(rng.choice([0, 1, 135, 136, 137, 1000]))
            prefix = pure_prefix(rand(rng.randint(0, 255)))
            rnd = rand(32) if i % 2 else ZERO_RND
            sig = key._sign(msg, rnd, prefix=prefix)
            out.append(sig)
            out.append(key._verify(msg, sig, prefix=prefix))
            bad = bytearray(sig)
            bad[rng.randrange(len(bad))] ^= 1
            out.append(key._verify(msg, bad, prefix=prefix))
            mu = rand(64)
            out.append(key._sign(mu, rnd, external_mu=True))
        return out

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_same_output(self, param_set, monkeypatch):
        results = []
        for lib in (MLDSA._raw_mldsa_portable_lib, MLDSA._raw_mldsa_avx2_bmi2_lib):
            monkeypatch.setattr(MLDSA, "_raw_mldsa_lib", lib)
            results.append(self._run(param_set, param_set.value))
        assert results[0] == results[1]
