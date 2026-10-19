# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Self-tests for Crypto.Signature.mldsa"""

from binascii import unhexlify

import pytest

from Crypto.Hash import (
    MD5,
    SHA1,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHAKE128,
    SHAKE256,
    BLAKE2b,
)
from Crypto.PublicKey import ECC, MLDSA
from Crypto.PublicKey.MLDSA import ParamSet
from Crypto.SelfTest.loader import load_test_vectors_wycheproof, wycheproof_id
from Crypto.SelfTest.PublicKey.test_MLDSA import ZERO_RND, _load_acvp, load_file, pure_prefix
from Crypto.Signature import mldsa
from Crypto.Util.asn1 import DerObjectId

PARAM_SETS = list(ParamSet)

# Run every test with each C implementation available on this machine
_implementations = [pytest.param(MLDSA._raw_mldsa_portable_lib, id="portable")]
if MLDSA._raw_mldsa_avx2_bmi2_lib is not None:
    _implementations.append(pytest.param(MLDSA._raw_mldsa_avx2_bmi2_lib, id="avx2_bmi2"))


@pytest.fixture(autouse=True, params=_implementations)
def mldsa_implementation(request, monkeypatch):
    monkeypatch.setattr(MLDSA, "_raw_mldsa_lib", request.param)


# The hash functions of the ACVP vectors
HASHES = {
    "SHA2-224": SHA224.new,
    "SHA2-256": SHA256.new,
    "SHA2-384": SHA384.new,
    "SHA2-512": SHA512.new,
    "SHA2-512/224": lambda data: SHA512.new(data, truncate="224"),
    "SHA2-512/256": lambda data: SHA512.new(data, truncate="256"),
    "SHA3-224": SHA3_224.new,
    "SHA3-256": SHA3_256.new,
    "SHA3-384": SHA3_384.new,
    "SHA3-512": SHA3_512.new,
    "SHAKE-128": SHAKE128.new,
    "SHAKE-256": SHAKE256.new,
}


def fixed_rng(rnd):
    def randfunc(n):
        assert n == len(rnd)
        return rnd

    return randfunc


def acvp_external(name):
    """The ACVP tests of the external interface (ML-DSA and HashML-DSA)"""
    return [
        p for p in _load_acvp(name) if p.values[0] is None or p.values[0]["signatureInterface"] == "external"
    ]


def acvp_message(group, test):
    msg = unhexlify(test["message"])
    if group["preHash"] == "preHash":
        return HASHES[test["hashAlg"]](msg)
    assert group["preHash"] == "pure"
    return msg


class TestACVP:
    """The NIST ACVP test vectors for the external interface"""

    @pytest.mark.parametrize(
        "group,test",
        acvp_external("ML-DSA-sigGen-FIPS204.json") + acvp_external("ML-DSA-sigGen-FIPS204-preHash.json"),
    )
    def test_sign(self, group, test):
        key = MLDSA.construct(param_set=ParamSet(group["parameterSet"]), sk=unhexlify(test["sk"]))
        context = unhexlify(test["context"])
        if group["deterministic"]:
            signer = mldsa.new(key, context, deterministic=True)
        else:
            signer = mldsa.new(key, context, randfunc=fixed_rng(unhexlify(test["rnd"])))
        signature = signer.sign(acvp_message(group, test))
        assert signature == unhexlify(test["signature"])

        verifier = mldsa.new(key.public_key(), context)
        verifier.verify(acvp_message(group, test), signature)

    @pytest.mark.parametrize(
        "group,test",
        acvp_external("ML-DSA-sigVer-FIPS204.json") + acvp_external("ML-DSA-sigVer-FIPS204-preHash.json"),
    )
    def test_verify(self, group, test):
        key = MLDSA.construct(param_set=ParamSet(group["parameterSet"]), pk=unhexlify(test["pk"]))
        verifier = mldsa.new(key, unhexlify(test["context"]))
        msg = acvp_message(group, test)
        signature = unhexlify(test["signature"])
        if test["testPassed"]:
            verifier.verify(msg, signature)
        else:
            with pytest.raises(ValueError, match="not authentic"):
                verifier.verify(msg, signature)


class TestOpenSSL:
    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_verify(self, param_set):
        # ML-DSA signature of b"message" by OpenSSL, with an empty context
        base = "openssl_" + param_set.value.lower().replace("-", "_") + "_"
        try:
            pub_der = load_file(base + "public.der")
            signature = unhexlify(load_file(base + "sig_message.hex", "r").strip())
        except FileNotFoundError:
            pytest.skip("Missing OpenSSL test vectors")
        verifier = mldsa.new(MLDSA.import_key(pub_der))
        verifier.verify(b"message", signature)
        with pytest.raises(ValueError):
            verifier.verify(b"messagE", signature)


class TestMLDSASigScheme:
    key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_sign_verify(self, param_set):
        key = MLDSA.generate(param_set=param_set)
        signature = mldsa.new(key).sign(b"message")
        assert (
            len(signature) == {MLDSA.ML_DSA_44: 2420, MLDSA.ML_DSA_65: 3309, MLDSA.ML_DSA_87: 4627}[param_set]
        )
        mldsa.new(key.public_key()).verify(b"message", signature)
        # A private key can verify too
        mldsa.new(key).verify(b"message", signature)

    def test_message_types(self):
        signer = mldsa.new(self.key, deterministic=True)
        signature = signer.sign(b"message")
        assert signer.sign(bytearray(b"message")) == signature
        assert signer.sign(memoryview(b"message")) == signature
        verifier = mldsa.new(self.key.public_key())
        verifier.verify(bytearray(b"message"), bytearray(signature))
        verifier.verify(memoryview(b"message"), memoryview(signature))
        with pytest.raises(TypeError):
            signer.sign("message")
        with pytest.raises(TypeError):
            verifier.verify("message", signature)

    def test_hedged(self):
        # Hedged signatures are randomized
        signer = mldsa.new(self.key)
        assert signer.sign(b"message") != signer.sign(b"message")

        # rnd comes from randfunc
        rnd = bytes(range(32))
        signature = mldsa.new(self.key, randfunc=fixed_rng(rnd)).sign(b"message")
        assert signature == self.key._sign(b"message", rnd, prefix=pure_prefix())

        with pytest.raises(ValueError):
            mldsa.new(self.key, randfunc=lambda n: b"\x00" * (n - 1)).sign(b"message")

    def test_deterministic(self):
        signer = mldsa.new(self.key, b"ctx", deterministic=True)
        signature = signer.sign(b"message")
        assert signer.sign(b"message") == signature
        assert signature == self.key._sign(b"message", ZERO_RND, prefix=pure_prefix(b"ctx"))
        mldsa.new(self.key.public_key(), b"ctx").verify(b"message", signature)

        with pytest.raises(ValueError):
            mldsa.new(self.key, deterministic=True, randfunc=fixed_rng(ZERO_RND))

    def test_context(self):
        signature = mldsa.new(self.key, b"ctx").sign(b"message")
        mldsa.new(self.key, bytearray(b"ctx")).verify(b"message", signature)
        mldsa.new(self.key, memoryview(b"ctx")).verify(b"message", signature)
        for context in (None, b"", b"ctX"):
            with pytest.raises(ValueError):
                mldsa.new(self.key, context).verify(b"message", signature)

        # Up to 255 bytes
        signature = mldsa.new(self.key, b"\xff" * 255).sign(b"message")
        mldsa.new(self.key, b"\xff" * 255).verify(b"message", signature)
        with pytest.raises(ValueError):
            mldsa.new(self.key, b"\xff" * 256)
        with pytest.raises(TypeError):
            mldsa.new(self.key, "ctx")

    def test_not_authentic(self):
        signature = bytearray(mldsa.new(self.key).sign(b"message"))
        verifier = mldsa.new(self.key.public_key())
        with pytest.raises(ValueError):
            verifier.verify(b"messagE", signature)
        for bad in (signature[:-1], signature + b"\x00", b""):
            with pytest.raises(ValueError):
                verifier.verify(b"message", bad)
        signature[100] ^= 1
        with pytest.raises(ValueError):
            verifier.verify(b"message", signature)

        # A signature by another parameter set
        key65 = MLDSA.generate(param_set=MLDSA.ML_DSA_65)
        with pytest.raises(ValueError):
            verifier.verify(b"message", mldsa.new(key65).sign(b"message"))

    def test_can_sign(self):
        assert mldsa.new(self.key).can_sign()
        verifier = mldsa.new(self.key.public_key())
        assert not verifier.can_sign()
        with pytest.raises(TypeError):
            verifier.sign(b"message")

    def test_key_type(self):
        for key in (ECC.generate(curve="ed25519"), b"\x00" * 32, None):
            with pytest.raises(TypeError):
                mldsa.new(key)


class TestHashMLDSA:
    key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)

    @pytest.mark.parametrize("name", list(HASHES))
    def test_sign_verify(self, name):
        h = HASHES[name](b"message")
        signature = mldsa.new(self.key, b"ctx").sign(h)
        mldsa.new(self.key.public_key(), b"ctx").verify(HASHES[name](b"message"), signature)
        with pytest.raises(ValueError):
            mldsa.new(self.key.public_key(), b"ctx").verify(HASHES[name](b"messagE"), signature)

    @pytest.mark.parametrize("name", list(HASHES))
    def test_message(self, name):
        # M' = 1 || |ctx| || ctx || OID || PH(M) (FIPS 204, Algorithm 4)
        h = HASHES[name](b"message")
        oid = DerObjectId(h.oid).encode()
        ph = h.digest() if hasattr(h, "digest") else h.copy().read(64 if name == "SHAKE-256" else 32)
        expected = self.key._sign(ph, ZERO_RND, prefix=b"\x01\x03ctx" + oid)
        assert mldsa.new(self.key, b"ctx", deterministic=True).sign(h) == expected

        # The hash object can still be used
        assert mldsa.new(self.key, b"ctx", deterministic=True).sign(h) == expected

    def test_domain_separation(self):
        # Signing the digest of a message is not like signing its hash object
        h = SHA256.new(b"message")
        signature = mldsa.new(self.key).sign(h)
        with pytest.raises(ValueError):
            mldsa.new(self.key).verify(h.digest(), signature)
        with pytest.raises(ValueError):
            mldsa.new(self.key).verify(SHA3_256.new(b"message"), signature)

    def test_unsupported_hash(self):
        for h in (SHA1.new(b"message"), MD5.new(b"message"), BLAKE2b.new(data=b"message"), 5):
            with pytest.raises(TypeError):
                mldsa.new(self.key).sign(h)
            with pytest.raises(TypeError):
                mldsa.new(self.key).verify(h, b"\x00" * 2420)

    def test_xof_already_read(self):
        h = SHAKE128.new(b"message")
        h.read(1)
        with pytest.raises(ValueError):
            mldsa.new(self.key).sign(h)
        with pytest.raises(ValueError):
            mldsa.new(self.key).verify(h, b"\x00" * 2420)


def compute_mu(pub_key, message, context=b""):
    """mu (FIPS 204, Algorithm 7)"""
    tr = SHAKE256.new(pub_key.pk).read(64)
    return SHAKE256.new(tr + b"\x00" + bytes([len(context)]) + context + message).read(64)


def acvp_pure(name):
    """The ACVP tests for ML-DSA (pure, external interface)"""
    return [p for p in acvp_external(name) if p.values[0] is None or p.values[0]["preHash"] == "pure"]


class TestMLDSAMuHash:
    key = MLDSA.generate(param_set=MLDSA.ML_DSA_44)

    @pytest.mark.parametrize("group,test", acvp_pure("ML-DSA-sigGen-FIPS204.json"))
    def test_acvp_sign(self, group, test):
        key = MLDSA.construct(param_set=ParamSet(group["parameterSet"]), sk=unhexlify(test["sk"]))
        if group["deterministic"]:
            signer = mldsa.new(key, deterministic=True)
        else:
            signer = mldsa.new(key, randfunc=fixed_rng(unhexlify(test["rnd"])))
        mu_hash = mldsa.MLDSAMuHash(key, data=unhexlify(test["message"]), context=unhexlify(test["context"]))
        signature = signer.sign(mu_hash)
        assert signature == unhexlify(test["signature"])
        mldsa.new(key.public_key()).verify(mu_hash, signature)

    @pytest.mark.parametrize("group,test", acvp_pure("ML-DSA-sigVer-FIPS204.json"))
    def test_acvp_verify(self, group, test):
        key = MLDSA.construct(param_set=ParamSet(group["parameterSet"]), pk=unhexlify(test["pk"]))
        mu_hash = mldsa.MLDSAMuHash(key, data=unhexlify(test["message"]), context=unhexlify(test["context"]))
        signature = unhexlify(test["signature"])
        if test["testPassed"]:
            mldsa.new(key).verify(mu_hash, signature)
        else:
            with pytest.raises(ValueError, match="not authentic"):
                mldsa.new(key).verify(mu_hash, signature)

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    @pytest.mark.parametrize("context", [None, b"", b"ctx", b"\xff" * 255])
    def test_same_as_message(self, param_set, context):
        key = MLDSA.generate(param_set=param_set)
        mu_hash = mldsa.MLDSAMuHash(key.public_key(), data=b"message", context=context)
        assert mu_hash.digest() == compute_mu(key, b"message", context or b"")

        # The same signature as for the message
        signature = mldsa.new(key, deterministic=True).sign(mu_hash)
        assert signature == mldsa.new(key, context, deterministic=True).sign(b"message")
        mldsa.new(key.public_key(), context).verify(b"message", signature)

        # A hedged signature of the message is verified with the MLDSAMuHash
        signature = mldsa.new(key, context).sign(b"message")
        mldsa.new(key.public_key()).verify(mu_hash, signature)

    def test_update(self):
        mu = compute_mu(self.key, b"message", b"ctx")
        mu_hash = mldsa.MLDSAMuHash(self.key, context=b"ctx")
        assert mu_hash.update(b"mes") is mu_hash
        mu_hash.update(bytearray(b"sa")).update(memoryview(b"ge"))
        assert mu_hash.digest() == mu
        # digest() does not change the state
        assert mu_hash.digest() == mu
        mu_hash.update(b"!")
        assert mu_hash.digest() == compute_mu(self.key, b"message!", b"ctx")

        assert mldsa.MLDSAMuHash(self.key, data=bytearray(b"message"), context=b"ctx").digest() == mu
        assert mldsa.MLDSAMuHash(self.key).digest() == compute_mu(self.key, b"")
        assert mldsa.MLDSAMuHash.digest_size == 64

        # A long message, in pieces
        message = bytes(range(256)) * 1000
        mu_hash = mldsa.MLDSAMuHash(self.key)
        for i in range(0, len(message), 1000):
            mu_hash.update(message[i : i + 1000])
        assert mu_hash.digest() == compute_mu(self.key, message)

    def test_copy(self):
        mu_hash = mldsa.MLDSAMuHash(self.key, data=b"mess", context=b"ctx")
        clone = mu_hash.copy()
        mu_hash.update(b"age")
        clone.update(b"y")
        assert mu_hash.digest() == compute_mu(self.key, b"message", b"ctx")
        assert clone.digest() == compute_mu(self.key, b"messy", b"ctx")
        mldsa.new(self.key).verify(clone, mldsa.new(self.key, b"ctx").sign(b"messy"))

    def test_hedged(self):
        mu_hash = mldsa.MLDSAMuHash(self.key, data=b"message")
        signer = mldsa.new(self.key)
        assert signer.sign(mu_hash) != signer.sign(mu_hash)
        rnd = bytes(range(32))
        signature = mldsa.new(self.key, randfunc=fixed_rng(rnd)).sign(mu_hash)
        assert signature == self.key._sign(b"message", rnd, prefix=pure_prefix())

    def test_not_authentic(self):
        signature = mldsa.new(self.key).sign(b"message")
        verifier = mldsa.new(self.key.public_key())
        verifier.verify(mldsa.MLDSAMuHash(self.key, data=b"message"), signature)
        for mu_hash in (
            mldsa.MLDSAMuHash(self.key, data=b"messagE"),
            mldsa.MLDSAMuHash(self.key, data=b"message", context=b"ctx"),
            mldsa.MLDSAMuHash(self.key, data=b"message", context=b"").update(b"!"),
        ):
            with pytest.raises(ValueError, match="not authentic"):
                verifier.verify(mu_hash, signature)
        with pytest.raises(ValueError, match="not authentic"):
            verifier.verify(mldsa.MLDSAMuHash(self.key, data=b"message"), signature[:-1])

    def test_context_of_signer(self):
        # The context is the one of the MLDSAMuHash: the signer cannot have one, not even an empty one
        mu_hash = mldsa.MLDSAMuHash(self.key, data=b"message", context=b"ctx")
        signature = mldsa.new(self.key, b"ctx").sign(b"message")
        for context in (b"ctx", b"", bytearray(), memoryview(b"")):
            with pytest.raises(ValueError, match="context"):
                mldsa.new(self.key, context).sign(mu_hash)
            with pytest.raises(ValueError, match="context"):
                mldsa.new(self.key, context).verify(mu_hash, signature)
        mldsa.new(self.key, None).verify(mu_hash, signature)

    def test_other_key(self):
        other = MLDSA.generate(param_set=MLDSA.ML_DSA_44)
        mu_hash = mldsa.MLDSAMuHash(other, data=b"message")
        with pytest.raises(ValueError, match="another key"):
            mldsa.new(self.key).sign(mu_hash)
        with pytest.raises(ValueError, match="another key"):
            mldsa.new(self.key).verify(mu_hash, mldsa.new(other).sign(b"message"))

        # A public key and its private key are the same key
        signature = mldsa.new(self.key).sign(mldsa.MLDSAMuHash(self.key.public_key(), data=b"message"))
        mldsa.new(self.key.public_key()).verify(mldsa.MLDSAMuHash(self.key, data=b"message"), signature)

    def test_errors(self):
        for key in (ECC.generate(curve="ed25519"), self.key.pk, None):
            with pytest.raises(TypeError):
                mldsa.MLDSAMuHash(key)
        with pytest.raises(ValueError):
            mldsa.MLDSAMuHash(self.key, context=b"\xff" * 256)
        with pytest.raises(TypeError):
            mldsa.MLDSAMuHash(self.key, context="ctx")
        # data and context are keyword-only
        with pytest.raises(TypeError):
            mldsa.MLDSAMuHash(self.key, b"message")
        with pytest.raises(TypeError):
            mldsa.MLDSAMuHash(self.key, data="message")
        with pytest.raises(TypeError):
            mldsa.MLDSAMuHash(self.key).update("message")

        # A public key cannot sign
        with pytest.raises(TypeError):
            mldsa.new(self.key.public_key()).sign(mldsa.MLDSAMuHash(self.key, data=b"message"))


def _load_wycheproof(filename):
    def param_set(group):
        return ParamSet("ML-DSA-" + filename.split("_")[1])

    def optional_hex(name):
        def convert(test):
            return unhexlify(test[name]) if name in test else None

        return convert

    def group_hex(name):
        def convert(group):
            return unhexlify(group[name]) if group.get(name) is not None else None

        return convert

    return load_test_vectors_wycheproof(
        ("Signature", "wycheproof"),
        filename,
        "Wycheproof ML-DSA (%s)" % filename,
        group_tag={
            "param_set": param_set,
            "seed": group_hex("privateSeed"),
            "sk": group_hex("privateKey"),
            "pk": group_hex("publicKey"),
            "pkcs8": group_hex("privateKeyPkcs8"),
            "pk_der": group_hex("publicKeyDer"),
        },
        unit_tag={"ctx": optional_hex("ctx"), "mu": optional_hex("mu"), "rnd": optional_hex("rnd")},
    )


def load_wycheproof_sign():
    vectors = []
    for level in (44, 65, 87):
        vectors += _load_wycheproof("mldsa_%d_sign_seed_test.json" % level)
        vectors += _load_wycheproof("mldsa_%d_sign_noseed_test.json" % level)
    return vectors


def load_wycheproof_verify():
    vectors = []
    for level in (44, 65, 87):
        vectors += _load_wycheproof("mldsa_%d_verify_test.json" % level)
    return vectors


class TestWycheproof:
    @pytest.mark.parametrize("tv", load_wycheproof_sign(), ids=wycheproof_id)
    def test_sign(self, tv):
        try:
            if tv.seed is not None:
                key = MLDSA.construct(param_set=tv.param_set, seed=tv.seed)
            else:
                key = MLDSA.construct(param_set=tv.param_set, sk=tv.sk)
        except ValueError:
            assert not tv.valid
            assert {"IncorrectPrivateKeyLength", "InvalidPrivateKey"} & set(tv.flags)
            return
        if tv.pk is not None:
            assert key.pk == tv.pk
        if tv.pkcs8 is not None:
            # RFC 9881, with the seed
            assert MLDSA.import_key(tv.pkcs8) == key
            assert key.export_key() == tv.pkcs8

        rnd = tv.rnd if tv.rnd is not None else ZERO_RND
        if not hasattr(tv, "msg"):
            # Sign_internal, with mu only
            assert "Internal" in tv.flags
            signature = key._sign(tv.mu, rnd, external_mu=True)
            assert signature == tv.sig
            assert key._verify(tv.mu, signature, external_mu=True)
            return

        try:
            if tv.rnd is None:
                signer = mldsa.new(key, tv.ctx, deterministic=True)
            else:
                signer = mldsa.new(key, tv.ctx, randfunc=fixed_rng(tv.rnd))
        except ValueError:
            assert not tv.valid
            assert "InvalidContext" in tv.flags
            return
        assert tv.valid

        signature = signer.sign(tv.msg)
        assert signature == tv.sig
        mldsa.new(key.public_key(), tv.ctx).verify(tv.msg, signature)

        # The message representative mu
        if tv.mu is not None:
            mu_hash = mldsa.MLDSAMuHash(key, data=tv.msg, context=tv.ctx)
            assert mu_hash.digest() == tv.mu
            assert key._sign(tv.mu, rnd, external_mu=True) == tv.sig

    @pytest.mark.parametrize("tv", load_wycheproof_verify(), ids=wycheproof_id)
    def test_verify(self, tv):
        try:
            key = MLDSA.construct(param_set=tv.param_set, pk=tv.pk)
        except ValueError:
            assert not tv.valid
            assert "IncorrectPublicKeyLength" in tv.flags
            return
        assert MLDSA.import_key(tv.pk_der) == key

        try:
            verifier = mldsa.new(key, tv.ctx)
        except ValueError:
            assert not tv.valid
            assert "InvalidContext" in tv.flags
            return

        try:
            verifier.verify(tv.msg, tv.sig)
        except ValueError:
            assert not tv.valid
        else:
            assert tv.valid
