# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Self-tests for Crypto.Signature.slhdsa"""

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
from Crypto.PublicKey import ECC, MLDSA, SLHDSA
from Crypto.PublicKey.SLHDSA import ParamSet
from Crypto.SelfTest.PublicKey.test_SLHDSA import (
    _implementations,
    _load_acvp,
    all_param_sets,
    pure_prefix,
    use_implementation,
)
from Crypto.Signature import slhdsa
from Crypto.Util.asn1 import DerObjectId


# Run every test with each C implementation (see test_SLHDSA.py)
@pytest.fixture(autouse=True, params=_implementations)
def slhdsa_implementation(request, monkeypatch):
    use_implementation(monkeypatch, *request.param)


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

SIG_LEN_128F = 17088


def fixed_rng(rnd):
    def randfunc(n):
        assert n == len(rnd)
        return rnd

    return randfunc


def acvp_external(name):
    """The ACVP tests of the external interface (SLH-DSA and HashSLH-DSA)"""
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
        acvp_external("SLH-DSA-sigGen-FIPS205.json") + acvp_external("SLH-DSA-sigGen-FIPS205-preHash.json"),
    )
    def test_sign(self, group, test):
        key = SLHDSA.construct(param_set=ParamSet(group["parameterSet"]), sk=unhexlify(test["sk"]))
        context = unhexlify(test["context"])
        if group["deterministic"]:
            signer = slhdsa.new(key, context=context, deterministic=True)
        else:
            signer = slhdsa.new(
                key, context=context, randfunc=fixed_rng(unhexlify(test["additionalRandomness"]))
            )
        signature = signer.sign(acvp_message(group, test))
        assert signature == unhexlify(test["signature"])

        verifier = slhdsa.new(key.public_key(), context=context)
        verifier.verify(acvp_message(group, test), signature)

    @pytest.mark.parametrize(
        "group,test",
        acvp_external("SLH-DSA-sigVer-FIPS205.json") + acvp_external("SLH-DSA-sigVer-FIPS205-preHash.json"),
    )
    def test_verify(self, group, test):
        key = SLHDSA.construct(param_set=ParamSet(group["parameterSet"]), pk=unhexlify(test["pk"]))
        verifier = slhdsa.new(key, context=unhexlify(test["context"]))
        msg = acvp_message(group, test)
        signature = unhexlify(test["signature"])
        if test["testPassed"]:
            verifier.verify(msg, signature)
        else:
            with pytest.raises(ValueError, match="not authentic"):
                verifier.verify(msg, signature)


class TestSLHDSASigScheme:
    key = SLHDSA.generate(param_set=SLHDSA.SLH_DSA_SHA2_128f)

    @pytest.mark.parametrize("param_set", all_param_sets())
    def test_sign_verify(self, param_set):
        key = SLHDSA.generate(param_set=param_set)
        signature = slhdsa.new(key).sign(b"message")
        assert len(signature) == SLHDSA._params[param_set].sig_len
        slhdsa.new(key.public_key()).verify(b"message", signature)
        # A private key can verify too
        slhdsa.new(key).verify(b"message", signature)

    def test_message_types(self):
        signer = slhdsa.new(self.key, deterministic=True)
        signature = signer.sign(b"message")
        assert signer.sign(bytearray(b"message")) == signature
        assert signer.sign(memoryview(b"message")) == signature
        verifier = slhdsa.new(self.key.public_key())
        verifier.verify(bytearray(b"message"), bytearray(signature))
        verifier.verify(memoryview(b"message"), memoryview(signature))
        with pytest.raises(TypeError):
            signer.sign("message")
        with pytest.raises(TypeError):
            verifier.verify("message", signature)
        with pytest.raises(TypeError):
            verifier.verify(b"message", signature.hex())

    def test_hedged(self):
        # Hedged signatures are randomized
        signer = slhdsa.new(self.key)
        assert signer.sign(b"message") != signer.sign(b"message")

        # addrnd comes from randfunc
        addrnd = bytes(range(16))
        signature = slhdsa.new(self.key, randfunc=fixed_rng(addrnd)).sign(b"message")
        assert signature == self.key._sign((pure_prefix(), b"message"), addrnd)

        with pytest.raises(ValueError):
            slhdsa.new(self.key, randfunc=lambda n: b"\x00" * (n - 1)).sign(b"message")

    def test_deterministic(self):
        signer = slhdsa.new(self.key, context=b"ctx", deterministic=True)
        signature = signer.sign(b"message")
        assert signer.sign(b"message") == signature
        assert signature == self.key._sign((pure_prefix(b"ctx"), b"message"), None)
        slhdsa.new(self.key.public_key(), context=b"ctx").verify(b"message", signature)

        with pytest.raises(ValueError):
            slhdsa.new(self.key, deterministic=True, randfunc=fixed_rng(b"\x00" * 16))

    def test_context(self):
        signature = slhdsa.new(self.key, context=b"ctx").sign(b"message")
        slhdsa.new(self.key, context=bytearray(b"ctx")).verify(b"message", signature)
        slhdsa.new(self.key, context=memoryview(b"ctx")).verify(b"message", signature)
        for context in (None, b"", b"ctX"):
            with pytest.raises(ValueError):
                slhdsa.new(self.key, context=context).verify(b"message", signature)

        # No context is the empty context
        signature = slhdsa.new(self.key).sign(b"message")
        slhdsa.new(self.key, context=b"").verify(b"message", signature)

        # Up to 255 bytes
        signature = slhdsa.new(self.key, context=b"\xff" * 255).sign(b"message")
        slhdsa.new(self.key, context=b"\xff" * 255).verify(b"message", signature)
        with pytest.raises(ValueError):
            slhdsa.new(self.key, context=b"\xff" * 256)
        with pytest.raises(TypeError):
            slhdsa.new(self.key, context="ctx")

        # The context is a keyword argument only
        with pytest.raises(TypeError):
            slhdsa.new(self.key, b"ctx")  # type: ignore[misc]

    def test_not_authentic(self):
        signature = bytearray(slhdsa.new(self.key).sign(b"message"))
        verifier = slhdsa.new(self.key.public_key())
        with pytest.raises(ValueError):
            verifier.verify(b"messagE", signature)
        for bad in (signature[:-1], signature + b"\x00", b""):
            with pytest.raises(ValueError):
                verifier.verify(b"message", bad)
        signature[100] ^= 1
        with pytest.raises(ValueError):
            verifier.verify(b"message", signature)

        # A signature by another parameter set with the same n
        key_shake = SLHDSA.generate(param_set=SLHDSA.SLH_DSA_SHAKE_128f)
        with pytest.raises(ValueError):
            verifier.verify(b"message", slhdsa.new(key_shake).sign(b"message"))

    def test_threads(self):
        signature = slhdsa.new(self.key, context=b"ctx", deterministic=True).sign(b"message")
        for threads in (2, 0):
            signer = slhdsa.new(self.key, context=b"ctx", deterministic=True, threads=threads)
            assert signer.sign(b"message") == signature
            slhdsa.new(self.key.public_key(), context=b"ctx", threads=threads).verify(b"message", signature)
        for bad, exc in ((-1, ValueError), ("2", TypeError), (2.0, TypeError), (False, TypeError)):
            with pytest.raises(exc):
                slhdsa.new(self.key, threads=bad)

    def test_can_sign(self):
        assert slhdsa.new(self.key).can_sign()
        verifier = slhdsa.new(self.key.public_key())
        assert not verifier.can_sign()
        with pytest.raises(TypeError):
            verifier.sign(b"message")

    def test_key_type(self):
        for key in (
            ECC.generate(curve="ed25519"),
            MLDSA.generate(param_set=MLDSA.ML_DSA_44),
            b"\x00" * 32,
            None,
        ):
            with pytest.raises(TypeError):
                slhdsa.new(key)


class TestHashSLHDSA:
    key = SLHDSA.generate(param_set=SLHDSA.SLH_DSA_SHA2_128f)

    @pytest.mark.parametrize("name", list(HASHES))
    def test_sign_verify(self, name):
        h = HASHES[name](b"message")
        signature = slhdsa.new(self.key, context=b"ctx").sign(h)
        slhdsa.new(self.key.public_key(), context=b"ctx").verify(HASHES[name](b"message"), signature)
        with pytest.raises(ValueError):
            slhdsa.new(self.key.public_key(), context=b"ctx").verify(HASHES[name](b"messagE"), signature)

    @pytest.mark.parametrize("name", list(HASHES))
    def test_message(self, name):
        # M' = 1 || |ctx| || ctx || OID || PH(M) (FIPS 205, Algorithm 23)
        h = HASHES[name](b"message")
        oid = DerObjectId(h.oid).encode()
        ph = h.digest() if hasattr(h, "digest") else h.copy().read(64 if name == "SHAKE-256" else 32)
        expected = self.key._sign((b"\x01\x03ctx" + oid, ph), None)
        assert slhdsa.new(self.key, context=b"ctx", deterministic=True).sign(h) == expected

        # The hash object can still be used
        assert slhdsa.new(self.key, context=b"ctx", deterministic=True).sign(h) == expected

    def test_domain_separation(self):
        # Signing the digest of a message is not like signing its hash object
        h = SHA256.new(b"message")
        signature = slhdsa.new(self.key).sign(h)
        with pytest.raises(ValueError):
            slhdsa.new(self.key).verify(h.digest(), signature)
        with pytest.raises(ValueError):
            slhdsa.new(self.key).verify(SHA3_256.new(b"message"), signature)

    def test_unsupported_hash(self):
        for h in (SHA1.new(b"message"), MD5.new(b"message"), BLAKE2b.new(data=b"message"), 5):
            with pytest.raises(TypeError):
                slhdsa.new(self.key).sign(h)
            with pytest.raises(TypeError):
                slhdsa.new(self.key).verify(h, b"\x00" * SIG_LEN_128F)

    def test_xof_already_read(self):
        h = SHAKE128.new(b"message")
        h.read(1)
        with pytest.raises(ValueError):
            slhdsa.new(self.key).sign(h)
        with pytest.raises(ValueError):
            slhdsa.new(self.key).verify(h, b"\x00" * SIG_LEN_128F)
