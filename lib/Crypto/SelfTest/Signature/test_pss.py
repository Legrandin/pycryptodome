# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause


import pytest

from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.SelfTest.loader import load_test_vectors, load_test_vectors_wycheproof, wycheproof_id
from Crypto.SelfTest.st_common import wycheproof_warnings
from Crypto.Signature import PKCS1_PSS, pss
from Crypto.Signature.pss import MGF1
from Crypto.Util.number import bytes_to_long
from Crypto.Util.strxor import strxor


def load_hash_by_name(hash_name):
    return __import__("Crypto.Hash." + hash_name, globals(), locals(), ["new"])


class PRNG:
    def __init__(self, stream):
        self.stream = stream
        self.idx = 0

    def __call__(self, rnd_size):
        result = self.stream[self.idx : self.idx + rnd_size]
        self.idx += rnd_size
        return result


class TestPSS:
    rsa_key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsvI34FgiTK8+txBvmooNGpNwk23YTU51dwNZi5yha3W4lA/Q\nvcZrDalkmD7ekWQwnduxVKa6pRSI13KBgeUOIqJoGXSWhntEtY3FEwvWOHW5AE7Q\njUzTzCiYT6TVaCcpa/7YLai+p6ai2g5f5Zfh4jSawa9uYeuggFygQq4IVW796MgV\nyqxYMM/arEj+/sKz3Viua9Rp9fFosertCYCX4DUTgW0mX9bwEnEOgjSI3pLOPXz1\n8vx+DRZS5wMCmwCUa0sKonLn3cAUPq+sGix7+eo7T0Z12MU8ud7IYVX/75r3cXiF\nPaYE2q8Le0kgOApIXbb+x74x0rNgyIh1yGygkwIDAQABAoIBABz4t1A0pLT6qHI2\nEIOaNz3mwhK0dZEqkz0GB1Dhtoax5ATgvKCFB98J3lYB08IBURe1snOsnMpOVUtg\naBRSM+QqnCUG6bnzKjAkuFP5liDE+oNQv1YpKp9CsUovuzdmI8Au3ewihl+ZTIN2\nUVNYMEOR1b5m+z2SSwWNOYsiJwpBrT7zkpdlDyjat7FiiPhMMIMXjhQFVxURMIcB\njUBtPzGvV/PG90cVDWi1wRGeeP1dDqti/jsnvykQ15KW1MqGrpeNKRmDdTy/Ucl1\nWIoYklKw3U456lgZ/rDTDB818+Tlnk35z4yF7d5ANPM8CKfqOPcnO1BCKVFzf4eq\n54wvUtkCgYEA1Zv2lp06l7rXMsvNtyYQjbFChezRDRnPwZmN4NCdRtTgGG1G0Ryd\nYz6WWoPGqZp0b4LAaaHd3W2GTcpXF8WXMKfMX1W+tMAxMozfsXRKMcHoypwuS5wT\nfJRXJCG4pvd57AB0iVUEJW2we+uGKU5Zxcx//id2nXGCpoRyViIplQsCgYEA1nVC\neHupHChht0Fh4N09cGqZHZzuwXjOUMzR3Vsfz+4WzVS3NvIgN4g5YgmQFOeKwo5y\niRq5yvubcNdFvf85eHWClg0zPAyxJCVUWigCrrOanGEhJo6re4idJvNVzu4Ucg0v\n6B3SJ1HsCda+ZSNz24bSyqRep8A+RoAaoVSFx5kCgYEAn3RvXPs9s+obnqWYiPF3\nRe5etE6Vt2vfNKwFxx6zaR6bsmBQjuUHcABWiHb6I71S0bMPI0tbrWGG8ibrYKl1\nNTLtUvVVCOS3VP7oNTWT9RTFTAnOXU7DFSo+6o/poWn3r36ff6zhDXeWWMr2OXtt\ndEQ1/2lCGEGVv+v61eVmmQUCgYABFHITPTwqwiFL1O5zPWnzyPWgaovhOYSAb6eW\n38CXQXGn8wdBJZL39J2lWrr4//l45VK6UgIhfYbY2JynSkO10ZGow8RARygVMILu\nOUlaK9lZdDvAf/NpGdUAvzTtZ9F+iYZ2OsA2JnlzyzsGM1l//3vMPWukmJk3ral0\nqoJJ8QKBgGRG3eVHnIegBbFVuMDp2NTcfuSuDVUQ1fGAwtPiFa8u81IodJnMk2pq\niXu2+0ytNA/M+SVrAnE2AgIzcaJbtr0p2srkuVM7KMWnG1vWFNjtXN8fAhf/joOv\nD+NmPL/N4uE57e40tbiU/H7KdyZaDt+5QiTmdhuyAe6CBjKsF2jy\n-----END RSA PRIVATE KEY-----"
    msg = b"AAA"
    tag = b'\x00[c5\xd8\xb0\x8b!D\x81\x83\x07\xc0\xdd\xb9\xb4\xb2`\x92\xe7\x02\xf1\xe1P\xea\xc3\xf0\xe3>\xddX5\xdd\x8e\xc5\x89\xef\xf3\xc2\xdc\xfeP\x02\x7f\x12+\xc9\xaf\xbb\xec\xfe\xb0\xa5\xb9\x08\x11P\x8fL\xee5\x9b\xb0k{=_\xd2\x14\xfb\x01R\xb7\xfe\x14}b\x03\x8d5Y\x89~}\xfc\xf2l\xd01-\xbd\xeb\x11\xcdV\x11\xe9l\x19k/o5\xa2\x0f\x15\xe7Q$\t=\xec\x1dAB\x19\xa5P\x9a\xaf\xa3G\x86"\xd6~\xf0<p5\x00\x86\xe0\xf3\x99\xc7+\xcfc,\\\x13)v\xcd\xff\x08o\x90\xc5\xd1\xca\x869\xf45\x1e\xfd\xa2\xf1n\xa3\xa6e\xc5\x11Q\xe4@\xbd\x17\x83x\xc9\x9b\xb5\xc7\xea\x03U\x9b\xa0\xccC\x17\xc9T\x86/\x05\x1c\xc7\x95hC\xf9b1\xbb\x05\xc3\xf0\x9a>j\xfcqkbs\x13\x84b\xe4\xbdm(\xed`\xa4F\xfb\x8f.\xe1\x8c)/_\x9eS\x98\xa4v\xb8\xdc\xfe\xf7/D\x18\x19\xb3T\x97:\xe2\x96s\xe8<\xa2\xb4\xb9\xf8/'

    def test_positive_1(self):
        key = RSA.import_key(self.rsa_key)
        h = SHA256.new(self.msg)
        verifier = pss.new(key)
        verifier.verify(h, self.tag)

    def test_negative_1(self):
        key = RSA.import_key(self.rsa_key)
        h = SHA256.new(self.msg + b"A")
        verifier = pss.new(key)
        tag = bytearray(self.tag)
        with pytest.raises(ValueError):
            verifier.verify(h, tag)

    def test_negative_2(self):
        key = RSA.import_key(self.rsa_key)
        h = SHA256.new(self.msg)
        verifier = pss.new(key, salt_bytes=1000)
        tag = bytearray(self.tag)
        with pytest.raises(ValueError):
            verifier.verify(h, tag)


class TestFIPS_PKCS1_Verify:
    def verify_positive(self, hashmod, message, public_key, salt, signature):
        prng = PRNG(salt)
        hashed = hashmod.new(message)
        verifier = pss.new(public_key, salt_bytes=len(salt), rand_func=prng)
        verifier.verify(hashed, signature)

    def verify_negative(self, hashmod, message, public_key, salt, signature):
        prng = PRNG(salt)
        hashed = hashmod.new(message)
        verifier = pss.new(public_key, salt_bytes=len(salt), rand_func=prng)
        with pytest.raises(ValueError):
            verifier.verify(hashed, signature)

    def test_can_sign(self):
        test_public_key = RSA.generate(1024).public_key()
        verifier = pss.new(test_public_key)
        assert verifier.can_sign() is False


test_vectors_verify = (
    load_test_vectors(
        ("Signature", "PKCS1-PSS"),
        "SigVerPSS_186-3.rsp",
        "Signature Verification 186-3",
        {"shaalg": lambda x: x, "result": lambda x: x},
    )
    or []
)


def _load_verify_vectors():
    params = []
    for count, tv in enumerate(test_vectors_verify):
        if isinstance(tv, str):
            continue
        if hasattr(tv, "n"):
            modulus = tv.n
            continue
        if hasattr(tv, "p"):
            continue

        hash_module = load_hash_by_name(tv.shaalg.upper())
        hash_obj = hash_module.new(tv.msg)
        public_key = RSA.construct([bytes_to_long(x) for x in (modulus, tv.e)])  # type: ignore
        if tv.saltval != b"\x00":
            prng = PRNG(tv.saltval)
            verifier = pss.new(public_key, salt_bytes=len(tv.saltval), rand_func=prng)
        else:
            verifier = pss.new(public_key, salt_bytes=0)
        params.append(pytest.param(hash_obj, verifier, tv.s, tv.result == "p", id=str(count)))
    return params


@pytest.mark.slow
class TestFIPS_PKCS1_Verify_Tests_KAT:
    @pytest.mark.parametrize("hash_obj, verifier, signature, valid", _load_verify_vectors())
    def test_verify(self, hash_obj, verifier, signature, valid):
        if valid:
            verifier.verify(hash_obj, signature)
        else:
            with pytest.raises(ValueError):
                verifier.verify(hash_obj, signature)


class TestFIPS_PKCS1_Sign:
    def test_can_sign(self):
        test_private_key = RSA.generate(1024)
        signer = pss.new(test_private_key)
        assert signer.can_sign() is True


test_vectors_sign = (
    load_test_vectors(
        ("Signature", "PKCS1-PSS"),
        "SigGenPSS_186-2.txt",
        "Signature Generation 186-2",
        {"shaalg": lambda x: x},
    )
    or []
)

test_vectors_sign += (
    load_test_vectors(
        ("Signature", "PKCS1-PSS"),
        "SigGenPSS_186-3.txt",
        "Signature Generation 186-3",
        {"shaalg": lambda x: x},
    )
    or []
)


def _load_sign_vectors():
    params = []
    for count, tv in enumerate(test_vectors_sign):
        if isinstance(tv, str):
            continue
        if hasattr(tv, "n"):
            modulus = tv.n
            continue
        if hasattr(tv, "e"):
            private_key = RSA.construct([bytes_to_long(x) for x in (modulus, tv.e, tv.d)])  # type: ignore
            continue

        hash_module = load_hash_by_name(tv.shaalg.upper())
        hash_obj = hash_module.new(tv.msg)
        if tv.saltval != b"\x00":
            prng = PRNG(tv.saltval)
            signer = pss.new(private_key, salt_bytes=len(tv.saltval), rand_func=prng)
        else:
            signer = pss.new(private_key, salt_bytes=0)
        params.append(pytest.param(hash_obj, signer, tv.s, id=str(count)))
    return params


@pytest.mark.slow
class TestFIPS_PKCS1_Sign_Tests_KAT:
    @pytest.mark.parametrize("hash_obj, signer, result", _load_sign_vectors())
    def test_sign(self, hash_obj, signer, result):
        signature = signer.sign(hash_obj)
        assert signature == result


class TestPKCS1_Legacy_Module:
    """Verify that the legacy module Crypto.Signature.PKCS1_PSS
    behaves as expected. The only difference is that the verify()
    method returns True/False and does not raise exceptions."""

    def test(self):
        key = RSA.generate(1024)
        hashed = SHA1.new(b"Test")
        good_signature = PKCS1_PSS.new(key).sign(hashed)
        verifier = PKCS1_PSS.new(key.public_key())

        assert verifier.verify(hashed, good_signature) is True

        # Flip a few bits in the signature
        bad_signature = strxor(good_signature, bytes([1]) * len(good_signature))
        assert verifier.verify(hashed, bad_signature) is False


class TestPKCS1_All_Hashes:
    def test(self):
        key = RSA.generate(1280)
        signer = pss.new(key)
        hash_names = (
            "MD2",
            "MD4",
            "MD5",
            "RIPEMD160",
            "SHA1",
            "SHA224",
            "SHA256",
            "SHA384",
            "SHA512",
            "SHA3_224",
            "SHA3_256",
            "SHA3_384",
            "SHA3_512",
        )

        for name in hash_names:
            hashed = load_hash_by_name(name).new(b"Test")
            signer.sign(hashed)

        from Crypto.Hash import BLAKE2b, BLAKE2s

        for hash_size in (20, 32, 48, 64):
            hashed_b = BLAKE2b.new(digest_bytes=hash_size, data=b"Test")
            signer.sign(hashed_b)
        for hash_size in (16, 20, 28, 32):
            hashed_s = BLAKE2s.new(digest_bytes=hash_size, data=b"Test")
            signer.sign(hashed_s)


def get_hash_module(hash_name):
    if hash_name == "SHA-512":
        hash_module = SHA512
    elif hash_name == "SHA-512/224":
        hash_module = SHA512.new(truncate="224")
    elif hash_name == "SHA-512/256":
        hash_module = SHA512.new(truncate="256")
    elif hash_name == "SHA-384":
        hash_module = SHA384
    elif hash_name == "SHA-256":
        hash_module = SHA256
    elif hash_name == "SHA-224":
        hash_module = SHA224
    elif hash_name == "SHA-1":
        hash_module = SHA1
    else:
        raise ValueError("Unknown hash algorithm: " + hash_name)
    return hash_module


def _load_tests(filename):
    def filter_rsa(group):
        return RSA.import_key(group["keyPem"])

    def filter_sha(group):
        return get_hash_module(group["sha"])

    def filter_type(group):
        type_name = group["type"]
        if type_name not in ("RsassaPssVerify",):
            raise ValueError("Unknown type name " + type_name)

    def filter_slen(group):
        return group["sLen"]

    def filter_mgf(group):
        mgf = group["mgf"]
        if mgf not in ("MGF1",):
            raise ValueError("Unknown MGF " + mgf)
        mgf1_hash = get_hash_module(group["mgfSha"])

        def mgf(x, y, mh=mgf1_hash):
            return MGF1(x, y, mh)

        return mgf

    result = load_test_vectors_wycheproof(
        ("Signature", "wycheproof"),
        filename,
        "Wycheproof PSS signature (%s)" % filename,
        group_tag={
            "key": filter_rsa,
            "hash_module": filter_sha,
            "sLen": filter_slen,
            "mgf": filter_mgf,
            "type": filter_type,
        },
    )
    return result


def load_wycheproof_vectors():
    vectors = []
    vectors += _load_tests("rsa_pss_2048_sha1_mgf1_20_test.json")
    vectors += _load_tests("rsa_pss_2048_sha256_mgf1_0_test.json")
    vectors += _load_tests("rsa_pss_2048_sha256_mgf1_32_test.json")
    vectors += _load_tests("rsa_pss_2048_sha512_256_mgf1_28_test.json")
    vectors += _load_tests("rsa_pss_2048_sha512_256_mgf1_32_test.json")
    vectors += _load_tests("rsa_pss_3072_sha256_mgf1_32_test.json")
    vectors += _load_tests("rsa_pss_4096_sha256_mgf1_32_test.json")
    vectors += _load_tests("rsa_pss_4096_sha512_mgf1_32_test.json")
    vectors += _load_tests("rsa_pss_misc_test.json")
    return vectors


class TestVectorsPSSWycheproof:
    _id = "None"

    def warn(self, tv):
        if tv.warning and wycheproof_warnings():
            import warnings

            warnings.warn("Wycheproof warning: %s (%s)" % (self._id, tv.comment))

    def check_verify(self, tv):
        self._id = "Wycheproof RSA PSS Test #%d (%s)" % (tv.id, tv.comment)

        hashed_msg = tv.hash_module.new(tv.msg)
        signer = pss.new(tv.key, mask_func=tv.mgf, salt_bytes=tv.sLen)
        try:
            signer.verify(hashed_msg, tv.sig)
        except ValueError:
            if tv.warning:
                return
            assert not tv.valid
        else:
            assert tv.valid
            self.warn(tv)

    @pytest.mark.parametrize("tv", load_wycheproof_vectors(), ids=wycheproof_id)
    def test(self, tv):
        self.check_verify(tv)
