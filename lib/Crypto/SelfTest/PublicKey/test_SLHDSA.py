# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import copy
import hashlib
import json
import os
import pickle
import random
from binascii import unhexlify

import pytest

from Crypto.PublicKey import SLHDSA, _fips205
from Crypto.PublicKey.SLHDSA import ParamSet, SLHDSAKey
from Crypto.Util._raw_api import c_size_t, create_string_buffer
from Crypto.Util.number import ceil_div

try:
    import pycryptodome_test_vectors  # type: ignore

    test_vectors_available = True
except ImportError:
    test_vectors_available = False


ALL_PARAM_SETS = list(ParamSet)

# The parameter sets of SP 800-230 (draft): key generation and signing take minutes
SP800230_PARAM_SETS = [ps for ps in ALL_PARAM_SETS if ps.value.endswith("-24")]

# The parameter sets of FIPS 205
PARAM_SETS = [ps for ps in ALL_PARAM_SETS if ps not in SP800230_PARAM_SETS]

# The "f" parameter sets sign quickly, the "s" ones take up to a few seconds
FAST_PARAM_SETS = [ps for ps in PARAM_SETS if ps.value.endswith("f")]
SLOW_PARAM_SETS = [ps for ps in PARAM_SETS if ps.value.endswith("s")]


def all_param_sets():
    """All the parameter sets, with the slow ones marked as such (for signing)"""
    return FAST_PARAM_SETS + [pytest.param(ps, marks=pytest.mark.slow) for ps in SLOW_PARAM_SETS]


# The C implementations available on this machine, besides the portable one
ACCELERATED_LIBS = [
    pytest.param(lib, id=name)
    for lib, name in (
        (_fips205._raw_slhdsa_shani_lib, "shani"),
        (_fips205._raw_slhdsa_armv8_lib, "armv8"),
        (_fips205._raw_slhdsa_avx2_bmi2_lib, "avx2_bmi2"),
    )
    if lib is not None
]

# Run every test with the portable C implementation, and with the ones used
# by default on this machine for SHA2 and SHAKE (if they are not the portable one)
_implementations = [
    pytest.param((_fips205._raw_slhdsa_portable_lib, _fips205._raw_slhdsa_portable_lib), id="portable")
]
if ACCELERATED_LIBS:
    _implementations.append(
        pytest.param((_fips205._raw_slhdsa_sha2_lib, _fips205._raw_slhdsa_shake_lib), id="accelerated")
    )


def use_implementation(monkeypatch, sha2_lib, shake_lib):
    monkeypatch.setattr(_fips205, "_raw_slhdsa_sha2_lib", sha2_lib)
    monkeypatch.setattr(_fips205, "_raw_slhdsa_shake_lib", shake_lib)


@pytest.fixture(autouse=True, params=_implementations)
def slhdsa_implementation(request, monkeypatch):
    use_implementation(monkeypatch, *request.param)


# Sizes of the public key, of the private key and of the signature
# (FIPS 205, Table 2, and SP 800-230, Table 1)
SIZES = {
    ParamSet.SLH_DSA_SHA2_128s: (32, 64, 7856),
    ParamSet.SLH_DSA_SHAKE_128s: (32, 64, 7856),
    ParamSet.SLH_DSA_SHA2_128f: (32, 64, 17088),
    ParamSet.SLH_DSA_SHAKE_128f: (32, 64, 17088),
    ParamSet.SLH_DSA_SHA2_192s: (48, 96, 16224),
    ParamSet.SLH_DSA_SHAKE_192s: (48, 96, 16224),
    ParamSet.SLH_DSA_SHA2_192f: (48, 96, 35664),
    ParamSet.SLH_DSA_SHAKE_192f: (48, 96, 35664),
    ParamSet.SLH_DSA_SHA2_256s: (64, 128, 29792),
    ParamSet.SLH_DSA_SHAKE_256s: (64, 128, 29792),
    ParamSet.SLH_DSA_SHA2_256f: (64, 128, 49856),
    ParamSet.SLH_DSA_SHAKE_256f: (64, 128, 49856),
    ParamSet.SLH_DSA_SHA2_128_24: (32, 64, 3856),
    ParamSet.SLH_DSA_SHAKE_128_24: (32, 64, 3856),
    ParamSet.SLH_DSA_SHA2_192_24: (48, 96, 7752),
    ParamSet.SLH_DSA_SHAKE_192_24: (48, 96, 7752),
    ParamSet.SLH_DSA_SHA2_256_24: (64, 128, 14944),
    ParamSet.SLH_DSA_SHAKE_256_24: (64, 128, 14944),
}


def toy_params(sha2, n, lg_w, hp, d, a, k):
    """A small parameter set, to test w = 4 and w = 8 (as in SP 800-230) quickly"""
    h = hp * d
    m = ceil_div(k * a, 8) + ceil_div(h - hp, 8) + ceil_div(hp, 8)
    return _fips205.Params(sha2, n, h, d, hp, a, k, lg_w, m)


# Toy parameter sets (sha2, n, lg_w, h', d, a, k), with PK.root and the SHA-256 of
# the signature of b"toy message", for the seeds 0x01..., 0x02..., 0x03... and
# addrnd 0x04... (all n bytes long). They were checked against the Python
# implementation of FIPS 205 in https://github.com/slh-dsa/slhdsa-c (test/fips205.py,
# commit 2b111e076a3bf0b6041651cf8746acf5ade56cc7).
TOY_KATS = [
    (
        (True, 16, 2, 4, 1, 5, 3),
        "c91d7693fd4a55f4b0247b06dfec6ee5",
        "ddf08894a33e9a6721a90d52075222fa6d9be248dc93a61c8b2d3ae10fc03248",
    ),
    (
        (False, 16, 2, 4, 1, 5, 3),
        "eae079630248f898d57e2ba883e5955a",
        "2d583b289dfcc76de99e9a8e6488a4d66e0965eaae54d1cee0441a0f8ab41089",
    ),
    (
        (True, 24, 3, 3, 2, 4, 5),
        "f26d4f38c79727c75609593dc824f9007965b8d18e896d22",
        "ada32e1d4d04b9f4bd04ccc62b6eba9cfcf818f043ea96ba5df62a91b45f1285",
    ),
    (
        (False, 24, 3, 3, 2, 4, 5),
        "8bca47da56bbbbcf0f556679f167a97d27b486807db18a4d",
        "f62e1a681e5c1723bb23b922d92b5a78601314ad7913266f07fa03755cac9c48",
    ),
    (
        (True, 32, 2, 2, 3, 3, 4),
        "983307f619e08a2e0f2d0765739595fd9ebcdfa0a7627ad3cd2384baead1412a",
        "0d8a264744fefd12f109f03d914623753d50f5c1a7bf1f6db9bfcd7afd208d18",
    ),
    (
        (False, 32, 2, 2, 3, 3, 4),
        "7975d44d500b3282f0c5836ba3a1e104faa06644bb9e0110c411af579128a470",
        "333ef92f50fac7291afd9422111167e4b8a84dd0fec5ea09b57169e859cee7f1",
    ),
]


def pure_prefix(context=b""):
    """The prefix of M' for pure SLH-DSA (FIPS 205, Algorithm 22)"""
    return b"\x00" + bytes([len(context)]) + context


class TestParams:
    @pytest.mark.parametrize("param_set", ALL_PARAM_SETS)
    def test_sizes(self, param_set):
        params = SLHDSA._params[param_set]
        assert (params.pk_len, params.sk_len, params.sig_len) == SIZES[param_set]

        # Table 2 and Section 4.1
        assert params.h == params.d * params.hp
        assert params.sha2 == ("SHA2" in param_set.value)
        if param_set in SP800230_PARAM_SETS:
            assert params.d == 1
            assert params.lg_w == (3 if params.n == 24 else 2)
        else:
            assert params.lg_w == 4
            assert params.len == 2 * params.n + 3
        md_len = ceil_div(params.k * params.a, 8)
        tree_len = ceil_div(params.h - params.hp, 8)
        leaf_len = ceil_div(params.hp, 8)
        assert params.m == md_len + tree_len + leaf_len

    def test_len(self):
        # Equations 5.1 to 5.4
        for n, lg_w, len1, len2 in (
            (16, 4, 32, 3),
            (24, 4, 48, 3),
            (32, 4, 64, 3),
            (16, 2, 64, 4),
            (24, 3, 64, 3),
            (32, 2, 128, 5),
        ):
            assert _fips205.gen_len2(n, lg_w) == len2
            params = toy_params(True, n, lg_w, 3, 1, 4, 5)
            assert (params.len1, params.len2, params.len) == (len1, len2, len1 + len2)

    def test_base_2b(self):
        assert _fips205.base_2b(b"\x12\x34", 4, 4) == [1, 2, 3, 4]
        assert _fips205.base_2b(b"\x12\x34", 4, 3) == [1, 2, 3]
        assert _fips205.base_2b(b"\xff\x00\xff", 12, 2) == [0xFF0, 0x0FF]
        assert _fips205.base_2b(b"\x80\x00\x01", 6, 4) == [32, 0, 0, 1]
        assert _fips205.base_2b(b"\xab", 8, 1) == [0xAB]
        # The bytes after the first ceil(b * out_len / 8) are ignored
        assert _fips205.base_2b(b"\x12\x34\x56", 4, 3) == [1, 2, 3]
        with pytest.raises(ValueError):
            _fips205.base_2b(b"\x12", 4, 3)

    def test_adrs(self):
        adrs = _fips205.ADRS()
        adrs.set_layer_address(0x01020304)
        adrs.set_tree_address(0x05060708090A0B0C0D0E0F10)
        adrs.set_type_and_clear(_fips205.ADRS.FORS_TREE)
        adrs.set_key_pair_address(0x15161718)
        adrs.set_tree_height(0x191A1B1C)
        adrs.set_tree_index(0x1D1E1F20)
        assert bytes(adrs) == bytes(range(1, 17)) + b"\x00\x00\x00\x03" + bytes(range(0x15, 0x21))
        assert adrs.get_key_pair_address() == 0x15161718
        assert adrs.get_tree_index() == 0x1D1E1F20

        clone = adrs.copy()
        adrs.set_type_and_clear(_fips205.ADRS.WOTS_HASH)
        assert bytes(adrs) == bytes(range(1, 17)) + bytes(16)
        assert bytes(clone)[16:20] == b"\x00\x00\x00\x03"


class TestC:
    """The checks on the arguments in src/slhdsa.c"""

    def _call(self, name, family=1, n=16, lg_w=4, *args):
        out = create_string_buffer(32)
        lib = _fips205._raw_slhdsa_sha2_lib if family == 1 else _fips205._raw_slhdsa_shake_lib
        return getattr(lib, name)(family, c_size_t(n), lg_w, out, *args)

    def test_thash(self):
        seed = b"\x00" * 32
        adrs = b"\x00" * 32
        m = b"\x00" * (133 * 32 + 1)
        assert self._call("slhdsa_thash", 1, 16, 4, seed, adrs, seed, c_size_t(16)) == 0
        assert self._call("slhdsa_thash", 0, 32, 2, seed, adrs, seed, c_size_t(32)) == 0
        # T_len with the largest len (n = 32 and lg_w = 2)
        assert self._call("slhdsa_thash", 1, 32, 2, seed, adrs, m, c_size_t(133 * 32)) == 0
        # Wrong family, n, lg_w, or length of M
        assert self._call("slhdsa_thash", 2, 16, 4, seed, adrs, seed, c_size_t(16)) != 0
        assert self._call("slhdsa_thash", 1, 20, 4, seed, adrs, seed, c_size_t(20)) != 0
        assert self._call("slhdsa_thash", 1, 16, 1, seed, adrs, seed, c_size_t(16)) != 0
        assert self._call("slhdsa_thash", 1, 16, 5, seed, adrs, seed, c_size_t(16)) != 0
        assert self._call("slhdsa_thash", 1, 16, 4, seed, adrs, seed, c_size_t(0)) != 0
        assert self._call("slhdsa_thash", 1, 16, 4, seed, adrs, seed, c_size_t(17)) != 0
        assert self._call("slhdsa_thash", 1, 32, 2, seed, adrs, m, c_size_t(134 * 32)) != 0

    def test_chain(self):
        seed = b"\x00" * 32
        adrs = b"\x00" * 32
        # i + s at most w - 1
        for lg_w in (2, 3, 4):
            w = 1 << lg_w
            assert self._call("slhdsa_chain", 0, 16, lg_w, seed, adrs, seed, 0, w - 1) == 0
            assert self._call("slhdsa_chain", 0, 16, lg_w, seed, adrs, seed, w - 1, 0) == 0
            assert self._call("slhdsa_chain", 0, 16, lg_w, seed, adrs, seed, 1, w - 1) != 0
            assert self._call("slhdsa_chain", 0, 16, lg_w, seed, adrs, seed, w, 0) != 0
        assert self._call("slhdsa_chain", 0, 16, 5, seed, adrs, seed, 0, 1) != 0

    def test_nodes(self):
        seed = b"\x00" * 32
        adrs = b"\x00" * 32
        for name in ("slhdsa_xmss_node", "slhdsa_fors_node"):
            assert self._call(name, 1, 16, 4, seed, seed, adrs, 1, 2) == 0
            assert self._call(name, 1, 16, 2, seed, seed, adrs, 1, 2) == 0
            assert self._call(name, 1, 16, 1, seed, seed, adrs, 1, 2) != 0
        # Too high (h' is at most 22, a at most 25)
        assert self._call("slhdsa_xmss_node", 1, 16, 4, seed, seed, adrs, 0, 23) != 0
        assert self._call("slhdsa_fors_node", 1, 16, 4, seed, seed, adrs, 0, 26) != 0
        # Leaves out of range (k * 2^a is less than 2^29)
        assert self._call("slhdsa_xmss_node", 1, 16, 4, seed, seed, adrs, 1 << 22, 0) != 0
        assert self._call("slhdsa_xmss_node", 1, 16, 4, seed, seed, adrs, 1 << 12, 10) != 0
        assert self._call("slhdsa_fors_node", 1, 16, 4, seed, seed, adrs, 1 << 29, 0) != 0
        assert self._call("slhdsa_fors_node", 1, 16, 4, seed, seed, adrs, 1 << 19, 10) != 0
        assert self._call("slhdsa_fors_node", 1, 16, 4, seed, seed, adrs, (1 << 29) - 1, 0) == 0

    def test_python_checks(self):
        # The lengths that the C code relies on are checked in Python
        params = SLHDSA._params[ParamSet.SLH_DSA_SHA2_128f]
        n = params.n
        for bad in (b"\x01" * (n - 1), b"\x01" * (n + 1)):
            with pytest.raises(ValueError):
                _fips205.Context(params, bad)
            with pytest.raises(ValueError):
                _fips205.Context(params, b"\x01" * n, bad)
        ctx = _fips205.Context(params, b"\x01" * n, b"\x02" * n)
        adrs = _fips205.ADRS()
        assert len(ctx.chain(b"\x03" * n, 0, 1, adrs)) == n
        for bad in (b"\x03" * (n - 1), b"\x03" * (n + 1)):
            with pytest.raises(ValueError):
                ctx.chain(bad, 0, 1, adrs)
        # T_l: the C code checks that the length of M is a multiple of n
        assert len(ctx.T(adrs, b"\x03" * (3 * n))) == n
        with pytest.raises(ValueError):
            ctx.T(adrs, b"\x03" * (3 * n + 1))


class TestSLHDSAKey:
    @pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle(self, protocol):
        key = SLHDSA.generate(param_set=SLHDSA.SLH_DSA_SHA2_128f)
        key_sk = SLHDSA.construct(param_set=SLHDSA.SLH_DSA_SHA2_128f, sk=key.sk)

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
        assert pub_key2.param_set is SLHDSA.SLH_DSA_SHA2_128f
        assert pub_key2._verify((b"msg",), key._sign((b"msg",), None))

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_generate(self, param_set):
        key = SLHDSA.generate(param_set=param_set)
        pk_len, sk_len, _ = SIZES[param_set]

        assert isinstance(key, SLHDSAKey)
        assert key.param_set == param_set
        assert key.has_private()
        assert len(key.sk) == sk_len
        assert len(key.pk) == pk_len
        # PK.seed and PK.root are also in the private key
        assert key.sk[sk_len // 2 :] == key.pk

        key2 = SLHDSA.generate(param_set=param_set)
        assert key2.sk != key.sk
        assert key2.pk != key.pk

    def test_generate_randfunc(self):
        seeds = []

        def randfunc(n):
            seeds.append(bytes([len(seeds) + 1]) * n)
            return seeds[-1]

        key = SLHDSA.generate(param_set=ParamSet.SLH_DSA_SHAKE_192f, randfunc=randfunc)
        # SK.seed, SK.prf and PK.seed (FIPS 205, Algorithm 21)
        assert seeds == [b"\x01" * 24, b"\x02" * 24, b"\x03" * 24]
        assert key.sk[:72] == b"".join(seeds)
        assert key.pk[:24] == seeds[2]
        assert key == SLHDSA.construct(param_set=ParamSet.SLH_DSA_SHAKE_192f, sk=key.sk)

        with pytest.raises(ValueError):
            SLHDSA.generate(param_set=ParamSet.SLH_DSA_SHAKE_192f, randfunc=lambda n: b"\x00" * (n - 1))

    def test_param_set_enum(self):
        assert list(SLHDSA._params) == list(ParamSet)
        assert len(ParamSet) == 18
        assert ParamSet("SLH-DSA-SHAKE-256f") is ParamSet.SLH_DSA_SHAKE_256f
        assert ParamSet("SLH-DSA-SHA2-192-24") is ParamSet.SLH_DSA_SHA2_192_24

        # The members are also at the module level
        for ps in ParamSet:
            assert getattr(SLHDSA, ps.name) is ps
        key = SLHDSA.generate(param_set=SLHDSA.SLH_DSA_SHA2_128f)
        assert key.param_set is ParamSet.SLH_DSA_SHA2_128f

        # Only members of the enum
        for bad in ("SLH-DSA-SHA2-128f", "slhdsa128f", 128, None):
            with pytest.raises(TypeError):
                SLHDSA.generate(param_set=bad)
            with pytest.raises(TypeError):
                SLHDSA.construct(param_set=bad, pk=key.pk)
            with pytest.raises(TypeError):
                SLHDSAKey(param_set=bad, pk=key.pk)

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_construct(self, param_set):
        key = SLHDSA.generate(param_set=param_set)

        key_sk = SLHDSA.construct(param_set=param_set, sk=key.sk)
        assert key_sk.has_private()
        assert key_sk.sk == key.sk
        assert key_sk.pk == key.pk
        assert key_sk == key

        key_pk = SLHDSA.construct(param_set=param_set, pk=key.pk)
        assert not key_pk.has_private()
        assert key_pk.pk == key.pk
        assert key_pk == key.public_key()
        assert key_pk != key
        with pytest.raises(ValueError):
            _ = key_pk.sk

        # Other types of buffers
        for conv in (bytearray, memoryview):
            assert SLHDSA.construct(param_set=param_set, pk=conv(key.pk)) == key.public_key()

    def test_construct_buffers(self):
        key = SLHDSA.generate(param_set=ParamSet.SLH_DSA_SHA2_128f)
        assert SLHDSA.construct(param_set=key.param_set, sk=key.sk, pk=key.pk) == key
        for conv in (bytearray, memoryview):
            assert SLHDSA.construct(param_set=key.param_set, sk=conv(key.sk)) == key
            assert SLHDSA.construct(param_set=key.param_set, sk=conv(key.sk), pk=conv(key.pk)) == key

    def test_construct_errors(self):
        ps = ParamSet.SLH_DSA_SHA2_128f
        key = SLHDSA.generate(param_set=ps)
        other = SLHDSA.generate(param_set=ps)

        with pytest.raises(ValueError):
            SLHDSA.construct(param_set=ps)

        # Wrong lengths
        with pytest.raises(ValueError):
            SLHDSA.construct(param_set=ps, sk=key.sk[:-1])
        with pytest.raises(ValueError):
            SLHDSA.construct(param_set=ps, sk=key.sk + b"\x00")
        with pytest.raises(ValueError):
            SLHDSA.construct(param_set=ps, pk=key.pk[:-1])
        with pytest.raises(ValueError):
            SLHDSA.construct(param_set=ps, pk=key.pk + b"\x00")
        with pytest.raises(ValueError):
            SLHDSA.construct(param_set=ParamSet.SLH_DSA_SHA2_192f, sk=key.sk)
        with pytest.raises(ValueError):
            SLHDSA.construct(param_set=ParamSet.SLH_DSA_SHA2_192f, pk=key.pk)

        # Mismatch
        with pytest.raises(ValueError, match="do not match"):
            SLHDSA.construct(param_set=ps, sk=key.sk, pk=other.pk)

        # PK.root does not match SK.seed and PK.seed (in any part of the private key)
        for pos in (0, 16, 32, 48, 63):
            sk = bytearray(key.sk)
            sk[pos] ^= 0x01
            if pos == 16:
                # SK.prf is not used for PK.root: the key is valid
                assert SLHDSA.construct(param_set=ps, sk=sk).pk == key.pk
                continue
            with pytest.raises(ValueError, match="PK\\.root"):
                SLHDSA.construct(param_set=ps, sk=sk)

        # The same seeds with another hash family
        with pytest.raises(ValueError, match="PK\\.root"):
            SLHDSA.construct(param_set=ParamSet.SLH_DSA_SHAKE_128f, sk=key.sk)

    def test_eq_repr(self):
        key = SLHDSA.generate(param_set=ParamSet.SLH_DSA_SHA2_128f)
        assert key == SLHDSA.construct(param_set=ParamSet.SLH_DSA_SHA2_128f, sk=key.sk)
        assert key != SLHDSA.generate(param_set=ParamSet.SLH_DSA_SHA2_128f)
        assert key != key.sk
        assert key.public_key() == key.public_key()
        # The same public key, with another parameter set (same n)
        assert key.public_key() != SLHDSA.construct(param_set=ParamSet.SLH_DSA_SHAKE_128s, pk=key.pk)

        assert repr(key) == "SLHDSAKey(param_set=ParamSet.SLH_DSA_SHA2_128f, private=True)"
        assert repr(key.public_key()) == "SLHDSAKey(param_set=ParamSet.SLH_DSA_SHA2_128f, private=False)"
        assert key.sk.hex() not in repr(key)

    @pytest.mark.parametrize("param_set", all_param_sets())
    def test_sign_verify(self, param_set):
        key = SLHDSA.generate(param_set=param_set)
        pub_key = key.public_key()
        n = len(key.pk) // 2
        sig_len = SIZES[param_set][2]
        params = SLHDSA._params[param_set]

        msg = b"Test message"
        prefix = pure_prefix(b"context")
        sig = key._sign((prefix, msg), None)
        assert len(sig) == sig_len
        assert pub_key._verify((prefix, msg), sig)
        assert key._verify((prefix, msg), sig)

        # Randomized
        sig2 = key._sign((prefix, msg), b"\x01" * n)
        assert sig2 != sig
        assert pub_key._verify((prefix, msg), sig2)

        # Wrong message or prefix
        assert not pub_key._verify((prefix, msg + b"\x00"), sig)
        assert not pub_key._verify((pure_prefix(b"contexT"), msg), sig)
        assert not pub_key._verify((msg,), sig)

        # Wrong signature: R, the FORS signature, each layer of the hypertree
        fors_len = params.k * (1 + params.a) * n
        xmss_len = (params.len + params.hp) * n
        positions = [0, n, n + fors_len - 1]
        positions += [n + fors_len + j * xmss_len for j in range(params.d)]
        positions += [sig_len - 1]
        for pos in positions:
            sig_bad = bytearray(sig)
            sig_bad[pos] ^= 0x01
            assert not pub_key._verify((prefix, msg), sig_bad), pos
        assert not pub_key._verify((prefix, msg), sig[:-1])
        assert not pub_key._verify((prefix, msg), sig + b"\x00")
        assert not pub_key._verify((prefix, msg), b"")

        # Wrong key
        other = SLHDSA.generate(param_set=param_set)
        assert not other._verify((prefix, msg), sig)

    @pytest.mark.parametrize("param_set", [ParamSet.SLH_DSA_SHA2_128f, ParamSet.SLH_DSA_SHAKE_128f])
    def test_sign_message(self, param_set):
        key = SLHDSA.generate(param_set=param_set)
        pub_key = key.public_key()
        n = len(key.pk) // 2

        msg = b"Test message"
        prefix = pure_prefix(b"context")
        sig = key._sign((prefix, msg), None)

        # Deterministic: opt_rand is PK.seed
        assert key._sign((prefix, msg), None) == sig
        assert key._sign((prefix, msg), key.pk[:n]) == sig

        # M is the concatenation of prefix and message
        assert key._sign((prefix + msg,), None) == sig
        assert key._sign((prefix + msg[:3], msg[3:]), None) == sig
        assert pub_key._verify((prefix + msg,), sig)

        # Empty message, other types of buffers
        sig = key._sign((b"",), None)
        assert pub_key._verify((b"",), sig)
        assert pub_key._verify((bytearray(),), bytearray(sig))
        assert pub_key._verify((memoryview(b""),), memoryview(sig))
        assert key._sign((memoryview(b""),), None) == sig
        assert key._sign((bytearray(),), None) == sig

    def test_long_message(self):
        key = SLHDSA.generate(param_set=ParamSet.SLH_DSA_SHA2_192f)
        msg = bytes(range(256)) * 4000
        sig = key._sign((pure_prefix(), msg), None)
        assert key._verify((pure_prefix() + msg,), sig)
        assert not key._verify((pure_prefix(), msg[:-1]), sig)

    def test_sign_errors(self):
        key = SLHDSA.generate(param_set=ParamSet.SLH_DSA_SHA2_128f)

        with pytest.raises(TypeError):
            key.public_key()._sign((b"msg",), None)

        with pytest.raises(ValueError):
            key._sign((b"msg",), b"\x00" * 15)
        with pytest.raises(ValueError):
            key._sign((b"msg",), b"\x00" * 17)

        with pytest.raises(TypeError):
            key._sign(("msg",), None)

        # The message must be a tuple of pieces
        for bad_msg in (b"msg", [b"msg"]):
            with pytest.raises(TypeError):
                key._sign(bad_msg, None)
            with pytest.raises(TypeError):
                key.public_key()._verify(bad_msg, key._sign((b"msg",), None))

        # Any number of pieces
        sig = key._sign((b"m", b"", b"s", bytearray(b"g")), None)
        assert sig == key._sign((b"msg",), None)
        assert key._verify((memoryview(b"ms"), b"g"), sig)
        assert key._sign((), None) == key._sign((b"",), None)


class TestThreads:
    """Key generation and signing with several threads give the same result as with one"""

    @pytest.fixture(autouse=True)
    def no_minimum(self, monkeypatch):
        # Use the threads even for the small trees of the "f" parameter sets
        monkeypatch.setattr(_fips205, "_MIN_HASHES_PER_THREAD", 1)

    def test_parallel_map(self):
        for count in (0, 1, 2, 7, 22):
            for threads in (1, 2, 3, 8, 30):
                assert _fips205.parallel_map(lambda i: i * i, count, threads) == [i * i for i in range(count)]

    @pytest.mark.parametrize("param_set", FAST_PARAM_SETS)
    def test_xmss_root(self, param_set):
        params = SLHDSA._params[param_set]
        ctx = _fips205.Context(params, b"\x01" * params.n, b"\x02" * params.n)
        adrs = _fips205.ADRS()
        adrs.set_layer_address(3)
        adrs.set_tree_address(12345)
        expected = ctx.xmss_node(0, params.hp, adrs)
        # Up to 2^h' subtrees (single leaves), and more threads than subtrees
        for threads in range(1, (1 << params.hp) + 3):
            assert _fips205.xmss_node_batch(ctx, [(0, params.hp, adrs)], threads) == [expected]

    def test_tree_node_batch(self):
        params = toy_params(False, 16, 2, 6, 1, 6, 5)
        ctx = _fips205.Context(params, b"\x01" * params.n, b"\x02" * params.n)
        adrs = _fips205.ADRS()
        adrs.set_tree_address(5)
        adrs2 = adrs.copy()
        adrs2.set_layer_address(1)
        fors_adrs = adrs.copy()
        fors_adrs.set_type_and_clear(_fips205.ADRS.FORS_TREE)
        fors_adrs.set_key_pair_address(7)
        before = [bytes(a) for a in (adrs, adrs2, fors_adrs)]
        # Nodes of each height, and of mixed heights
        heights = [[z] for z in range(params.hp + 1)] + [list(range(params.hp + 1)), [0, params.hp, 1, 3]]
        for zs in heights:
            roots = [
                (i, z, a) for z in zs for a, i in ((adrs, 0), (adrs2, 0), (adrs, (1 << (params.hp - z)) - 1))
            ]
            expected = [ctx.xmss_node(i, z, a) for i, z, a in roots]
            # Each node split into subtrees, and more threads than subtrees
            for threads in (1, 2, 3, 4, 13, 64, 300):
                assert _fips205.xmss_node_batch(ctx, roots, threads) == expected
            # FORS nodes, in the last tree
            fors_roots = [
                (i, z, fors_adrs) for z in zs for i in ((4 << (params.a - z)), (5 << (params.a - z)) - 1)
            ]
            expected = [ctx.fors_node(i, z, a) for i, z, a in fors_roots]
            for threads in (1, 3, 8):
                roots4 = [(i, z, a, a.copy()) for i, z, a in fors_roots]
                assert _fips205.tree_node_batch(ctx, ctx.fors_node, 3, roots4, threads) == expected
        assert [bytes(a) for a in (adrs, adrs2, fors_adrs)] == before

    @pytest.mark.parametrize("param_set", FAST_PARAM_SETS)
    def test_same_output(self, param_set):
        key = SLHDSA.generate(param_set=param_set)
        sig = key._sign((b"message",), None)
        for threads in (2, 3, 5, 0):
            assert SLHDSA.construct(param_set=param_set, sk=key.sk, threads=threads) == key
            assert key._sign((b"message",), None, threads=threads) == sig

        seeds = [bytes([i]) * key._params.n for i in range(3)]
        expected = SLHDSA.generate(param_set=param_set, randfunc=lambda n: seeds.pop(0))
        seeds = [bytes([i]) * key._params.n for i in range(3)]
        assert SLHDSA.generate(param_set=param_set, randfunc=lambda n: seeds.pop(0), threads=4) == expected

    @pytest.mark.parametrize(
        "param_set", [pytest.param(ps, marks=pytest.mark.slow) for ps in SLOW_PARAM_SETS]
    )
    def test_same_output_slow(self, param_set, monkeypatch):
        monkeypatch.setattr(_fips205, "_MIN_HASHES_PER_THREAD", 32768)
        key = SLHDSA.generate(param_set=param_set, threads=3)
        assert SLHDSA.construct(param_set=param_set, sk=key.sk) == key
        assert key._sign((b"message",), None, threads=4) == key._sign((b"message",), None)

    def test_threads_param(self):
        ps = ParamSet.SLH_DSA_SHA2_128f
        key = SLHDSA.generate(param_set=ps)
        for bad, exc in (
            (-1, ValueError),
            ("2", TypeError),
            (1.5, TypeError),
            (True, TypeError),
            (None, TypeError),
        ):
            with pytest.raises(exc):
                SLHDSA.generate(param_set=ps, threads=bad)
            with pytest.raises(exc):
                SLHDSA.construct(param_set=ps, sk=key.sk, threads=bad)
            with pytest.raises(exc):
                key._sign((b"message",), None, threads=bad)

    def test_useful_threads(self, monkeypatch):
        monkeypatch.setattr(_fips205, "_MIN_HASHES_PER_THREAD", 1000)
        assert _fips205.useful_threads(8, 100000) == 8
        assert _fips205.useful_threads(8, 2999) == 2
        assert _fips205.useful_threads(8, 999) == 1
        assert _fips205.useful_threads(1, 100000) == 1


class TestToyParams:
    """Small parameter sets with w = 4 and w = 8 (like SP 800-230), and up to 3 layers"""

    @pytest.mark.parametrize("toy,pk_root,sig_sha256", TOY_KATS, ids=[str(kat[0]) for kat in TOY_KATS])
    def test_kat(self, toy, pk_root, sig_sha256, monkeypatch):
        params = toy_params(*toy)
        n = params.n
        sk, pk = _fips205.slh_keygen_internal(params, b"\x01" * n, b"\x02" * n, b"\x03" * n)
        assert pk == b"\x03" * n + unhexlify(pk_root)
        assert sk == b"\x01" * n + b"\x02" * n + pk

        msg = (b"toy ", b"message")
        sig = _fips205.slh_sign_internal(params, msg, sk, b"\x04" * n)
        assert len(sig) == params.sig_len
        assert hashlib.sha256(sig).hexdigest() == sig_sha256
        assert _fips205.slh_verify_internal(params, msg, sig, pk)
        for pos in (0, n, len(sig) - 1):
            sig_bad = bytearray(sig)
            sig_bad[pos] ^= 0x01
            assert not _fips205.slh_verify_internal(params, msg, bytes(sig_bad), pk)

        # The same, with threads
        monkeypatch.setattr(_fips205, "_MIN_HASHES_PER_THREAD", 1)
        assert _fips205.slh_keygen_internal(params, b"\x01" * n, b"\x02" * n, b"\x03" * n, 5) == (sk, pk)
        assert _fips205.slh_sign_internal(params, msg, sk, b"\x04" * n, 7) == sig


def _load_acvp(name):
    """Load the test vectors of the given ACVP file, as a list of pytest parameters.
    Signing with the "s" parameter sets is marked as slow."""

    # The test vectors are loaded when pytest collects the tests:
    # a missing file is only reported when the test runs
    try:
        if not test_vectors_available:
            raise FileNotFoundError
        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        with open(os.path.join(init_dir, "PublicKey", "SLHDSA", name)) as file_in:
            tv_tree = json.load(file_in)
    except FileNotFoundError:
        return [pytest.param(None, None, id="missing", marks=pytest.mark.skip(reason="Missing " + name))]

    result = []
    for group in tv_tree["testGroups"]:
        slow = "sigGen" in name and group["parameterSet"].endswith("s")
        marks = [pytest.mark.slow] if slow else []
        for test in group["tests"]:
            result.append(pytest.param(group, test, id="tcId%d" % test["tcId"], marks=marks))
    return result


def _acvp_message(group, test):
    """The message and the prefix for _sign() and _verify()"""

    msg = unhexlify(test["message"])
    if group["signatureInterface"] == "internal":
        return msg, b""
    assert group["preHash"] == "pure"
    return msg, pure_prefix(unhexlify(test["context"]))


class TestACVP:
    """A subset of the NIST ACVP test vectors (internal projection)"""

    @pytest.mark.parametrize("group,test", _load_acvp("SLH-DSA-keyGen-FIPS205.json"))
    def test_keygen(self, group, test):
        param_set = ParamSet(group["parameterSet"])
        key = SLHDSAKey._from_seeds(
            param_set, unhexlify(test["skSeed"]), unhexlify(test["skPrf"]), unhexlify(test["pkSeed"])
        )
        assert key.pk == unhexlify(test["pk"])
        assert key.sk == unhexlify(test["sk"])
        assert SLHDSA.construct(param_set=param_set, sk=unhexlify(test["sk"])) == key

    @pytest.mark.parametrize("group,test", _load_acvp("SLH-DSA-sigGen-FIPS205.json"))
    def test_siggen(self, group, test):
        key = SLHDSA.construct(param_set=ParamSet(group["parameterSet"]), sk=unhexlify(test["sk"]))
        assert key.pk == unhexlify(test["pk"])

        msg, prefix = _acvp_message(group, test)
        addrnd = None if group["deterministic"] else unhexlify(test["additionalRandomness"])
        sig = key._sign((prefix, msg), addrnd)
        assert sig == unhexlify(test["signature"])
        assert key._verify((prefix, msg), sig)

    @pytest.mark.parametrize("group,test", _load_acvp("SLH-DSA-sigVer-FIPS205.json"))
    def test_sigver(self, group, test):
        key = SLHDSA.construct(param_set=ParamSet(group["parameterSet"]), pk=unhexlify(test["pk"]))

        msg, prefix = _acvp_message(group, test)
        signature = unhexlify(test["signature"])
        result = key._verify((prefix, msg), signature)
        assert result == test["testPassed"], test["reason"]


def _load_sp800230():
    """Load the test vectors for the parameter sets of SP 800-230, as a list of pytest parameters"""

    name = "SLH-DSA-SP800-230-ipd.json"
    try:
        if not test_vectors_available:
            raise FileNotFoundError
        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        with open(os.path.join(init_dir, "PublicKey", "SLHDSA", name)) as file_in:
            tests = json.load(file_in)
    except FileNotFoundError:
        return [pytest.param(None, id="missing", marks=pytest.mark.skip(reason="Missing " + name))]
    return [pytest.param(test, id=test["parameterSet"]) for test in tests]


class TestSP800230:
    """The parameter sets of the draft SP 800-230: verifying is fast, but generating
    a key and signing take minutes (about a billion hashes each)"""

    @pytest.mark.parametrize("test", _load_sp800230())
    def test_verify(self, test):
        param_set = ParamSet(test["parameterSet"])
        assert param_set in SP800230_PARAM_SETS
        key = SLHDSA.construct(param_set=param_set, pk=unhexlify(test["pk"]))
        msg = unhexlify(test["message"])
        prefix = pure_prefix(unhexlify(test["context"]))
        sig = unhexlify(test["signature"])
        assert len(sig) == SIZES[param_set][2]
        assert key._verify((prefix, msg), sig)

        assert not key._verify((prefix, msg + b"\x00"), sig)
        assert not key._verify((pure_prefix(b"other context"), msg), sig)
        n = key._params.n
        for pos in (0, n, n + 100, len(sig) - 1):
            sig_bad = bytearray(sig)
            sig_bad[pos] ^= 0x01
            assert not key._verify((prefix, msg), sig_bad), pos

    # About 27 minutes for all the parameter sets and both implementations
    @pytest.mark.very_slow
    @pytest.mark.parametrize("test", _load_sp800230())
    def test_keygen_sign(self, test):
        param_set = ParamSet(test["parameterSet"])
        key = SLHDSAKey._from_seeds(
            param_set,
            unhexlify(test["skSeed"]),
            unhexlify(test["skPrf"]),
            unhexlify(test["pkSeed"]),
            threads=0,
        )
        assert key.pk == unhexlify(test["pk"])
        assert key.sk == unhexlify(test["sk"])

        msg = unhexlify(test["message"])
        prefix = pure_prefix(unhexlify(test["context"]))
        addrnd = None if test["deterministic"] else unhexlify(test["additionalRandomness"])
        assert key._sign((prefix, msg), addrnd, threads=0) == unhexlify(test["signature"])


class TestImplementations:
    """The test vectors exercise the implementations one at a time.
    Check that each one (SHA-NI, AVX2 and BMI2) returns the same output
    as the portable one on random inputs, for both hash families."""

    def _run(self, seed):
        rng = random.Random(seed)

        def rand(n):
            return bytes(rng.getrandbits(8) for _ in range(n))

        out = []
        for param_set in FAST_PARAM_SETS:
            n = SLHDSA._params[param_set].n
            key = SLHDSAKey._from_seeds(param_set, rand(n), rand(n), rand(n))
            msg = rand(rng.choice([0, 1, 55, 56, 64, 1000]))
            out += [key.pk, key._sign((msg,), rand(n))]
        # len is 68, 67 or 133: not always a multiple of 4 (for AVX2)
        for toy, _, _ in TOY_KATS:
            params = toy_params(*toy)
            n = params.n
            sk, pk = _fips205.slh_keygen_internal(params, rand(n), rand(n), rand(n))
            out += [pk, _fips205.slh_sign_internal(params, (rand(100),), sk, rand(n))]
        return out

    @pytest.mark.parametrize("lib", ACCELERATED_LIBS or [pytest.param(None, marks=pytest.mark.skip)])
    def test_same_output(self, lib, monkeypatch):
        portable = _fips205._raw_slhdsa_portable_lib
        use_implementation(monkeypatch, portable, portable)
        expected = self._run(1)
        use_implementation(monkeypatch, lib, lib)
        assert self._run(1) == expected
