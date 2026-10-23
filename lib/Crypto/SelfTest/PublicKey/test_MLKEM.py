# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import copy
import pickle
import random
from binascii import unhexlify

import pytest

from Crypto.PublicKey import MLKEM
from Crypto.PublicKey.MLKEM import MLKEMKey, ParamSet
from Crypto.SelfTest.loader import load_test_vectors_wycheproof, wycheproof_id

PARAM_SETS = list(ParamSet)

# Run every test with each C implementation available on this machine
_implementations = [pytest.param(MLKEM._raw_mlkem_portable_lib, id="portable")]
if MLKEM._raw_mlkem_avx2_bmi2_lib is not None:
    _implementations.append(pytest.param(MLKEM._raw_mlkem_avx2_bmi2_lib, id="avx2_bmi2"))


@pytest.fixture(autouse=True, params=_implementations)
def mlkem_implementation(request, monkeypatch):
    monkeypatch.setattr(MLKEM, "_raw_mlkem_lib", request.param)


# Sizes of the public key, of the expanded private key and of the ciphertext
SIZES = {
    ParamSet.ML_KEM_512: (800, 1632, 768),
    ParamSet.ML_KEM_768: (1184, 2400, 1088),
    ParamSet.ML_KEM_1024: (1568, 3168, 1568),
}


class TestMLKEMKey:
    @pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle(self, protocol):
        key = MLKEM.generate(param_set=MLKEM.ML_KEM_512)
        key_dk = MLKEM.construct(param_set=MLKEM.ML_KEM_512, expanded_dk=key.expanded_dk)

        # Private keys cannot be pickled (nor copied)
        for private_key in (key, key_dk):
            with pytest.raises(pickle.PicklingError):
                pickle.dumps(private_key, protocol)
            with pytest.raises(pickle.PicklingError):
                copy.deepcopy(private_key)

        # Public keys can
        pub_key = key.public_key()
        pub_key2 = pickle.loads(pickle.dumps(pub_key, protocol))
        assert pub_key2 == pub_key
        assert not pub_key2.has_private()
        assert pub_key2.param_set is MLKEM.ML_KEM_512
        ss, ct = pub_key2._encaps()
        assert key._decaps(ct) == ss

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_generate(self, param_set):
        key = MLKEM.generate(param_set=param_set)
        ek_len, dk_len, _ = SIZES[param_set]

        assert isinstance(key, MLKEMKey)
        assert key.param_set == param_set
        assert key.has_private()
        assert len(key.seed) == 64
        assert len(key.expanded_dk) == dk_len
        assert len(key.ek) == ek_len

        key2 = MLKEM.generate(param_set=param_set)
        assert key2.seed != key.seed
        assert key2.ek != key.ek

    def test_generate_randfunc(self):
        seeds = []

        def randfunc(n):
            seeds.append(b"\xaa" * n)
            return seeds[-1]

        key = MLKEM.generate(param_set=ParamSet.ML_KEM_512, randfunc=randfunc)
        assert seeds == [b"\xaa" * 64]
        assert key.seed == seeds[0]
        assert key == MLKEM.construct(param_set=ParamSet.ML_KEM_512, seed=seeds[0])

    def test_param_set_enum(self):
        assert [ps.value for ps in ParamSet] == ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
        assert MLKEM.ML_KEM_512 is ParamSet.ML_KEM_512
        assert MLKEM.ML_KEM_768 is ParamSet.ML_KEM_768
        assert MLKEM.ML_KEM_1024 is ParamSet.ML_KEM_1024
        assert ParamSet("ML-KEM-768") is MLKEM.ML_KEM_768

        for bad in ("ML-KEM-768", 768, None):
            with pytest.raises(TypeError):
                MLKEM.generate(param_set=bad)
            with pytest.raises(TypeError):
                MLKEM.construct(param_set=bad, seed=bytes(64))

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_construct(self, param_set):
        key = MLKEM.generate(param_set=param_set)

        # From the seed
        key2 = MLKEM.construct(param_set=param_set, seed=key.seed)
        assert key2 == key
        assert key2.expanded_dk == key.expanded_dk
        assert key2.seed == key.seed

        # From the expanded private key: no seed
        key3 = MLKEM.construct(param_set=param_set, expanded_dk=key.expanded_dk)
        assert key3 == key
        assert key3.ek == key.ek
        with pytest.raises(ValueError):
            _ = key3.seed

        # Buffers other than bytes
        assert MLKEM.construct(param_set=param_set, seed=bytearray(key.seed)) == key
        assert MLKEM.construct(param_set=param_set, expanded_dk=memoryview(key.expanded_dk)) == key

        # All together
        key4 = MLKEM.construct(param_set=param_set, seed=key.seed, expanded_dk=key.expanded_dk, ek=key.ek)
        assert key4 == key

        # Public key
        pub = MLKEM.construct(param_set=param_set, ek=key.ek)
        assert pub == key.public_key()
        assert not pub.has_private()
        assert pub != key
        with pytest.raises(ValueError):
            _ = pub.expanded_dk
        with pytest.raises(ValueError):
            _ = pub.seed

    def test_construct_errors(self):
        ps = ParamSet.ML_KEM_768
        _, dk_len, _ = SIZES[ps]
        key = MLKEM.generate(param_set=ps)
        other = MLKEM.generate(param_set=ps)

        with pytest.raises(ValueError):
            MLKEM.construct(param_set=ps)

        # Wrong lengths
        for bad_seed in (bytes(63), bytes(65), bytes(32)):
            with pytest.raises(ValueError):
                MLKEM.construct(param_set=ps, seed=bad_seed)
        for bad_dk in (key.expanded_dk[:-1], key.expanded_dk + b"\x00"):
            with pytest.raises(ValueError):
                MLKEM.construct(param_set=ps, expanded_dk=bad_dk)
        for bad_ek in (key.ek[:-1], key.ek + b"\x00"):
            with pytest.raises(ValueError):
                MLKEM.construct(param_set=ps, ek=bad_ek)

        # Of another parameter set
        with pytest.raises(ValueError):
            MLKEM.construct(param_set=ParamSet.ML_KEM_1024, ek=key.ek)

        # Mismatching components
        with pytest.raises(ValueError):
            MLKEM.construct(param_set=ps, seed=key.seed, expanded_dk=other.expanded_dk)
        with pytest.raises(ValueError):
            MLKEM.construct(param_set=ps, seed=key.seed, ek=other.ek)
        with pytest.raises(ValueError):
            MLKEM.construct(param_set=ps, expanded_dk=key.expanded_dk, ek=other.ek)

        # The public key fails the modulus check (a coefficient equal to q = 3329)
        bad_ek = bytearray(key.ek)
        bad_ek[0] = 0x01
        bad_ek[1] = (bad_ek[1] & 0xF0) | 0x0D
        with pytest.raises(ValueError):
            MLKEM.construct(param_set=ps, ek=bad_ek)

        # The expanded private key fails the hash check
        for offset in (384 * 3, dk_len - 64):
            bad_dk = bytearray(key.expanded_dk)
            bad_dk[offset] ^= 1
            with pytest.raises(ValueError):
                MLKEM.construct(param_set=ps, expanded_dk=bad_dk)

        # The secret vector (dk_PKE) is corrupted: the hash check passes,
        # but not the pairwise consistency check
        for offset in (0, 384 * 3 - 1):
            bad_dk = bytearray(key.expanded_dk)
            bad_dk[offset] ^= 1
            with pytest.raises(ValueError, match="pairwise"):
                MLKEM.construct(param_set=ps, expanded_dk=bad_dk)
            # With the seed, the expanded key is compared with the one derived from it
            with pytest.raises(ValueError, match="do not match"):
                MLKEM.construct(param_set=ps, seed=key.seed, expanded_dk=bad_dk)

    def test_eq_repr(self):
        key = MLKEM.generate(param_set=ParamSet.ML_KEM_512)
        other = MLKEM.generate(param_set=ParamSet.ML_KEM_512)

        assert key == MLKEM.construct(param_set=ParamSet.ML_KEM_512, seed=key.seed)
        assert key != other
        assert key != key.public_key()
        assert key.public_key() == key.public_key()
        assert key != key.ek
        assert repr(key) == "MLKEMKey(param_set=ParamSet.ML_KEM_512, private=True)"
        assert repr(key.public_key()) == "MLKEMKey(param_set=ParamSet.ML_KEM_512, private=False)"

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_encaps_decaps(self, param_set):
        _, _, ct_len = SIZES[param_set]
        key = MLKEM.generate(param_set=param_set)

        ss, ct = key.public_key()._encaps()
        assert len(ss) == 32
        assert len(ct) == ct_len
        assert key._decaps(ct) == ss
        # Also from the expanded private key
        assert MLKEM.construct(param_set=param_set, expanded_dk=key.expanded_dk)._decaps(ct) == ss

        # The randomness is new each time
        ss2, ct2 = key.public_key()._encaps()
        assert ss2 != ss
        assert ct2 != ct

        # Deterministic, with the given randomness m
        assert key._encaps(b"\x11" * 32) == key._encaps(b"\x11" * 32)

        # Implicit rejection: a modified ciphertext gives another (pseudorandom) secret
        bad_ct = bytearray(ct)
        bad_ct[0] ^= 1
        ss_bad = key._decaps(bytes(bad_ct))
        assert len(ss_bad) == 32
        assert ss_bad != ss
        assert key._decaps(bytes(bad_ct)) == ss_bad

    def test_encaps_decaps_errors(self):
        key = MLKEM.generate(param_set=ParamSet.ML_KEM_512)
        _, ct = key._encaps()

        for bad in (bytes(31), bytes(33)):
            with pytest.raises(ValueError):
                key._encaps(bad)
        for bad_ct in (ct[:-1], ct + b"\x00"):
            with pytest.raises(ValueError):
                key._decaps(bad_ct)
        with pytest.raises(TypeError):
            key.public_key()._decaps(ct)


def _load_wycheproof(filename, key_name):
    def param_set(group):
        return ParamSet(group["parameterSet"])

    def optional_hex(name):
        def convert(test):
            return unhexlify(test[name]) if name in test else None

        return convert

    return load_test_vectors_wycheproof(
        ("Protocol", "wycheproof"),
        filename,
        "Wycheproof ML-KEM (%s)" % filename,
        group_tag={"param_set": param_set},
        unit_tag={
            "key": optional_hex(key_name),
            "ek": optional_hex("ek"),
            "dk": optional_hex("dk"),
            "m": optional_hex("m"),
            "c": optional_hex("c"),
            "K": optional_hex("K"),
        },
    )


def load_wycheproof(kind, key_name):
    vectors = []
    for level in (512, 768, 1024):
        vectors += _load_wycheproof("mlkem_%d_%stest.json" % (level, kind), key_name)
    return vectors


class TestWycheproof:
    @pytest.mark.parametrize("tv", load_wycheproof("keygen_seed_", "seed"), ids=wycheproof_id)
    def test_keygen(self, tv):
        assert tv.valid
        key = MLKEM.construct(param_set=tv.param_set, seed=tv.key)
        assert key.ek == tv.ek
        assert key.expanded_dk == tv.dk

    @pytest.mark.parametrize("tv", load_wycheproof("", "seed"), ids=wycheproof_id)
    def test_decaps(self, tv):
        try:
            key = MLKEM.construct(param_set=tv.param_set, seed=tv.key)
            assert key.ek == tv.ek
            shared_secret = key._decaps(tv.c)
        except ValueError:
            assert not tv.valid
            return
        assert tv.valid
        assert shared_secret == tv.K

    @pytest.mark.parametrize("tv", load_wycheproof("semi_expanded_decaps_", "dk"), ids=wycheproof_id)
    def test_decaps_expanded(self, tv):
        try:
            key = MLKEM.construct(param_set=tv.param_set, expanded_dk=tv.key)
            shared_secret = key._decaps(tv.c)
        except ValueError:
            assert not tv.valid
            return
        assert tv.valid
        assert key.ek == tv.ek
        assert shared_secret == tv.K

    @pytest.mark.parametrize("tv", load_wycheproof("encaps_", "ek"), ids=wycheproof_id)
    def test_encaps(self, tv):
        try:
            key = MLKEM.construct(param_set=tv.param_set, ek=tv.key)
        except ValueError:
            assert not tv.valid
            return
        assert tv.valid
        shared_secret, ct = key._encaps(tv.m)
        assert ct == tv.c
        assert shared_secret == tv.K


@pytest.mark.skipif(MLKEM._raw_mlkem_avx2_bmi2_lib is None, reason="AVX2 and BMI2 not available")
class TestImplementations:
    """The test vectors exercise the implementations one at a time.
    Check that both (portable C, and AVX2/BMI2) return the same output on random inputs."""

    def _run(self, param_set, seed):
        rng = random.Random(seed)

        def rand(n):
            return bytes(rng.getrandbits(8) for _ in range(n))

        _, _, ct_len = SIZES[param_set]
        out = []
        for _ in range(10):
            key = MLKEM.construct(param_set=param_set, seed=rand(64))
            out += [key.ek, key.expanded_dk]
            ss, ct = key._encaps(rand(32))
            out += [ss, ct, key._decaps(ct), key._decaps(rand(ct_len))]
        return out

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_same_output(self, param_set, monkeypatch):
        results = []
        for lib in (MLKEM._raw_mlkem_portable_lib, MLKEM._raw_mlkem_avx2_bmi2_lib):
            monkeypatch.setattr(MLKEM, "_raw_mlkem_lib", lib)
            results.append(self._run(param_set, param_set.value))
        assert results[0] == results[1]
