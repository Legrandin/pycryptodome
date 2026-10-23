# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import copy
import json
import os
import pickle
from binascii import unhexlify

import pytest

from Crypto.Hash import SHA3_256, SHAKE256
from Crypto.Protocol.DH import import_x25519_private_key
from Crypto.PublicKey import MLKEM, Hybrid
from Crypto.PublicKey.Hybrid import HybridKey, ParamSet
from Crypto.SelfTest.loader import warn_skipped_tests

try:
    import pycryptodome_test_vectors  # type: ignore

    test_vectors_available = True
except ImportError:
    test_vectors_available = False


PARAM_SETS = list(ParamSet)

# ML-KEM parameter set, length of the ECDH point (Nelem),
# and length of the randomness for the encapsulation (Nrandom)
CONFIGS = {
    ParamSet.MLKEM768_X25519: (MLKEM.ML_KEM_768, 32, 32 + 32),
}

# Sizes of the public key and of the ciphertext (draft-irtf-cfrg-concrete-hybrid-kems, Section 4)
SIZES = {
    ParamSet.MLKEM768_X25519: (1216, 1120),
}


class TestHybridKey:
    @pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle(self, protocol):
        key = Hybrid.generate(param_set=Hybrid.MLKEM768_X25519)

        with pytest.raises(pickle.PicklingError):
            pickle.dumps(key, protocol)
        with pytest.raises(pickle.PicklingError):
            copy.deepcopy(key)

        pub_key = key.public_key()
        pub_key2 = pickle.loads(pickle.dumps(pub_key, protocol))
        assert pub_key2 == pub_key
        assert not pub_key2.has_private()
        ss, ct = pub_key2._encaps()
        assert key._decaps(ct) == ss

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_generate(self, param_set):
        key = Hybrid.generate(param_set=param_set)
        pk_len, _ = SIZES[param_set]

        assert isinstance(key, HybridKey)
        assert key.param_set == param_set
        assert key.has_private()
        assert len(key._seed) == 32
        assert len(key._pk) == pk_len

        key2 = Hybrid.generate(param_set=param_set)
        assert key2._seed != key._seed
        assert key2._pk != key._pk

    def test_generate_randfunc(self):
        seeds = []

        def randfunc(n):
            seeds.append(b"\xaa" * n)
            return seeds[-1]

        key = Hybrid.generate(param_set=ParamSet.MLKEM768_X25519, randfunc=randfunc)
        assert seeds == [b"\xaa" * 32]
        assert key._seed == seeds[0]
        assert key == Hybrid._construct(param_set=ParamSet.MLKEM768_X25519, seed=seeds[0])

    def test_param_set_enum(self):
        assert [ps.value for ps in ParamSet] == ["MLKEM768-X25519"]
        assert Hybrid.MLKEM768_X25519 is ParamSet.MLKEM768_X25519

        for bad in ("MLKEM768-X25519", MLKEM.ML_KEM_768, None):
            with pytest.raises(TypeError):
                Hybrid.generate(param_set=bad)
            with pytest.raises(TypeError):
                Hybrid._construct(param_set=bad, seed=bytes(32))

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_construct(self, param_set):
        key = Hybrid.generate(param_set=param_set)

        key2 = Hybrid._construct(param_set=param_set, seed=key._seed)
        assert key2 == key
        assert key2._pk == key._pk
        assert Hybrid._construct(param_set=param_set, seed=bytearray(key._seed)) == key
        assert Hybrid._construct(param_set=param_set, seed=key._seed, pk=key._pk) == key

        pub = Hybrid._construct(param_set=param_set, pk=key._pk)
        assert pub == key.public_key()
        assert not pub.has_private()
        assert pub != key
        assert Hybrid._construct(param_set=param_set, pk=memoryview(key._pk)) == pub
        assert pub._seed is None

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_construct_errors(self, param_set):
        _, elem_len, _ = CONFIGS[param_set]
        key = Hybrid.generate(param_set=param_set)
        other = Hybrid.generate(param_set=param_set)

        with pytest.raises(ValueError):
            Hybrid._construct(param_set=param_set)
        for bad_seed in (bytes(31), bytes(33), bytes(64)):
            with pytest.raises(ValueError):
                Hybrid._construct(param_set=param_set, seed=bad_seed)
        for bad_pk in (key._pk[:-1], key._pk + b"\x00"):
            with pytest.raises(ValueError):
                Hybrid._construct(param_set=param_set, pk=bad_pk)
        with pytest.raises(ValueError):
            Hybrid._construct(param_set=param_set, seed=key._seed, pk=other._pk)

        # The ML-KEM public key fails the modulus check
        bad_pk = bytearray(key._pk)
        bad_pk[0] = 0x01
        bad_pk[1] = (bad_pk[1] & 0xF0) | 0x0D
        with pytest.raises(ValueError):
            Hybrid._construct(param_set=param_set, pk=bad_pk)

        # The ECDH public key is not valid
        ek_pq = key._pk[:-elem_len]
        if param_set == ParamSet.MLKEM768_X25519:
            bad_points = [bytes(32), b"\x01" + bytes(31)]  # low order
        else:
            # Not on the curve, and not an uncompressed point
            point = bytearray(key._pk[-elem_len:])
            point[-1] ^= 1
            bad_points = [bytes(point), b"\x05" + key._pk[-elem_len + 1 :], bytes(elem_len)]
        for bad_point in bad_points:
            with pytest.raises(ValueError):
                Hybrid._construct(param_set=param_set, pk=ek_pq + bad_point)

    def test_eq_repr(self):
        key = Hybrid.generate(param_set=ParamSet.MLKEM768_X25519)
        other = Hybrid.generate(param_set=ParamSet.MLKEM768_X25519)

        assert key == Hybrid._construct(param_set=ParamSet.MLKEM768_X25519, seed=key._seed)
        assert key != other
        assert key != key.public_key()
        assert key != key._pk
        assert repr(key) == "HybridKey(param_set=ParamSet.MLKEM768_X25519, private=True)"
        assert repr(key.public_key()) == "HybridKey(param_set=ParamSet.MLKEM768_X25519, private=False)"

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_encaps_decaps(self, param_set):
        _, ct_len = SIZES[param_set]
        _, _, rnd_len = CONFIGS[param_set]
        key = Hybrid.generate(param_set=param_set)

        ss, ct = key.public_key()._encaps()
        assert len(ss) == 32
        assert len(ct) == ct_len
        assert key._decaps(ct) == ss

        ss2, ct2 = key.public_key()._encaps()
        assert ss2 != ss
        assert ct2 != ct

        rnd = b"\x11" * rnd_len
        assert key._encaps(rnd) == key._encaps(rnd)

        # An invalid ML-KEM ciphertext: implicit rejection
        bad_ct = bytearray(ct)
        bad_ct[0] ^= 1
        ss_bad = key._decaps(bytes(bad_ct))
        assert ss_bad != ss

        # The ML-KEM ciphertext of one encapsulation, the ECDH point of another: another secret
        elem_len = CONFIGS[param_set][1]
        ss3, ct3 = key._encaps()
        mixed = ct[:-elem_len] + ct3[-elem_len:]
        assert key._decaps(mixed) not in (ss, ss3)

    @pytest.mark.parametrize("param_set", PARAM_SETS)
    def test_encaps_decaps_errors(self, param_set):
        _, elem_len, rnd_len = CONFIGS[param_set]
        key = Hybrid.generate(param_set=param_set)
        _, ct = key._encaps()

        for bad in (bytes(rnd_len - 1), bytes(rnd_len + 1)):
            with pytest.raises(ValueError):
                key._encaps(bad)
        for bad_ct in (ct[:-1], ct + b"\x00"):
            with pytest.raises(ValueError):
                key._decaps(bad_ct)
        with pytest.raises(TypeError):
            key.public_key()._decaps(ct)

        # An invalid ECDH point in the ciphertext
        with pytest.raises(ValueError):
            key._decaps(ct[:-elem_len] + bytes(elem_len))

    def test_x25519_is_xwing(self):
        """MLKEM768-X25519 is X-Wing: check the derivation of the keys and the combiner step by step"""

        key = Hybrid.generate(param_set=ParamSet.MLKEM768_X25519)

        expanded = SHAKE256.new(key._seed).read(96)
        pq = MLKEM.construct(param_set=MLKEM.ML_KEM_768, seed=expanded[:64])
        t = import_x25519_private_key(expanded[64:])
        pk_t = t.public_key().export_key(format="raw")
        assert key._pk == pq.ek + pk_t

        rnd = bytes(range(64))
        ss, ct = key._encaps(rnd)
        ss_pq, ct_pq = pq._encaps(rnd[:32])
        eph = import_x25519_private_key(rnd[32:])
        ct_t = eph.public_key().export_key(format="raw")
        assert ct == ct_pq + ct_t

        ss_t = (t.pointQ * eph._d).x.to_bytes(32, "little")
        expected = SHA3_256.new(ss_pq + ss_t + ct_t + pk_t + b"\\.//^\\").digest()
        assert ss == expected


def _load_cfrg_vectors():
    try:
        if not test_vectors_available:
            raise FileNotFoundError
        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        with open(os.path.join(init_dir, "PublicKey", "Hybrid", "test-vectors.json")) as file_in:
            vectors = json.load(file_in)
    except FileNotFoundError:
        warn_skipped_tests("Skipping the test vectors of the hybrid KEMs")
        return [
            pytest.param(None, None, id="missing", marks=pytest.mark.skip(reason="Missing test-vectors.json"))
        ]

    # Only X-Wing: MLKEM768-P256 and MLKEM1024-P384 are not supported
    names = {
        "mlkem768_x25519": ParamSet.MLKEM768_X25519,
    }
    return [
        pytest.param(names[name], test, id="%s-%d" % (name, idx))
        for name, tests in vectors.items()
        if name in names
        for idx, test in enumerate(tests)
    ]


class TestCFRGVectors:
    """The test vectors of draft-irtf-cfrg-concrete-hybrid-kems"""

    @pytest.mark.parametrize("param_set,test", _load_cfrg_vectors())
    def test_vector(self, param_set, test):
        mlkem_ps, _, _ = CONFIGS[param_set]

        key = Hybrid._construct(param_set=param_set, seed=unhexlify(test["seed"]))
        assert key._seed == unhexlify(test["decapsulation_key"])
        assert key._pk == unhexlify(test["encapsulation_key"])

        # The keys of the components
        pq = MLKEM.construct(param_set=mlkem_ps, seed=unhexlify(test["decapsulation_key_pq"]))
        assert key._pk.startswith(pq.ek)
        t = import_x25519_private_key(unhexlify(test["decapsulation_key_t"]))
        assert key._pk.endswith(t.public_key().export_key(format="raw"))

        shared_secret, ct = key.public_key()._encaps(unhexlify(test["randomness"]))
        assert ct == unhexlify(test["ciphertext"])
        assert shared_secret == unhexlify(test["shared_secret"])
        assert key._decaps(ct) == shared_secret
