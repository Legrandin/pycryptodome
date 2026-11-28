# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Tests for Argon2 (RFC 9106): argon2(), argon2_hash() and argon2_check()"""

import base64
import time

import pytest

from Crypto import KdfIterationLimitError, KdfMemoryLimitError
from Crypto.Protocol import KDF, _argon2
from Crypto.Protocol.KDF import (
    ARGON2_DEFAULT_PROFILE,
    Argon2Params,
    Argon2Profile,
    Argon2Variant,
    argon2,
    argon2_check,
    argon2_hash,
)
from Crypto.SelfTest.st_common import mark_slow

V = Argon2Variant
P = Argon2Profile

# The classes with test vectors run with each C implementation available on this machine
_argon2._lib()
_implementations = [pytest.param(lib, id=name) for name, lib in _argon2._raw_argon2_libs.items()]


@pytest.fixture(params=_implementations)
def argon2_implementation(request, monkeypatch):
    monkeypatch.setattr(_argon2, "_raw_argon2_lib", request.param)


def _b64(data):
    return base64.b64encode(data).rstrip(b"=")


@pytest.mark.usefixtures("argon2_implementation")
class TestRFC9106:
    """The test vectors of RFC 9106 (Section 5): t=3, m=32 KiB, p=4, T=32, with K and X"""

    tags = {
        V.ARGON2D: "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        V.ARGON2I: "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        V.ARGON2ID: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
    }

    @pytest.mark.parametrize("variant", list(V))
    @pytest.mark.parametrize("threads", [1, 2, 3, 4, 5, 0])
    def test_vector(self, variant, threads):
        tag = argon2(
            b"\x01" * 32,
            32,
            salt=b"\x02" * 16,
            secret=b"\x03" * 8,
            associated_data=b"\x04" * 12,
            time_cost=3,
            memory_cost=32,
            lanes=4,
            variant=variant,
            threads=threads,
        )
        assert tag.hex() == self.tags[variant]

    def test_buffers(self):
        tag = argon2(
            bytearray(b"\x01" * 32),
            32,
            salt=memoryview(b"\x02" * 16),
            secret=bytearray(b"\x03" * 8),
            associated_data=memoryview(b"\x04" * 12),
            time_cost=3,
            memory_cost=32,
            lanes=4,
        )
        assert tag.hex() == self.tags[V.ARGON2ID]

    def test_num_keys(self):
        params = {"salt": b"\x02" * 16, "secret": b"\x03" * 8, "associated_data": b"\x04" * 12}
        params.update(time_cost=3, memory_cost=32, lanes=4)
        keys = argon2(b"\x01" * 32, 8, num_keys=4, **params)
        assert keys == [bytes.fromhex(self.tags[V.ARGON2ID])[i : i + 8] for i in range(0, 32, 8)]
        assert argon2(b"\x01" * 32, 32, num_keys=1, **params).hex() == self.tags[V.ARGON2ID]
        # A tag of 64 bytes is not 2 tags of 32
        two = argon2(b"\x01" * 32, 32, num_keys=2, **params)
        assert two[0] != bytes.fromhex(self.tags[V.ARGON2ID])


@pytest.mark.usefixtures("argon2_implementation")
class TestOpenSSL:
    """Vectors created with OpenSSL 3.5.5 (openssl kdf ... ARGON2D/ARGON2I/ARGON2ID),
    with random inputs: odd memory sizes (rounded down to a multiple of 4*p KiB),
    up to 8 lanes, empty and long inputs, and tags longer than 64 bytes"""

    # fmt: off
    vectors = (
        # variant, t, m, p, password, salt, secret, associated data, tag (all in hex)
        ("ARGON2D", 1, 8, 1, "", "f43771980eb2d9d6", "", "", "b41493e0"),
        ("ARGON2I", 1, 8, 1, "34", "8ddf5917172afbc5", "", "", "aba46e7ee8051fe47ef3f2bcab6ec89cd27dca7d18b86daf7b2c70968327a81d"),
        ("ARGON2ID", 2, 100, 3, "5140b498be9f0b84df39c9745b", "421f72181c89bc0f4beb876f8468213a", "f1aebd8a27", "30fdf12bea2c23", "c59a3bc512b0a42ad91eb097b331a831556701d5298ffe916d5989678cc2dad7"),
        ("ARGON2D", 3, 1001, 2, "1e579655e0d28093b102f026b7f3bb76ecfdacf10ebcb85bfec5ba41ff44f521", "ea190859e65d654b35cd586a42468ee6", "", "50ccc47a9a96f9cca3fcb80e", "d1135f98a92d2f0bb86b78e5c8f3356e9564baec4293f91bcc551895e8f95643c9918b0ee67e6382aee4f8ca20fd4a4c86307e9944c2fe3233cf00e1427cf04c"),
        ("ARGON2I", 2, 1500, 1, "8d8ab62ad07ffbc3", "fc974e10ab19541790782bca67146c31d79fecd8", "069341b8c0d375e22d70a0459d584295", "", "a6cd44b4bb7eea3c5ae95a9246a266c43fef61d4b502042c1de7b4c81906f4b6125be401b856d8e62577c92913a3f7aa692308f46795b2a4797842c7f021c053e7"),
        ("ARGON2ID", 1, 2000, 5, "ad230f35361f02e3b8c929f22055fa9cbff5f0e6d3ecfd39ba071100c3bf4d5f7a6439f8053f512d05faee5d9a0278d6373236ddeba45ada7ae8aa45d71ed410", "5e9967ee3473353184a31140f66eec07f7c9e88bbcc215f18680a238328f45fb", "161a6295a2ff10799968dd1883ed9435f3408c8538a7113cbb4e43f189f55edc", "4dcbb7260a9e5a8b0a1fc35d3eb477025d4a266bbcc1b005133a91a86361cf82", "d5421acf37a672eb088c97abc326e69771d640fa61b3967ec0911a4a1eafb3cedd575d199182053a0f93e2271e2ff0ff88206e3e635a0aeef1e16c1c07cd2dccd7ed58308ff2d3d72febaf54257f61a341002db40e3336291c9e93543c42eac9e6adf14a"),
        ("ARGON2I", 4, 600, 4, "240d4a", "4ecd7da2a8fbb1d19d", "", "7f8a46", "9b4e0bdb7de487875732727e995b4f1371263d84a92ccb7960adae9b138466bd56cb9c6520598183da22a131803980f9ec459c4908ededbd7762448967176c29a01d5f0e0992360d108b87a884d46be11b8ad8b223f2727d9e9d9a88295f60a2de5a1fdfbe4eb40ee0e47eb01a267bee5ab6e4b50cd7654cd06a5ee0e7b10bba"),
        ("ARGON2ID", 3, 4096, 8, "92222bddaa57dbabfd57d471d862414f9dfdbf2d", "1aa9dd710dff37cbb610a5053d91c190", "ca19809c8f304cab", "", "ff6defa4a87a2bf25cc090a07bd8a52f155f37c7608a723bba097cbcaa500cad73"),
    )
    # fmt: on

    @pytest.mark.parametrize("vector", vectors)
    @pytest.mark.parametrize("threads", [1, 3])
    def test_vector(self, vector, threads):
        variant, t, m, p, pw, salt, secret, ad, tag = vector
        result = argon2(
            bytes.fromhex(pw),
            len(tag) // 2,
            salt=bytes.fromhex(salt),
            secret=bytes.fromhex(secret),
            associated_data=bytes.fromhex(ad),
            time_cost=t,
            memory_cost=m,
            lanes=p,
            variant=Argon2Variant[variant],
            threads=threads,
        )
        assert result.hex() == tag


# The PHC strings of the reference implementation (phc-winner-argon2, src/test.c),
# all with the password "password" (or "differentpassword") and 8-byte salts
_REFERENCE = [
    ("password", "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA"),
    ("password", "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8"),
    ("password", "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E"),
    ("password", "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8"),
    ("password", "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls"),
    (
        "differentpassword",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4",
    ),
    ("password", "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE"),
    ("password", "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"),
    ("password", "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4"),
    ("password", "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc"),
    ("password", "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg"),
    ("password", "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw"),
    (
        "differentpassword",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94",
    ),
    ("password", "$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw"),
]

# With 64 MiB, only the first one of each variant in the quick tests
_REFERENCE_QUICK = [v for i, v in enumerate(_REFERENCE) if "m=65536" not in v[1] or i in (0, 7)]
_REFERENCE_SLOW = [v for v in _REFERENCE if v not in _REFERENCE_QUICK]

# 256 MiB each: about one second
_REFERENCE_LARGE = [
    ("password", "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s"),
    ("password", "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow"),
]

# PHC strings created by argon2-cffi 25.1.0 (with random salts), which also cover Argon2d,
# empty and non-ASCII passwords, short and long tags, and salts of odd length
_ARGON2_CFFI = [
    ("", "$argon2i$v=19$m=816,t=3,p=1$giO09hF1IvjafjYsGgkNPjhh0qAxEmTwQJso2yd/tBPD$EyO38w"),
    ("password", "$argon2d$v=19$m=1209,t=1,p=2$sNgBPrweGGI$oMBtdQ"),
    (
        "",
        "$argon2d$v=19$m=285,t=1,p=4$jUZLfqBBaBH1i6n3hFVNn8uh1prxsbY8HboU/kmx2J1C$Shjnnw5vkQ/qt4Yg6ZweDGo3ZO0J2cgE"
        "XCPprKuE6sSc1+cDY7NsulOcl7+vJEDXrnBebDda/zc4U9TthfikwFQ",
    ),
    ("password", "$argon2id$v=19$m=402,t=1,p=4$lAInAKD8vC8$z0G7bfSyGVgwahI46D4ywGYdTy3rYLTR06VCoKtOtNI"),
    (
        "",
        "$argon2id$v=19$m=160,t=3,p=4$eZJAGNsQFZY$J/c7P76YpHSF697rVeIS9w1iy/ZI+FQ3kby4OUyVCHst+zkXxH4qeYNggFolQk/XA"
        "0OTYhBrocfoCmVA0EVnKfA",
    ),
    (
        "pässwörd ✓",
        "$argon2i$v=19$m=1120,t=2,p=4$MhQzLvGwhZOhGQhA3EarQWFzpyfDuyTURmaztirhK2hs$rt6XLZi8Tdiooegl08XewoP3cqjhC3+G"
        "80viUhlVH7hRADI2A1swa3U3aoya4oO5KvJ0q6tplTZUaUN2Srsqdw",
    ),
    ("password", "$argon2i$v=19$m=629,t=1,p=2$kBS5YPY3jr4$t0/NJYnhpNHo5d1PEPrqcQ"),
    (
        "pässwörd ✓",
        "$argon2id$v=19$m=1091,t=2,p=2$qCsdPRjCjwKTXh8WmAI2Ag$1srrke6wMel/LW2kmh4+SeGhn39tQ51GAkZiyV6gD0usxIdW7rpS3U"
        "laAjc8sVVRfJMq45guD42+4DaGT7uWsA",
    ),
    ("x" * 100, "$argon2id$v=19$m=249,t=3,p=1$SsubeMDhDtajK6dFpREDOA$2gsANC2ZQ7jKXtEqSMFfMg"),
]


def _parse(phc):
    """The parameters of a PHC string, as keyword arguments of argon2_hash()"""
    _, variant, _, params, salt, tag = phc.split("$")
    m, t, p = (int(x.split("=")[1]) for x in params.split(","))
    tag = base64.b64decode(tag + "=" * (-len(tag) % 4))
    salt = base64.b64decode(salt + "=" * (-len(salt) % 4))
    return {
        "variant": V(variant),
        "memory_cost": m,
        "time_cost": t,
        "lanes": p,
        "salt": salt,
        "hash_len": len(tag),
    }


@pytest.mark.usefixtures("argon2_implementation")
class TestPHCStrings:
    @pytest.mark.parametrize(
        "vector", _REFERENCE_QUICK + mark_slow(_REFERENCE_SLOW + _REFERENCE_LARGE) + _ARGON2_CFFI
    )
    def test_check(self, vector):
        password, phc = vector
        argon2_check(password, phc)
        argon2_check(password.encode("utf-8"), phc.encode("ascii"))
        with pytest.raises(ValueError, match="Incorrect Argon2 hash"):
            argon2_check(password + "x", phc)

    @pytest.mark.parametrize("vector", _REFERENCE_QUICK + mark_slow(_REFERENCE_SLOW) + _ARGON2_CFFI)
    def test_hash(self, vector):
        password, phc = vector
        assert argon2_hash(password, **_parse(phc)) == phc.encode("ascii")

    def test_mismatch(self):
        # From the reference implementation: the hash of "passwore"
        with pytest.raises(ValueError, match="Incorrect Argon2 hash"):
            argon2_check(
                "password",
                "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM",
            )

    def test_secret(self):
        stored = argon2_hash("password", profile=P.OWASP_2023_19MIB, secret=b"pepper")
        argon2_check("password", stored, secret=b"pepper")
        with pytest.raises(ValueError, match="Incorrect Argon2 hash"):
            argon2_check("password", stored)
        with pytest.raises(ValueError, match="Incorrect Argon2 hash"):
            argon2_check("password", stored, secret=b"pepperoni")

    def test_default(self):
        stored = argon2_hash("correct horse battery staple")
        assert isinstance(stored, bytes)
        assert stored.startswith(b"$argon2id$v=19$m=65536,t=3,p=4$")
        _, _, _, _, salt, tag = stored.split(b"$")
        assert len(base64.b64decode(salt + b"==")) == 16
        assert len(base64.b64decode(tag + b"=")) == 32
        argon2_check("correct horse battery staple", stored)
        # A new random salt every time
        assert argon2_hash("correct horse battery staple") != stored

    @pytest.mark.parametrize("variant", list(V))
    def test_variants(self, variant):
        stored = argon2_hash("pw", variant=variant, memory_cost=64, time_cost=1, lanes=1)
        assert stored.startswith(b"$" + variant.value.encode() + b"$v=19$m=64,t=1,p=1$")
        argon2_check("pw", stored)

    # The reference implementation's error tests, and others
    bad_hashes = [
        # missing $
        "$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        # empty salt
        "$argon2i$v=19$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
        # no version (v=16 is implied)
        "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        # other order of the parameters
        "$argon2i$v=19$t=2,m=65536,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        # missing or extra parameters (keyid and data are obsolete)
        "$argon2i$v=19$m=65536,t=2$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=1,keyid=AAAA$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=1,data=AAAA$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        # leading zeros, signs, spaces
        "$argon2i$v=19$m=065536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=+2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        " $argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA\n",
        # padding, non-canonical base64, URL-safe alphabet
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ=$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHR$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj-qf_YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtAA",
        # salt shorter than 8 bytes, tag shorter than 4 bytes
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbA$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKI",
        # parameters outside the range of RFC 9106
        "$argon2i$v=19$m=7,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=0,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=0$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=65536,t=2,p=16777216$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=4294967296,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=99999999999999999999,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "$argon2i$v=19$m=64,t=2,p=9$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        # not a hash
        "",
        "$argon2i$",
        "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
    ]

    @pytest.mark.parametrize("bad", bad_hashes)
    def test_bad_format(self, bad):
        with pytest.raises(ValueError):
            argon2_check("password", bad)

    @pytest.mark.parametrize("identifier", ["argon2", "argon2x", "argon2ID", "scrypt"])
    def test_unknown_variant(self, identifier):
        stored = "$%s$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4" % identifier
        with pytest.raises(ValueError):
            argon2_check("password", stored)

    @pytest.mark.parametrize("version", ["16", "18", "20", "019"])
    def test_unsupported_version(self, version):
        stored = (
            "$argon2id$v=%s$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4" % version
        )
        with pytest.raises(ValueError, match="version"):
            argon2_check("password", stored)

    def test_type_errors(self):
        good = _REFERENCE[1][1]
        for bad in (None, 1, ["x"]):
            with pytest.raises(TypeError):
                argon2_check("password", bad)
        with pytest.raises(TypeError):
            argon2_check(1, good)
        with pytest.raises(TypeError):
            argon2_check("password", good, secret="pepper")


class TestLimits:
    def _hash(self, m, t, p=1):
        return "$argon2id$v=19$m=%d,t=%d,p=%d$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4" % (
            m,
            t,
            p,
        )

    def test_memory_default(self):
        # 256 MiB is allowed (it is the limit), but not 4 more blocks (with p=1, m is a multiple of 4)
        with pytest.raises(KdfMemoryLimitError, match="the default"):
            argon2_check("password", self._hash(256 * 1024 + 4, 1))
        # Only the memory of the blocks counts: m is rounded down to a multiple of 4*p
        with pytest.raises(ValueError, match="Incorrect Argon2 hash"):
            argon2_check("password", self._hash(256 * 1024 + 3, 1), max_cost=0)

    def test_memory_explicit(self):
        # self._hash(256, 2) is a valid hash of "password" (from the reference implementation)
        with pytest.raises(KdfMemoryLimitError, match="max_memory: 262143"):
            argon2_check("password", self._hash(256, 2), max_memory=256 * 1024 - 1)
        argon2_check("password", self._hash(256, 2), max_memory=256 * 1024)
        argon2_check("password", self._hash(256, 2), max_memory=0)

    def test_cost_default(self):
        # 2**25 KiB of work is allowed, but not more
        with pytest.raises(KdfIterationLimitError, match="the default"):
            argon2_check("password", self._hash(64, 2**19 + 1))
        with pytest.raises(KdfIterationLimitError):
            argon2_check("password", self._hash(64, 2**32 - 1))

    def test_cost_explicit(self):
        with pytest.raises(KdfIterationLimitError, match="max_cost: 511"):
            argon2_check("password", self._hash(256, 2), max_cost=511)
        argon2_check("password", self._hash(256, 2), max_cost=512)
        argon2_check("password", self._hash(256, 2), max_cost=0)

    def test_both_limits_are_subclasses(self):
        assert issubclass(KdfMemoryLimitError, ValueError)
        assert issubclass(KdfIterationLimitError, ValueError)

    def test_before_allocation(self):
        # The hash wants 4 TiB of memory: the check must come first, so it fails at once
        start = time.monotonic()
        with pytest.raises(KdfMemoryLimitError):
            argon2_check("password", self._hash(2**32 - 1, 2**32 - 1))
        with pytest.raises(KdfIterationLimitError):
            argon2_check("password", self._hash(2**32 - 1, 2**32 - 1), max_memory=0)
        assert time.monotonic() - start < 1

    @pytest.mark.parametrize("name", ["max_memory", "max_cost"])
    def test_bad_limits(self, name):
        good = _REFERENCE[1][1]
        for bad in ("1", 1.5, True):
            with pytest.raises(TypeError):
                argon2_check("password", good, **{name: bad})
        with pytest.raises(ValueError, match="non-negative"):
            argon2_check("password", good, **{name: -1})


class TestParameters:
    common = {"salt": b"saltsalt", "time_cost": 1, "memory_cost": 16, "lanes": 2}

    def test_lanes_and_threads(self):
        ref = argon2("pw", 32, salt=b"saltsalt", time_cost=2, memory_cost=128, lanes=7)
        for threads in (0, 2, 3, 7, 8, 100):
            assert (
                argon2("pw", 32, salt=b"saltsalt", time_cost=2, memory_cost=128, lanes=7, threads=threads)
                == ref
            )
        # The lanes change the result
        assert argon2("pw", 32, salt=b"saltsalt", time_cost=2, memory_cost=128, lanes=6) != ref

    def test_str_password(self):
        assert argon2("pässwörd", 32, **self.common) == argon2("pässwörd".encode(), 32, **self.common)

    def test_rounding(self):
        # m is rounded down to a multiple of 4*p blocks, but the original m goes into H0
        a = argon2("pw", 32, salt=b"saltsalt", time_cost=1, memory_cost=24, lanes=3)
        b = argon2("pw", 32, salt=b"saltsalt", time_cost=1, memory_cost=25, lanes=3)
        assert a != b

    @pytest.mark.parametrize(
        "name, low, high",
        [
            ("time_cost", 1, 2**32 - 1),
            ("lanes", 1, 2**24 - 1),
            ("memory_cost", 16, 2**32 - 1),
        ],
    )
    def test_bounds(self, name, low, high):
        params = dict(self.common)
        params[name] = low
        argon2("pw", 32, **params)
        params[name] = low - 1
        with pytest.raises(ValueError):
            argon2("pw", 32, **params)
        params[name] = high + 1
        with pytest.raises(ValueError):
            argon2("pw", 32, **params)

    def test_memory_per_lane(self):
        argon2("pw", 32, salt=b"saltsalt", time_cost=1, memory_cost=8 * 3, lanes=3)
        with pytest.raises(ValueError, match="8 KiB for each lane"):
            argon2("pw", 32, salt=b"saltsalt", time_cost=1, memory_cost=8 * 3 - 1, lanes=3)

    def test_too_many_lanes(self):
        # Valid in RFC 9106, but it needs 8 KiB per lane (128 GiB)
        with pytest.raises(ValueError):
            argon2("pw", 32, salt=b"saltsalt", time_cost=1, memory_cost=16, lanes=2**24 - 1)

    def test_tag_length(self):
        assert len(argon2("pw", 4, **self.common)) == 4
        assert len(argon2("pw", 1000, **self.common)) == 1000
        assert len(argon2("pw", 2, num_keys=2, **self.common)[0]) == 2
        for key_len, num_keys in ((3, 1), (1, 3), (0, 10)):
            with pytest.raises(ValueError):
                argon2("pw", key_len, num_keys=num_keys, **self.common)
        with pytest.raises(ValueError):
            argon2("pw", 32, num_keys=0, **self.common)

    def test_salt(self):
        params = dict(self.common)
        del params["salt"]
        argon2("pw", 32, salt=b"8 bytes!", **params)
        for bad in (b"", b"7 bytes"):
            with pytest.raises(ValueError, match="salt"):
                argon2("pw", 32, salt=bad, **params)
        with pytest.raises(TypeError):
            argon2("pw", 32, salt="a string salt", **params)
        with pytest.raises(TypeError):
            argon2("pw", 32, **params)  # salt is required

    def test_keyword_only(self):
        with pytest.raises(TypeError):
            argon2("pw", b"saltsalt", 32, 1, 16, 2)
        with pytest.raises(TypeError):
            argon2_hash("pw", P.OWASP_2023_19MIB)

    @pytest.mark.parametrize("name", ["time_cost", "memory_cost", "lanes", "key_len", "num_keys"])
    def test_integer_types(self, name):
        for bad in (True, 32.0, "32"):
            params = dict(self.common)
            key_len = 32
            if name == "key_len":
                key_len = bad
            else:
                params[name] = bad
            with pytest.raises(TypeError):
                argon2("pw", key_len, **params)

    @pytest.mark.parametrize("name", ["secret", "associated_data"])
    def test_buffer_types(self, name):
        with pytest.raises(TypeError):
            argon2("pw", 32, **dict(self.common, **{name: "text"}))
        with pytest.raises(TypeError):
            argon2(1234, 32, **self.common)

    def test_threads(self):
        for bad in (-1, 1.0, True):
            with pytest.raises((TypeError, ValueError)):
                argon2("pw", 32, threads=bad, **self.common)

    def test_variant_type(self):
        with pytest.raises(TypeError, match="Argon2Variant"):
            argon2("pw", 32, variant="argon2id", **self.common)
        with pytest.raises(TypeError, match="Argon2Variant"):
            argon2_hash("pw", variant=2, **self.common)

    def test_variants_differ(self):
        tags = {argon2("pw", 32, variant=v, **self.common) for v in V}
        assert len(tags) == 3
        assert argon2("pw", 32, **self.common) == argon2("pw", 32, variant=V.ARGON2ID, **self.common)


@pytest.mark.usefixtures("argon2_implementation")
class TestProfiles:
    # Each profile must never change: its parameters, and the key it derives
    # (the keys with p=1 are the same as libsodium's crypto_pwhash with
    # Argon2id, as computed by PyNaCl 1.6.2 with libsodium)
    pinned = {
        "RFC9106_2021_2GIB": (V.ARGON2ID, 1, 2 * 1024 * 1024, 4, 16, 32, 2021),
        "RFC9106_2021_64MIB": (V.ARGON2ID, 3, 64 * 1024, 4, 16, 32, 2021),
        "OWASP_2023_19MIB": (V.ARGON2ID, 2, 19 * 1024, 1, 16, 32, 2023),
        "LIBSODIUM_2017_INTERACTIVE": (V.ARGON2ID, 2, 64 * 1024, 1, 16, 32, 2017),
        "LIBSODIUM_2017_MODERATE": (V.ARGON2ID, 3, 256 * 1024, 1, 16, 32, 2017),
        "LIBSODIUM_2017_SENSITIVE": (V.ARGON2ID, 4, 1024 * 1024, 1, 16, 32, 2017),
    }

    libsodium = {
        "LIBSODIUM_2017_INTERACTIVE": "c05ce4c4dd7e0e45ee6011cc59d068ade47df1b01fc0cf9cd4678bdf68a5b7b0",
        "LIBSODIUM_2017_MODERATE": "aad608b5866cef907f47d5cae529ed01a91301c92c5d5fef46e1a65e394e5742",
        "LIBSODIUM_2017_SENSITIVE": "744c15fa0c4849143860af4fd976da2b4ea6c1f7c8e786f2343651215925ef2c",
    }

    def test_members(self):
        assert [p.name for p in P] == list(self.pinned)
        for profile in P:
            assert isinstance(profile, Argon2Params)
            expected = self.pinned[profile.name]
            got = (
                profile.variant,
                profile.time_cost,
                profile.memory_cost,
                profile.lanes,
                profile.salt_len,
                profile.key_len,
                profile.year,
            )
            assert got == expected
            assert profile.source and profile.rationale
            assert profile.deprecated is None
            assert str(profile.year) in profile.name
            assert Argon2Profile[profile.name] is profile
            assert isinstance(profile._asdict(), dict)

    def test_default(self):
        assert ARGON2_DEFAULT_PROFILE is P.RFC9106_2021_64MIB
        assert KDF.ARGON2_DEFAULT_PROFILE is ARGON2_DEFAULT_PROFILE

    @pytest.mark.parametrize("name", ["LIBSODIUM_2017_INTERACTIVE", *mark_slow(["LIBSODIUM_2017_MODERATE"])])
    def test_libsodium(self, name):
        key = argon2(b"correct horse battery staple", 32, salt=bytes(range(16)), profile=Argon2Profile[name])
        assert key.hex() == self.libsodium[name]

    @pytest.mark.slow
    def test_libsodium_sensitive(self):
        # 1 GiB
        name = "LIBSODIUM_2017_SENSITIVE"
        key = argon2(
            b"correct horse battery staple", 32, salt=bytes(range(16)), profile=Argon2Profile[name], threads=0
        )
        assert key.hex() == self.libsodium[name]

    def test_profile_equals_explicit(self):
        profile = P.OWASP_2023_19MIB
        a = argon2("pw", 32, salt=b"saltsalt", profile=profile)
        b = argon2(
            "pw",
            32,
            salt=b"saltsalt",
            time_cost=profile.time_cost,
            memory_cost=profile.memory_cost,
            lanes=profile.lanes,
            variant=profile.variant,
        )
        assert a == b

    def test_overrides(self):
        base = {"salt": b"saltsalt", "profile": P.OWASP_2023_19MIB}
        explicit = {
            "salt": b"saltsalt",
            "time_cost": 2,
            "memory_cost": 19 * 1024,
            "lanes": 1,
            "variant": V.ARGON2ID,
        }
        for name, value in (("time_cost", 1), ("memory_cost", 64), ("lanes", 2), ("variant", V.ARGON2D)):
            got = argon2("pw", 16, **dict(base, **{name: value}))
            assert got == argon2("pw", 16, **dict(explicit, **{name: value}))
            assert got != argon2("pw", 16, **base)

    def test_overrides_hash(self):
        stored = argon2_hash("pw", memory_cost=64)
        # The default profile gives the passes and the lanes
        assert stored.startswith(b"$argon2id$v=19$m=64,t=3,p=4$")
        stored = argon2_hash(
            "pw", profile=P.OWASP_2023_19MIB, lanes=2, time_cost=1, salt=b"saltsalt", hash_len=20
        )
        assert stored.startswith(b"$argon2id$v=19$m=19456,t=1,p=2$" + _b64(b"saltsalt") + b"$")
        assert stored == argon2_hash(
            "pw", time_cost=1, memory_cost=19456, lanes=2, variant=V.ARGON2ID, salt=b"saltsalt", hash_len=20
        )
        _, _, _, _, _, tag = stored.split(b"$")
        assert len(base64.b64decode(tag + b"=" * (-len(tag) % 4))) == 20
        argon2_check("pw", stored)

    def test_override_out_of_range(self):
        with pytest.raises(ValueError, match="8 KiB for each lane"):
            argon2("pw", 32, salt=b"saltsalt", profile=P.OWASP_2023_19MIB, lanes=19 * 1024 // 8 + 1)
        with pytest.raises(ValueError):
            argon2("pw", 32, salt=b"saltsalt", profile=P.OWASP_2023_19MIB, time_cost=0)

    def test_partial_costs(self):
        for params in (
            {"time_cost": 1},
            {"time_cost": 1, "memory_cost": 16},
            {"memory_cost": 16, "lanes": 1},
            {"variant": V.ARGON2ID},
            {},
        ):
            with pytest.raises(TypeError, match="profile"):
                argon2("pw", 32, salt=b"saltsalt", **params)

    def test_profile_type(self):
        for bad in ("RFC9106_2021_64MIB", tuple(P.OWASP_2023_19MIB), Argon2Params(*P.OWASP_2023_19MIB), 1):
            with pytest.raises(TypeError, match="Argon2Profile"):
                argon2("pw", 32, salt=b"saltsalt", profile=bad)
            with pytest.raises(TypeError, match="Argon2Profile"):
                argon2_hash("pw", profile=bad)

    def test_enum_lookup(self):
        with pytest.raises(KeyError):
            Argon2Profile["rfc9106_2021_64mib"]
        with pytest.raises(AttributeError):
            P.RFC9106_2021_64MB  # noqa: B018
        assert V("argon2id") is V.ARGON2ID
        assert V.ARGON2ID.value == "argon2id"

    def test_variants(self):
        assert [v.value for v in V] == ["argon2d", "argon2i", "argon2id"]
