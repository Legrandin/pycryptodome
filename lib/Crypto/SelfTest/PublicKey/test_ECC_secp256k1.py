# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import pytest

from Crypto.Hash import SHA256
from Crypto.Math.Numbers import Integer
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccPoint, _curves
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS

# SEC 2, Section 2.4.1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# The X coordinate of k*G, checked against the reference implementation below
MULTIPLES = {
    2: 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
    3: 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
    4: 0xE493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13,
    5: 0x2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4,
}


# A simple reference implementation: affine coordinates, Python integers


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        slope = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (slope * slope - a[0] - b[0]) % P
    return (x, (slope * (a[0] - x) - a[1]) % P)


def _mul(k, point):
    result = None
    k %= N
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


def _xy(point):
    return (0, 0) if point is None else point


G = (GX, GY)


class TestCurve:
    def test_parameters(self):
        curve = _curves["secp256k1"]
        assert curve.canonical == "secp256k1"
        assert curve.oid == "1.3.132.0.10"
        assert curve.openssh is None
        assert curve.p == P
        assert curve.b == 7
        assert curve.order == N
        assert curve.modulus_bits == 256
        assert curve.is_weierstrass
        assert not curve.is_edwards
        assert not curve.is_montgomery
        assert curve.G.xy == (GX, GY)

    @pytest.mark.parametrize("name", ["secp256k1", "k256", "K-256", "bitcoin"])
    def test_names(self, name):
        assert ECC.generate(curve=name).curve == "secp256k1"
        assert _curves[name] is _curves["secp256k1"]

    def test_not_secp256r1(self):
        assert _curves["secp256r1"] is not _curves["secp256k1"]


class TestPoints:
    g = EccPoint(GX, GY, "secp256k1")

    def test_known_multiples(self):
        for k, x in MULTIPLES.items():
            assert _mul(k, G)[0] == x
            assert (self.g * k).x == x

    def test_add_double_neg(self):
        two = self.g.copy().double()
        assert two.xy == _add(G, G)
        three = two + self.g
        assert three.xy == _add(_add(G, G), G)
        assert (three + self.g).xy == _mul(4, G)
        # Complete formulas: same point, opposite points, point at infinity
        assert (self.g + self.g) == two
        assert (self.g + (-self.g)).is_point_at_infinity()
        pai = self.g.point_at_infinity()
        assert (pai + self.g) == self.g
        assert (self.g + pai) == self.g
        assert (pai + pai).is_point_at_infinity()
        assert pai.copy().double().is_point_at_infinity()
        assert (-self.g).xy == (GX, P - GY)

    @pytest.mark.parametrize("public", [False, True])
    def test_scalar(self, public):
        q = _mul(0x1234567890ABCDEF, G)
        base_q = EccPoint(q[0], q[1], "secp256k1")
        scalars = [0, 1, 2, 3, 15, 16, 17, 31, 32, 33, N - 2, N - 1, N, N + 1, 2 * N, 2**256 - 1, 2**300 + 5]
        scalars += [Integer.from_bytes(get_random_bytes(32)) for _ in range(5)]
        for k in scalars:
            k_int = int(k)
            scalar = Integer(k_int, public=True) if public else k_int
            assert (self.g * scalar).xy == _xy(_mul(k_int, G))
            assert (base_q * scalar).xy == _xy(_mul(k_int, q))

    def test_scalar_in_place_and_rmul(self):
        point = self.g.copy()
        point *= 5
        assert point.x == MULTIPLES[5]
        assert (5 * self.g).x == MULTIPLES[5]

    def test_public_and_secret_paths_match(self):
        q = self.g * 0xABCDEF
        for k in (1, 2, 2**128, N - 1, N):
            assert q * k == q * Integer(k, public=True)

    def test_not_on_curve(self):
        for x, y in ((GX, GY + 1), (1, 1), (0, 7), (0, 1)):
            with pytest.raises(ValueError, match="does not belong to the curve"):
                EccPoint(x, y, "secp256k1")
        # A point of P-256 is not a point of this curve
        p256_g = _curves["p256"].G
        with pytest.raises(ValueError, match="does not belong to the curve"):
            EccPoint(p256_g.x, p256_g.y, "secp256k1")

    def test_other_curve(self):
        with pytest.raises(ValueError, match="not on the same curve"):
            self.g + _curves["p256"].G

    def test_coordinates_reduced(self):
        # Only an x below 2^256 - p fits in 32 bytes once p is added to it
        x = 1
        while pow(x**3 + 7, (P - 1) // 2, P) != 1:
            x += 1
        y = pow(x**3 + 7, (P + 1) // 4, P)
        assert EccPoint(x + P, y, "secp256k1").xy == (x, y)

        # An imported point is rejected instead
        encoded = b"\x04" + (x + P).to_bytes(32, "big") + y.to_bytes(32, "big")
        with pytest.raises(ValueError, match="does not belong to the curve"):
            ECC.import_key(encoded, curve_name="secp256k1")

    def test_sizes(self):
        assert self.g.size_in_bits() == 256
        assert self.g.size_in_bytes() == 32


class TestKeys:
    def test_generate(self):
        key = ECC.generate(curve="secp256k1")
        assert key.has_private()
        assert key.curve == "secp256k1"
        assert 1 <= key.d < N
        assert key.pointQ.xy == _mul(key.d, G)
        public = key.public_key()
        assert not public.has_private()
        assert public.pointQ == key.pointQ

    def test_construct(self):
        d = 0x1000
        x, y = _mul(d, G)
        private = ECC.construct(curve="secp256k1", d=d)
        assert private.d == d
        assert private.pointQ.xy == (x, y)
        assert ECC.construct(curve="secp256k1", d=d, point_x=x, point_y=y) == private
        public = ECC.construct(curve="secp256k1", point_x=x, point_y=y)
        assert not public.has_private()
        assert public == private.public_key()

    def test_construct_errors(self):
        x, y = _mul(5, G)
        for d in (0, N, N + 1):
            with pytest.raises(ValueError):
                ECC.construct(curve="secp256k1", d=d)
        with pytest.raises(ValueError, match="do not match"):
            ECC.construct(curve="secp256k1", d=6, point_x=x, point_y=y)
        with pytest.raises(ValueError, match="does not belong to the curve"):
            ECC.construct(curve="secp256k1", point_x=x, point_y=y + 1)
        with pytest.raises(ValueError, match="'seed' cannot be used"):
            ECC.construct(curve="secp256k1", seed=b"H" * 32)

    def test_repr(self):
        assert repr(ECC.construct(curve="secp256k1", d=1)).startswith("EccKey(curve='secp256k1', point_x=")

    @pytest.mark.parametrize("d", [1, 2, 3, 5, 6, 7, N - 1, N - 2])
    def test_sec1_round_trip(self, d):
        """Both parities of Y, in both forms (the compressed one has no 3x term)"""

        public = ECC.construct(curve="secp256k1", d=d).public_key()
        x, y = public.pointQ.xy

        uncompressed = public.export_key(format="SEC1")
        assert uncompressed == b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        assert public.export_key(format="raw") == uncompressed
        assert ECC.import_key(uncompressed, curve_name="secp256k1") == public

        compressed = public.export_key(format="SEC1", compress=True)
        assert compressed == bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
        assert ECC.import_key(compressed, curve_name="k256") == public

    def test_sec1_compressed_generator(self):
        encoded = bytes.fromhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        assert ECC.import_key(encoded, curve_name="secp256k1").pointQ.xy == (GX, GY)

    def test_sec1_invalid(self):
        # x = 5 is not the X coordinate of any point: x^3 + 7 is not a square
        assert pow(5**3 + 7, (P - 1) // 2, P) != 1
        for encoded in (
            b"\x02" + (5).to_bytes(32, "big"),
            b"\x02" + P.to_bytes(32, "big"),
            b"\x04" + P.to_bytes(32, "big") + GY.to_bytes(32, "big"),
            b"\x04" + GX.to_bytes(32, "big") + (GY + 1).to_bytes(32, "big"),
            b"\x05" + GX.to_bytes(32, "big"),
            b"\x02" + GX.to_bytes(32, "big")[:31],
        ):
            with pytest.raises(ValueError):
                ECC.import_key(encoded, curve_name="secp256k1")

    @pytest.mark.parametrize("fmt", ["DER", "PEM"])
    @pytest.mark.parametrize("compress", [False, True])
    def test_export_import_public(self, fmt, compress):
        public = ECC.generate(curve="secp256k1").public_key()
        assert ECC.import_key(public.export_key(format=fmt, compress=compress)) == public

    @pytest.mark.parametrize("fmt", ["DER", "PEM"])
    @pytest.mark.parametrize("use_pkcs8", [False, True])
    def test_export_import_private(self, fmt, use_pkcs8):
        key = ECC.generate(curve="secp256k1")
        imported = ECC.import_key(key.export_key(format=fmt, use_pkcs8=use_pkcs8))
        assert imported == key
        assert imported.d == key.d
        assert imported.curve == "secp256k1"

    def test_export_import_private_protected(self):
        key = ECC.generate(curve="secp256k1")
        encoded = key.export_key(
            format="PEM",
            passphrase="secret",
            protection="PBKDF2WithHMAC-SHA256AndAES128-CBC",
            prot_params={"iteration_count": 1000},
        )
        assert ECC.import_key(encoded, passphrase="secret").d == key.d

    def test_no_openssh(self):
        with pytest.raises(ValueError, match="Cannot export secp256k1 keys as OpenSSH"):
            ECC.generate(curve="secp256k1").public_key().export_key(format="OpenSSH")


class TestSignatures:
    def test_deterministic_known_answer(self):
        """RFC 6979, with the signature computed by OpenSSL 3"""

        key = ECC.construct(curve="secp256k1", d=1)
        signature = DSS.new(key, "deterministic-rfc6979").sign(SHA256.new(b"Satoshi Nakamoto"))
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        assert r == 0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8
        assert s == 0xDBBD3162D46E9F9BEF7FEB87C16DC13B4F6568A87F4E83F728E2443BA586675C

        # The low-S form is the value published for Bitcoin wallets
        low_s_signature = DSS.new(key, "deterministic-rfc6979", low_s=True).sign(
            SHA256.new(b"Satoshi Nakamoto")
        )
        assert low_s_signature[:32] == signature[:32]
        assert low_s_signature[32:] == bytes.fromhex(
            "2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5"
        )

    @pytest.mark.parametrize("mode", ["sec1", "deterministic-rfc6979"])
    @pytest.mark.parametrize("encoding", ["binary", "der"])
    def test_sign_verify(self, mode, encoding):
        key = ECC.generate(curve="secp256k1")
        msg_hash = SHA256.new(b"message")
        signature = DSS.new(key, mode, encoding=encoding).sign(msg_hash)
        verifier = DSS.new(key.public_key(), mode, encoding=encoding)
        verifier.verify(msg_hash, signature)
        if encoding == "binary":
            assert len(signature) == 64
        with pytest.raises(ValueError, match="not authentic"):
            verifier.verify(SHA256.new(b"other message"), signature)

    def test_randomized_nonce(self):
        key = ECC.generate(curve="secp256k1")
        msg_hash = SHA256.new(b"message")
        signer = DSS.new(key, "sec1")
        assert signer.sign(msg_hash) != signer.sign(msg_hash)

    def test_wrong_curve(self):
        msg_hash = SHA256.new(b"message")
        signature = DSS.new(ECC.generate(curve="secp256k1"), "sec1").sign(msg_hash)
        with pytest.raises(ValueError, match="not authentic"):
            DSS.new(ECC.generate(curve="p256").public_key(), "fips-186-3").verify(msg_hash, signature)

    def test_verify_range(self):
        key = ECC.construct(curve="secp256k1", d=1)
        verifier = DSS.new(key.public_key(), "sec1")
        msg_hash = SHA256.new(b"message")
        for r, s in ((0, 1), (1, 0), (N, 1), (1, N)):
            bad = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            with pytest.raises(ValueError, match="not authentic"):
                verifier.verify(msg_hash, bad)


class TestECDH:
    def test_agreement(self):
        a = ECC.generate(curve="secp256k1")
        b = ECC.generate(curve="secp256k1")
        secret_a = key_agreement(static_priv=a, static_pub=b.public_key(), kdf=lambda x: x)
        secret_b = key_agreement(static_priv=b, static_pub=a.public_key(), kdf=lambda x: x)
        assert secret_a == secret_b
        assert len(secret_a) == 32
        assert int.from_bytes(secret_a, "big") == _mul(a.d * b.d, G)[0]

    def test_other_curve(self):
        a = ECC.generate(curve="secp256k1")
        b = ECC.generate(curve="p256")
        with pytest.raises((ValueError, TypeError)):
            key_agreement(static_priv=a, static_pub=b.public_key(), kdf=lambda x: x)
