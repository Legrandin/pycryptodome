import json
import os
from binascii import unhexlify

import pytest

from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Protocol import DH, HPKE
from Crypto.Protocol.HPKE import DeserializeError
from Crypto.PublicKey import ECC, MLKEM, Hybrid


class TestHPKE:
    key1 = ECC.generate(curve="p256")
    key2 = ECC.generate(curve="p256")

    # name, size of enc
    curves = {
        "p256": 65,
        "p384": 97,
        "p521": 133,
        "curve25519": 32,
        "curve448": 56,
    }

    def round_trip(self, curve, aead_id):
        key1 = ECC.generate(curve=curve)
        aead_id = aead_id

        encryptor = HPKE.new(receiver_key=key1.public_key(), aead_id=aead_id)
        assert len(encryptor.enc) == self.curves[curve]

        # First message
        ct = encryptor.seal(b"ABC", auth_data=b"DEF")

        decryptor = HPKE.new(receiver_key=key1, aead_id=aead_id, enc=encryptor.enc)

        pt = decryptor.unseal(ct, auth_data=b"DEF")
        assert pt == b"ABC"

        # Second message
        ct2 = encryptor.seal(b"GHI")
        pt2 = decryptor.unseal(ct2)
        assert pt2 == b"GHI"

    def test_round_trip(self):
        for curve in self.curves:
            for aead_id in HPKE.AEAD:
                if aead_id == HPKE.AEAD.EXPORT_ONLY:
                    continue
                self.round_trip(curve, aead_id)

    def test_psk(self):
        aead_id = HPKE.AEAD.AES128_GCM
        HPKE.new(receiver_key=self.key1.public_key(), aead_id=aead_id, psk=(b"a", b"c" * 32))

    def test_info(self):
        aead_id = HPKE.AEAD.AES128_GCM
        HPKE.new(receiver_key=self.key1.public_key(), aead_id=aead_id, info=b"baba")

    def test_neg_unsupported_curve(self):
        key3 = ECC.generate(curve="p224")
        with pytest.raises(ValueError) as cm:
            HPKE.new(receiver_key=key3.public_key(), aead_id=HPKE.AEAD.AES128_GCM)
        assert "Unsupported curve" in str(cm.value)

    def test_neg_too_many_private_keys(self):
        with pytest.raises(ValueError) as cm:
            HPKE.new(receiver_key=self.key1, sender_key=self.key2, aead_id=HPKE.AEAD.AES128_GCM)
        assert "Exactly 1 private key" in str(cm.value)

    def test_neg_curve_mismatch(self):
        key3 = ECC.generate(curve="p384")
        with pytest.raises(ValueError) as cm:
            HPKE.new(receiver_key=self.key1.public_key(), sender_key=key3, aead_id=HPKE.AEAD.AES128_GCM)
        assert "but recipient key" in str(cm.value)

    def test_neg_psk(self):
        with pytest.raises(ValueError) as cm:
            HPKE.new(receiver_key=self.key1.public_key(), psk=(b"", b"G" * 32), aead_id=HPKE.AEAD.AES128_GCM)

        with pytest.raises(ValueError) as cm:
            HPKE.new(receiver_key=self.key1.public_key(), psk=(b"JJJ", b""), aead_id=HPKE.AEAD.AES128_GCM)

        with pytest.raises(ValueError) as cm:
            HPKE.new(
                receiver_key=self.key1.public_key(), psk=(b"JJJ", b"Y" * 31), aead_id=HPKE.AEAD.AES128_GCM
            )
        assert "at least 32" in str(cm.value)

    def test_neg_wrong_enc(self):
        wrong_enc = b"\xff" + b"8" * 64
        with pytest.raises(DeserializeError):
            HPKE.new(receiver_key=self.key1, aead_id=HPKE.AEAD.AES128_GCM, enc=wrong_enc)

        with pytest.raises(ValueError) as cm:
            HPKE.new(
                receiver_key=self.key1.public_key(),
                enc=self.key1.public_key().export_key(format="raw"),
                aead_id=HPKE.AEAD.AES128_GCM,
            )
        assert "'enc' cannot be an input" in str(cm.value)

        with pytest.raises(ValueError) as cm:
            HPKE.new(receiver_key=self.key1, aead_id=HPKE.AEAD.AES128_GCM)
        assert "'enc' required" in str(cm.value)

    def test_neg_unseal_wrong_ct(self):
        decryptor = HPKE.new(
            receiver_key=self.key1,
            aead_id=HPKE.AEAD.CHACHA20_POLY1305,
            enc=self.key2.public_key().export_key(format="raw"),
        )

        with pytest.raises(ValueError):
            decryptor.unseal(b"XYZ" * 20)

    def test_neg_unseal_no_auth_data(self):
        aead_id = HPKE.AEAD.CHACHA20_POLY1305

        encryptor = HPKE.new(receiver_key=self.key1.public_key(), aead_id=aead_id)

        ct = encryptor.seal(b"ABC", auth_data=b"DEF")

        decryptor = HPKE.new(receiver_key=self.key1, aead_id=aead_id, enc=encryptor.enc)

        with pytest.raises(ValueError):
            decryptor.unseal(ct)

    def test_x25519_mode_0(self):
        # RFC x9180, A.1.1.1, seq 0 and 1

        keyR_hex = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"
        keyR = DH.import_x25519_private_key(bytes.fromhex(keyR_hex))

        pt_hex = "4265617574792069732074727574682c20747275746820626561757479"
        pt = bytes.fromhex(pt_hex)

        ct0_hex = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
        ct0 = bytes.fromhex(ct0_hex)

        enc_hex = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
        enc = bytes.fromhex(enc_hex)

        aad0_hex = "436f756e742d30"
        aad0 = bytes.fromhex(aad0_hex)

        aad1_hex = "436f756e742d31"
        aad1 = bytes.fromhex(aad1_hex)

        info_hex = "4f6465206f6e2061204772656369616e2055726e"
        info = bytes.fromhex(info_hex)

        ct1_hex = "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"
        ct1 = bytes.fromhex(ct1_hex)

        aead_id = HPKE.AEAD.AES128_GCM

        decryptor = HPKE.new(receiver_key=keyR, aead_id=aead_id, info=info, enc=enc)

        pt_X0 = decryptor.unseal(ct0, aad0)
        assert pt_X0 == pt

        pt_X1 = decryptor.unseal(ct1, aad1)
        assert pt_X1 == pt

    def test_x25519_mode_1(self):
        # RFC x9180, A.1.2.1, seq 0 and 1

        keyR_hex = "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd"
        keyR = DH.import_x25519_private_key(bytes.fromhex(keyR_hex))

        psk_id_hex = "456e6e796e20447572696e206172616e204d6f726961"
        psk_id = bytes.fromhex(psk_id_hex)

        psk_hex = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"
        psk = bytes.fromhex(psk_hex)

        pt_hex = "4265617574792069732074727574682c20747275746820626561757479"
        pt = bytes.fromhex(pt_hex)

        ct0_hex = "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea"
        ct0 = bytes.fromhex(ct0_hex)

        enc_hex = "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b"
        enc = bytes.fromhex(enc_hex)

        aad0_hex = "436f756e742d30"
        aad0 = bytes.fromhex(aad0_hex)

        aad1_hex = "436f756e742d31"
        aad1 = bytes.fromhex(aad1_hex)

        info_hex = "4f6465206f6e2061204772656369616e2055726e"
        info = bytes.fromhex(info_hex)

        ct1_hex = "49f3b19b28a9ea9f43e8c71204c00d4a490ee7f61387b6719db765e948123b45b61633ef059ba22cd62437c8ba"
        ct1 = bytes.fromhex(ct1_hex)

        aead_id = HPKE.AEAD.AES128_GCM

        decryptor = HPKE.new(receiver_key=keyR, aead_id=aead_id, info=info, psk=(psk_id, psk), enc=enc)

        pt_X0 = decryptor.unseal(ct0, aad0)
        assert pt_X0 == pt

        pt_X1 = decryptor.unseal(ct1, aad1)
        assert pt_X1 == pt

    def test_x25519_mode_2(self):
        # RFC x9180, A.1.3.1, seq 0 and 1

        keyR_hex = "fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e"
        keyR = DH.import_x25519_private_key(bytes.fromhex(keyR_hex))

        keyS_hex = "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd"
        keyS = DH.import_x25519_private_key(bytes.fromhex(keyS_hex))

        pt_hex = "4265617574792069732074727574682c20747275746820626561757479"
        pt = bytes.fromhex(pt_hex)

        ct0_hex = "5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e21b680c141b"
        ct0 = bytes.fromhex(ct0_hex)

        enc_hex = "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76"
        enc = bytes.fromhex(enc_hex)

        aad0_hex = "436f756e742d30"
        aad0 = bytes.fromhex(aad0_hex)

        aad1_hex = "436f756e742d31"
        aad1 = bytes.fromhex(aad1_hex)

        info_hex = "4f6465206f6e2061204772656369616e2055726e"
        info = bytes.fromhex(info_hex)

        ct1_hex = "d3736bb256c19bfa93d79e8f80b7971262cb7c887e35c26370cfed62254369a1b52e3d505b79dd699f002bc8ed"
        ct1 = bytes.fromhex(ct1_hex)

        aead_id = HPKE.AEAD.AES128_GCM

        decryptor = HPKE.new(
            receiver_key=keyR, sender_key=keyS.public_key(), aead_id=aead_id, info=info, enc=enc
        )

        pt_X0 = decryptor.unseal(ct0, aad0)
        assert pt_X0 == pt

        pt_X1 = decryptor.unseal(ct1, aad1)
        assert pt_X1 == pt

    def test_x25519_mode_3(self):
        # RFC x9180, A.1.4.1, seq 0 and 1

        keyR_hex = "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423"
        keyR = DH.import_x25519_private_key(bytes.fromhex(keyR_hex))

        keyS_hex = "fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4"
        keyS = DH.import_x25519_private_key(bytes.fromhex(keyS_hex))

        psk_id_hex = "456e6e796e20447572696e206172616e204d6f726961"
        psk_id = bytes.fromhex(psk_id_hex)

        psk_hex = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"
        psk = bytes.fromhex(psk_hex)

        pt_hex = "4265617574792069732074727574682c20747275746820626561757479"
        pt = bytes.fromhex(pt_hex)

        ct0_hex = "a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40f27e45e141a24001697737533e"
        ct0 = bytes.fromhex(ct0_hex)

        enc_hex = "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c"
        enc = bytes.fromhex(enc_hex)

        aad0_hex = "436f756e742d30"
        aad0 = bytes.fromhex(aad0_hex)

        aad1_hex = "436f756e742d31"
        aad1 = bytes.fromhex(aad1_hex)

        info_hex = "4f6465206f6e2061204772656369616e2055726e"
        info = bytes.fromhex(info_hex)

        ct1_hex = "4d19303b848f424fc3c3beca249b2c6de0a34083b8e909b6aa4c3688505c05ffe0c8f57a0a4c5ab9da127435d9"
        ct1 = bytes.fromhex(ct1_hex)

        aead_id = HPKE.AEAD.AES128_GCM

        decryptor = HPKE.new(
            receiver_key=keyR,
            sender_key=keyS.public_key(),
            aead_id=aead_id,
            psk=(psk_id, psk),
            info=info,
            enc=enc,
        )

        pt_X0 = decryptor.unseal(ct0, aad0)
        assert pt_X0 == pt

        pt_X1 = decryptor.unseal(ct1, aad1)
        assert pt_X1 == pt

    def test_x25519_export_only_mode_0(self):
        # RFC 9180, A.7.1

        keyR_hex = "33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848"
        keyR = DH.import_x25519_private_key(bytes.fromhex(keyR_hex))

        enc_hex = "e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918"
        enc = bytes.fromhex(enc_hex)

        info_hex = "4f6465206f6e2061204772656369616e2055726e"
        info = bytes.fromhex(info_hex)

        decryptor = HPKE.new(receiver_key=keyR, aead_id=HPKE.AEAD.EXPORT_ONLY, info=info, enc=enc)

        assert decryptor.export(b"", 32) == bytes.fromhex(
            "7a36221bd56d50fb51ee65edfd98d06a23c4dc87085aa5866cb7087244bd2a36"
        )
        assert decryptor.export(b"\x00", 32) == bytes.fromhex(
            "d5535b87099c6c3ce80dc112a2671c6ec8e811a2f284f948cec6dd1708ee33f0"
        )
        assert decryptor.export(b"TestContext", 32) == bytes.fromhex(
            "ffaabc85a776136ca0c378e5d084c9140ab552b78f039d2e8775f26efff4c70e"
        )

    def test_integer_aead_id(self):
        keyR_hex = "33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848"
        keyR = DH.import_x25519_private_key(bytes.fromhex(keyR_hex))

        enc_hex = "e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918"
        enc = bytes.fromhex(enc_hex)

        info_hex = "4f6465206f6e2061204772656369616e2055726e"
        info = bytes.fromhex(info_hex)

        decryptor = HPKE.new(receiver_key=keyR, aead_id=0xFFFF, info=info, enc=enc)

        assert decryptor.export(b"", 32) == bytes.fromhex(
            "7a36221bd56d50fb51ee65edfd98d06a23c4dc87085aa5866cb7087244bd2a36"
        )

    def test_neg_export_only_cannot_seal_or_unseal(self):
        keyR = ECC.generate(curve="p256")

        encryptor = HPKE.new(receiver_key=keyR.public_key(), aead_id=HPKE.AEAD.EXPORT_ONLY)

        with pytest.raises(ValueError, match="export-only"):
            encryptor.seal(b"ABC")

        decryptor = HPKE.new(receiver_key=keyR, aead_id=HPKE.AEAD.EXPORT_ONLY, enc=encryptor.enc)

        with pytest.raises(ValueError, match="export-only"):
            decryptor.unseal(b"ABC")


# We support only one KDF per curve
_supported_kdf = {
    (0x10, 0x1): SHA256,
    (0x11, 0x2): SHA384,
    (0x12, 0x3): SHA512,
    (0x20, 0x1): SHA256,
    (0x21, 0x3): SHA512,
}


def _load_test_vectors():
    try:
        import pycryptodome_test_vectors  # type: ignore
    except ImportError:
        return []

    init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
    full_file_name = os.path.join(init_dir, "Protocol", "wycheproof", "HPKE-test-vectors.json")
    with open(full_file_name) as f:
        vectors = json.load(f)

    return [
        pytest.param(vector, id="%d-kem%x-aead%x" % (idx, vector["kem_id"], vector["aead_id"]))
        for idx, vector in enumerate(vectors)
        if (vector["kem_id"], vector["kdf_id"]) in _supported_kdf
    ]


def import_private_key(key_hex, kem_id):
    key_bin = unhexlify(key_hex)
    if kem_id == 0x0010:
        return ECC.construct(curve="p256", d=int.from_bytes(key_bin, byteorder="big"))
    elif kem_id == 0x0011:
        return ECC.construct(curve="p384", d=int.from_bytes(key_bin, byteorder="big"))
    elif kem_id == 0x0012:
        return ECC.construct(curve="p521", d=int.from_bytes(key_bin, byteorder="big"))
    elif kem_id == 0x0020:
        return DH.import_x25519_private_key(key_bin)
    elif kem_id == 0x0021:
        return DH.import_x448_private_key(key_bin)


@pytest.mark.slow
class TestHPKE_TestVectors:
    test_vectors = _load_test_vectors()

    @pytest.mark.parametrize("vector", test_vectors)
    def test_hpke_encap(self, vector):
        """Test HPKE encapsulation using test vectors."""

        kem_id = vector["kem_id"]
        hashmod = _supported_kdf[(kem_id, vector["kdf_id"])]

        receiver_pub = import_private_key(vector["skRm"], kem_id).public_key()

        sender_priv = None
        if "skSm" in vector:
            sender_priv = import_private_key(vector["skSm"], kem_id)

        encap_key = import_private_key(vector["skEm"], kem_id)

        shared_secret, enc = HPKE.HPKE_Cipher._encap(receiver_pub, kem_id, hashmod, sender_priv, encap_key)
        assert enc.hex() == vector["enc"]
        assert shared_secret == unhexlify(vector["shared_secret"])

    @pytest.mark.parametrize("vector", test_vectors)
    def test_hpke_unseal(self, vector):
        """Test HPKE decryption and secret export using test vectors."""

        kem_id = vector["kem_id"]
        receiver_priv = import_private_key(vector["skRm"], kem_id)

        sender_pub = None
        if "skSm" in vector:
            sender_priv = import_private_key(vector["skSm"], kem_id)
            sender_pub = sender_priv.public_key()

        encap_key = unhexlify(vector["enc"])

        psk = None
        if "psk_id" in vector:
            psk = unhexlify(vector["psk_id"]), unhexlify(vector["psk"])

        receiver_hpke = HPKE.new(
            receiver_key=receiver_priv,
            aead_id=HPKE.AEAD(vector["aead_id"]),
            enc=encap_key,
            sender_key=sender_pub,
            psk=psk,
            info=unhexlify(vector["info"]),
        )

        for encryption in vector["encryptions"]:
            plaintext = unhexlify(encryption["pt"])
            ciphertext = unhexlify(encryption["ct"])
            aad = unhexlify(encryption["aad"])

            # Decrypt (unseal)
            decrypted = receiver_hpke.unseal(ciphertext, aad)
            assert decrypted == plaintext, "Decryption failed"

        for export in vector["exports"]:
            exported = receiver_hpke.export(unhexlify(export["exporter_context"]), export["L"])
            assert exported == unhexlify(export["exported_value"])


# The KEMs of draft-ietf-hpke-pq: module, parameter set, KEM ID, and length of enc
_PQ_KEMS = {
    0x0040: (MLKEM, MLKEM.ML_KEM_512, 768),
    0x0041: (MLKEM, MLKEM.ML_KEM_768, 1088),
    0x0042: (MLKEM, MLKEM.ML_KEM_1024, 1568),
    0x647A: (Hybrid, Hybrid.MLKEM768_X25519, 1120),
}


def _import_pq_key(kem_id, seed=None, pub=None):
    """A PQ private key (from its seed) or public key (from its encoding)"""
    module, param_set, _ = _PQ_KEMS[kem_id]
    if module is MLKEM:
        return MLKEM.construct(param_set=param_set, seed=seed, ek=pub)
    return Hybrid._construct(param_set=param_set, seed=seed, pk=pub)


# The KDF implied by each KEM
_PQ_KDF = {
    0x0040: 0x0001,
    0x0041: 0x0001,
    0x0042: 0x0002,
    0x647A: 0x0001,
}


@pytest.fixture(params=list(_PQ_KEMS), ids=lambda kem_id: "kem%x" % kem_id)
def pq_key(request):
    module, param_set, _ = _PQ_KEMS[request.param]
    return request.param, module.generate(param_set=param_set)


class TestHPKE_PQ:
    """HPKE with ML-KEM and with the hybrid KEMs (draft-ietf-hpke-pq)"""

    @pytest.mark.parametrize("aead_id", [a for a in HPKE.AEAD if a != HPKE.AEAD.EXPORT_ONLY])
    def test_round_trip(self, pq_key, aead_id):
        kem_id, key = pq_key

        encryptor = HPKE.new(receiver_key=key.public_key(), aead_id=aead_id)
        assert len(encryptor.enc) == _PQ_KEMS[kem_id][2]
        assert encryptor._kem_id == kem_id
        assert encryptor._kdf_id == _PQ_KDF[kem_id]

        ct = encryptor.seal(b"ABC", auth_data=b"DEF")
        ct2 = encryptor.seal(b"GHI")

        decryptor = HPKE.new(receiver_key=key, aead_id=aead_id, enc=encryptor.enc)
        assert decryptor.unseal(ct, auth_data=b"DEF") == b"ABC"
        assert decryptor.unseal(ct2) == b"GHI"

        # A new encapsulation each time
        assert HPKE.new(receiver_key=key.public_key(), aead_id=aead_id).enc != encryptor.enc

    def test_psk_info_export(self, pq_key):
        _, key = pq_key
        psk = (b"id", b"s" * 32)

        encryptor = HPKE.new(
            receiver_key=key.public_key(), aead_id=HPKE.AEAD.EXPORT_ONLY, psk=psk, info=b"info"
        )
        decryptor = HPKE.new(
            receiver_key=key, aead_id=HPKE.AEAD.EXPORT_ONLY, enc=encryptor.enc, psk=psk, info=b"info"
        )
        assert encryptor.export(b"ctx", 40) == decryptor.export(b"ctx", 40)

        # Another info: another secret
        decryptor2 = HPKE.new(receiver_key=key, aead_id=HPKE.AEAD.EXPORT_ONLY, enc=encryptor.enc, psk=psk)
        assert encryptor.export(b"ctx", 40) != decryptor2.export(b"ctx", 40)

    def test_neg_auth_mode(self, pq_key):
        _, key = pq_key
        sender = ECC.generate(curve="p256")

        # The PQ and hybrid KEMs have no AuthEncap/AuthDecap
        with pytest.raises(ValueError) as cm:
            HPKE.new(receiver_key=key.public_key(), sender_key=sender, aead_id=HPKE.AEAD.AES128_GCM)
        assert "authenticated modes" in str(cm.value)

        # Nor can the receiver be ECC and the sender ML-KEM
        with pytest.raises(TypeError):
            HPKE.new(receiver_key=sender.public_key(), sender_key=key, aead_id=HPKE.AEAD.AES128_GCM)

    def test_neg_wrong_enc(self, pq_key):
        kem_id, key = pq_key
        enc = HPKE.new(receiver_key=key.public_key(), aead_id=HPKE.AEAD.AES128_GCM).enc

        for bad_enc in (enc[:-1], enc + b"\x00", b""):
            with pytest.raises(DeserializeError):
                HPKE.new(receiver_key=key, aead_id=HPKE.AEAD.AES128_GCM, enc=bad_enc)

        # An invalid ECDH point
        if _PQ_KEMS[kem_id][0] is Hybrid:
            bad_enc = enc[:-32] + bytes(32)
            with pytest.raises(DeserializeError):
                HPKE.new(receiver_key=key, aead_id=HPKE.AEAD.AES128_GCM, enc=bad_enc)

    def test_neg_wrong_key(self, pq_key):
        kem_id, key = pq_key
        module, param_set, _ = _PQ_KEMS[kem_id]
        encryptor = HPKE.new(receiver_key=key.public_key(), aead_id=HPKE.AEAD.AES128_GCM)
        ct = encryptor.seal(b"ABC")

        # Another key: implicit rejection of ML-KEM, then the tag is wrong
        other = module.generate(param_set=param_set)
        decryptor = HPKE.new(receiver_key=other, aead_id=HPKE.AEAD.AES128_GCM, enc=encryptor.enc)
        with pytest.raises(ValueError):
            decryptor.unseal(ct)

        # A modified enc (ML-KEM part)
        bad_enc = bytearray(encryptor.enc)
        bad_enc[0] ^= 1
        decryptor = HPKE.new(receiver_key=key, aead_id=HPKE.AEAD.AES128_GCM, enc=bytes(bad_enc))
        with pytest.raises(ValueError):
            decryptor.unseal(ct)

    def test_neg_key_type(self):
        with pytest.raises(TypeError):
            HPKE.new(receiver_key=b"key", aead_id=HPKE.AEAD.AES128_GCM)


def _load_pq_test_vectors():
    try:
        import pycryptodome_test_vectors  # type: ignore
    except ImportError:
        return [pytest.param(None, id="missing", marks=pytest.mark.skip(reason="Missing test vectors"))]

    init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
    full_file_name = os.path.join(init_dir, "Protocol", "wycheproof", "HPKE-PQ-test-vectors.json")
    try:
        with open(full_file_name) as f:
            vectors = json.load(f)
    except FileNotFoundError:
        return [
            pytest.param(
                None, id="missing", marks=pytest.mark.skip(reason="Missing HPKE-PQ-test-vectors.json")
            )
        ]

    # Only the KEMs of draft-ietf-hpke-pq that we support (not MLKEM768-P256 and
    # MLKEM1024-P384), and the KDF that HPKE uses for them:
    # the one-stage KDFs (SHAKE and TurboSHAKE) are not supported
    return [
        pytest.param(
            vector, id="%d-kem%x-kdf%x-aead%x" % (idx, vector["kem_id"], vector["kdf_id"], vector["aead_id"])
        )
        for idx, vector in enumerate(vectors)
        if _PQ_KDF.get(vector["kem_id"]) == vector["kdf_id"]
    ]


class TestHPKE_PQ_TestVectors:
    """The test vectors of draft-ietf-hpke-pq"""

    test_vectors = _load_pq_test_vectors()

    @pytest.mark.parametrize("vector", test_vectors)
    def test_hpke_encap(self, vector):
        # skRm is the seed format of the private key; ikmR is not used
        # because DeriveKeyPair (draft-ietf-hpke-pq, Sections 3 and 4) is not implemented
        receiver_priv = _import_pq_key(vector["kem_id"], seed=unhexlify(vector["skRm"]))
        receiver_pub = _import_pq_key(vector["kem_id"], pub=unhexlify(vector["pkRm"]))
        assert receiver_priv.public_key() == receiver_pub

        # ikmE is the randomness of the encapsulation
        shared_secret, enc = HPKE.HPKE_Cipher._encap_pq(receiver_pub, unhexlify(vector["ikmE"]))
        assert enc == unhexlify(vector["enc"])
        assert shared_secret == unhexlify(vector["shared_secret"])

    @pytest.mark.parametrize("vector", test_vectors)
    def test_hpke_unseal(self, vector):
        receiver_priv = _import_pq_key(vector["kem_id"], seed=unhexlify(vector["skRm"]))

        assert vector["mode"] == HPKE.MODE.BASE
        receiver_hpke = HPKE.new(
            receiver_key=receiver_priv,
            aead_id=HPKE.AEAD(vector["aead_id"]),
            enc=unhexlify(vector["enc"]),
            info=unhexlify(vector["info"]),
        )
        assert receiver_hpke._key == unhexlify(vector["key"])
        assert receiver_hpke._base_nonce == unhexlify(vector["base_nonce"])
        assert receiver_hpke._export_secret == unhexlify(vector["exporter_secret"])

        for encryption in vector["encryptions"]:
            decrypted = receiver_hpke.unseal(unhexlify(encryption["ct"]), unhexlify(encryption["aad"]))
            assert decrypted == unhexlify(encryption["pt"])

        for export in vector["exports"]:
            exported = receiver_hpke.export(unhexlify(export["exporter_context"]), export["L"])
            assert exported == unhexlify(export["exported_value"])
