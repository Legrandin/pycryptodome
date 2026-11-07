# SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from binascii import unhexlify

import pytest

from Crypto import MessageTooLongError
from Crypto.Cipher import AES, _mode_gcm_siv
from Crypto.Cipher._mode_gcm import _GHASH, _ghash_clmul, _ghash_portable
from Crypto.Cipher._mode_gcm_siv import _mul_x_ghash, _Polyval
from Crypto.Hash import SHAKE128
from Crypto.SelfTest.loader import load_test_vectors_wycheproof, wycheproof_id
from Crypto.Util._bytes import tobytes

MODE = AES.MODE_GCM_SIV

KEY_128 = bytes(range(16))
KEY_256 = bytes(range(32))
NONCE = bytes(range(12))

GHASH_IMPLS = [_ghash_portable] + ([_ghash_clmul] if _ghash_clmul else [])
BACKENDS = [
    {"use_aesni": use_aesni, "use_clmul": use_clmul}
    for use_aesni in (True, False)
    for use_clmul in (True, False)
]


def get_tag_random(tag, length):
    return SHAKE128.new(data=tobytes(tag)).read(length)


class TestPolyval:
    # RFC 8452, Appendix A
    h = unhexlify("25629347589242761d31f826ba4b757b")
    x1 = unhexlify("4f4f95668c83dfb6401762bb2d01a262")
    x2 = unhexlify("d1a24ddd2721d006bbe45f20d3c9f362")
    polyval = unhexlify("f7a3b47b846119fae5b7866cf5e5b77e")
    ghash = unhexlify("bd9b3997046731fb96251b91f9c99d7a")

    def test_mul_x_ghash(self):
        assert _mul_x_ghash(self.h[::-1]) == unhexlify("dcbaa5dd137c188ebb21492c23c9b112")

    @pytest.mark.parametrize("impl", GHASH_IMPLS)
    def test_ghash_of_appendix_a(self, impl):
        # The example gives the GHASH with H, of the same blocks
        assert _GHASH(self.h, impl).update(self.x1 + self.x2).digest() == self.ghash

    @pytest.mark.parametrize("impl", GHASH_IMPLS)
    def test_polyval(self, impl):
        polyval = _Polyval(self.h, impl)
        polyval.update(self.x1 + self.x2)
        assert polyval.digest() == self.polyval

    @pytest.mark.parametrize("cut", range(33))
    def test_split_input(self, cut):
        data = self.x1 + self.x2
        polyval = _Polyval(self.h, _ghash_portable)
        polyval.update(data[:cut])
        polyval.update(data[cut:])
        assert polyval.digest() == self.polyval

    def test_small_pieces_of_input(self):
        polyval = _Polyval(self.h, _ghash_portable)
        for i in range(32):
            polyval.update((self.x1 + self.x2)[i : i + 1])
        assert polyval.digest() == self.polyval

    def test_pad(self):
        polyval1 = _Polyval(self.h, _ghash_portable)
        polyval1.update(b"\x11" * 5)
        polyval1.pad()
        polyval1.pad()

        polyval2 = _Polyval(self.h, _ghash_portable)
        polyval2.update(b"\x11" * 5 + bytes(11))

        assert polyval1.digest() == polyval2.digest()

    @pytest.mark.parametrize("impl", GHASH_IMPLS)
    @pytest.mark.parametrize("blocks", [0, 1, 3, 4, 5, 7, 8, 9, 16, 17, 100])
    def test_against_ghash_of_reversed_blocks(self, impl, blocks):
        # The definition in Appendix A, with the blocks reversed here
        data = get_tag_random("polyval", blocks * 16)
        reversed_blocks = b"".join(data[i : i + 16][::-1] for i in range(0, len(data), 16))
        ghash = _GHASH(_mul_x_ghash(self.h[::-1]), impl).update(reversed_blocks).digest()

        polyval = _Polyval(self.h, impl)
        polyval.update(data)
        assert polyval.digest() == ghash[::-1]

    @pytest.mark.parametrize("impl", GHASH_IMPLS)
    @pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview])
    def test_buffer_types(self, impl, wrap):
        polyval = _Polyval(self.h, impl)
        polyval.update(wrap(self.x1 + self.x2))
        assert polyval.digest() == self.polyval

    @pytest.mark.parametrize("impl", GHASH_IMPLS)
    @pytest.mark.parametrize("threads", [2, 3])
    def test_threads(self, impl, threads):
        # Enough data for GHASH to really use the threads, with any implementation
        data = get_tag_random("polyval", 2 * 1024 * 1024 * threads + 16 * 5)

        polyval1 = _Polyval(self.h, impl)
        polyval1.update(data)
        polyval2 = _Polyval(self.h, impl, threads)
        polyval2.update(data)
        assert polyval1.digest() == polyval2.digest()

    def test_no_side_effect_on_ghash(self):
        # The same object type still computes plain GHASH by default
        plain = _GHASH(self.h, _ghash_portable).update(self.x1 + self.x2).digest()
        rev = _GHASH(self.h, _ghash_portable, reversed_blocks=True).update(self.x1 + self.x2).digest()
        assert plain == self.ghash
        assert rev != plain


# RFC 8452, Appendix C (K: key, N: nonce, A: associated data,
# P: plaintext, R: result, which is the ciphertext with the tag)
RFC8452_VECTORS = """
K=01000000000000000000000000000000
N=030000000000000000000000
A=
P=
R=dc20e2d83f25705bb49e439eca56de25

K=01000000000000000000000000000000
N=030000000000000000000000
A=
P=0100000000000000
R=b5d839330ac7b786578782fff6013b815b287c22493a364c

K=01000000000000000000000000000000
N=030000000000000000000000
A=
P=010000000000000000000000
R=7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639

K=01000000000000000000000000000000
N=030000000000000000000000
A=
P=01000000000000000000000000000000
R=743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4

K=01000000000000000000000000000000
N=030000000000000000000000
A=
P=0100000000000000000000000000000002000000000000000000000000000000
R=84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667cd86847bf6155ff

K=01000000000000000000000000000000
N=030000000000000000000000
A=
P=010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000
R=3fd24ce1f5a67b75bf2351f181a475c7b800a5b4d3dcf70106b1eea82fa1d64df42bf7226122fa92e17a40eeaac1201b5e6e311dbf395d35b0fe39c2714388f8

K=01000000000000000000000000000000
N=030000000000000000000000
A=
P=01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000
R=2433668f1058190f6d43e360f4f35cd8e475127cfca7028ea8ab5c20f7ab2af02516a2bdcbc08d521be37ff28c152bba36697f25b4cd169c6590d1dd39566d3f8a263dd317aa88d56bdf3936dba75bb8

K=01000000000000000000000000000000
N=030000000000000000000000
A=01
P=0200000000000000
R=1e6daba35669f4273b0a1a2560969cdf790d99759abd1508

K=01000000000000000000000000000000
N=030000000000000000000000
A=01
P=020000000000000000000000
R=296c7889fd99f41917f4462008299c5102745aaa3a0c469fad9e075a

K=01000000000000000000000000000000
N=030000000000000000000000
A=01
P=02000000000000000000000000000000
R=e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f

K=01000000000000000000000000000000
N=030000000000000000000000
A=01
P=0200000000000000000000000000000003000000000000000000000000000000
R=620048ef3c1e73e57e02bb8562c416a319e73e4caac8e96a1ecb2933145a1d71e6af6a7f87287da059a71684ed3498e1

K=01000000000000000000000000000000
N=030000000000000000000000
A=01
P=020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000
R=50c8303ea93925d64090d07bd109dfd9515a5a33431019c17d93465999a8b0053201d723120a8562b838cdff25bf9d1e6a8cc3865f76897c2e4b245cf31c51f2

K=01000000000000000000000000000000
N=030000000000000000000000
A=01
P=02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000
R=2f5c64059db55ee0fb847ed513003746aca4e61c711b5de2e7a77ffd02da42feec601910d3467bb8b36ebbaebce5fba30d36c95f48a3e7980f0e7ac299332a80cdc46ae475563de037001ef84ae21744

K=01000000000000000000000000000000
N=030000000000000000000000
A=010000000000000000000000
P=02000000
R=a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14

K=01000000000000000000000000000000
N=030000000000000000000000
A=010000000000000000000000000000000200
P=0300000000000000000000000000000004000000
R=6bb0fecf5ded9b77f902c7d5da236a4391dd029724afc9805e976f451e6d87f6fe106514

K=01000000000000000000000000000000
N=030000000000000000000000
A=0100000000000000000000000000000002000000
P=030000000000000000000000000000000400
R=44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13b9fd

K=e66021d5eb8e4f4066d4adb9c33560e4
N=f46e44bb3da0015c94f70887
A=
P=
R=a4194b79071b01a87d65f706e3949578

K=36864200e0eaf5284d884a0e77d31646
N=bae8e37fc83441b16034566b
A=46bb91c3c5
P=7a806c
R=af60eb711bd85bc1e4d3e0a462e074eea428a8

K=aedb64a6c590bc84d1a5e269e4b47801
N=afc0577e34699b9e671fdd4f
A=fc880c94a95198874296
P=bdc66f146545
R=bb93a3e34d3cd6a9c45545cfc11f03ad743dba20f966

K=d5cc1fd161320b6920ce07787f86743b
N=275d1ab32f6d1f0434d8848c
A=046787f3ea22c127aaf195d1894728
P=1177441f195495860f
R=4f37281f7ad12949d01d02fd0cd174c84fc5dae2f60f52fd2b

K=b3fed1473c528b8426a582995929a149
N=9e9ad8780c8d63d0ab4149c0
A=c9882e5386fd9f92ec489c8fde2be2cf97e74e93
P=9f572c614b4745914474e7c7
R=f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0

K=2d4ed87da44102952ef94b02b805249b
N=ac80e6f61455bfac8308a2d4
A=2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a
P=0d8c8451178082355c9e940fea2f58
R=c9ff545e07b88a015f05b274540aa183b3449b9f39552de99dc214a1190b0b

K=bde3b2f204d1e9f8b06bc47f9745b3d1
N=ae06556fb6aa7890bebc18fe
A=1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f
P=6b3db4da3d57aa94842b9803a96e07fb6de7
R=6298b296e24e8cc35dce0bed484b7f30d5803e377094f04709f64d7b985310a4db84

K=f901cfe8a69615a93fdf7a98cad48179
N=6245709fb18853f68d833640
A=7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21
P=e42a3c02c25b64869e146d7b233987bddfc240871d
R=391cc328d484a4f46406181bcd62efd9b3ee197d052d15506c84a9edd65e13e9d24a2a6e70

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=
P=
R=07f5f4169bbf55a8400cd47ea6fd400f

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=
P=0100000000000000
R=c2ef328e5c71c83b843122130f7364b761e0b97427e3df28

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=
P=010000000000000000000000
R=9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=
P=01000000000000000000000000000000
R=85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=
P=0100000000000000000000000000000002000000000000000000000000000000
R=4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=
P=010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000
R=c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e39cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=
P=01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000
R=c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=01
P=0200000000000000
R=1de22967237a813291213f267e3b452f02d01ae33e4ec854

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=01
P=020000000000000000000000
R=163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=01
P=02000000000000000000000000000000
R=c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=01
P=0200000000000000000000000000000003000000000000000000000000000000
R=07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e1965604374aab96dbbc

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=01
P=020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000
R=c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=01
P=02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000
R=67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc98cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c895bde0285037c5de81e5b570a049b62a0

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=010000000000000000000000
P=02000000
R=22b3f4cd1835e517741dfddccfa07fa4661b74cf

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=010000000000000000000000000000000200
P=0300000000000000000000000000000004000000
R=43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59cabfe307

K=0100000000000000000000000000000000000000000000000000000000000000
N=030000000000000000000000
A=0100000000000000000000000000000002000000
P=030000000000000000000000000000000400
R=462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543

K=e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200
N=e0eaf5284d884a0e77d31646
A=
P=
R=169fbb2fbf389a995f6390af22228a62

K=bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269
N=e4b47801afc0577e34699b9e
A=4fbdc66f14
P=671fdd
R=0eaccb93da9bb81333aee0c785b240d319719d

K=6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3
N=2f6d1f0434d8848c1177441f
A=6787f3ea22c127aaf195
P=195495860f04
R=a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c

K=d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0
N=9f572c614b4745914474e7c7
A=489c8fde2be2cf97e74e932d4ed87d
P=c9882e5386fd9f92ec
R=0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2

K=a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235
N=5c9e940fea2f582950a70d5a
A=0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f
P=1db2316fd568378da107b52b
R=8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5

K=9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb
N=6de71860f762ebfbd08284e4
A=f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f
P=21702de0de18baa9c9596291b08466
R=793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd

K=b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7
N=028ec6eb5ea7e298342a94d4
A=9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7
P=b202b370ef9768ec6561c4fe6b7e7296fa85
R=857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d0a49

K=3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23
N=688089e55540db1872504e1c
A=734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541
P=ced532ce4159b035277d4dfbb7db62968b13cd4eec
R=626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594

K=0000000000000000000000000000000000000000000000000000000000000000
N=000000000000000000000000
A=
P=000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108
R=f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3eaffffffff000000000000000000000000

K=0000000000000000000000000000000000000000000000000000000000000000
N=000000000000000000000000
A=
P=eb3640277c7ffd1303c7a542d02d3e4c0000000000000000
R=18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff000000000000000000000000
"""


def load_rfc8452_vectors():
    result = []
    for text in RFC8452_VECTORS.strip().split("\n\n"):
        fields = dict(line.split("=") for line in text.split("\n"))
        result.append({name: unhexlify(value) for name, value in fields.items()})
    return result


rfc8452_vectors = load_rfc8452_vectors()


class TestRFC8452:
    def test_number_of_vectors(self):
        # C.1, C.2 and C.3
        assert len(rfc8452_vectors) == 24 + 24 + 2

    @pytest.mark.parametrize("backend", BACKENDS, ids=str)
    @pytest.mark.parametrize("tv", rfc8452_vectors)
    def test_encrypt(self, tv, backend):
        cipher = AES.new(tv["K"], MODE, nonce=tv["N"], **backend)
        cipher.update(tv["A"])
        ct, tag = cipher.encrypt_and_digest(tv["P"])
        assert ct + tag == tv["R"]

    @pytest.mark.parametrize("backend", BACKENDS, ids=str)
    @pytest.mark.parametrize("tv", rfc8452_vectors)
    def test_decrypt(self, tv, backend):
        cipher = AES.new(tv["K"], MODE, nonce=tv["N"], **backend)
        cipher.update(tv["A"])
        assert cipher.decrypt_and_verify(tv["R"][:-16], tv["R"][-16:]) == tv["P"]


def load_wycheproof_vectors():
    return load_test_vectors_wycheproof(
        ("Cipher", "wycheproof"), "aes_gcm_siv_test.json", "Wycheproof AES-GCM-SIV"
    )


class TestWycheproof:
    @pytest.mark.parametrize("tv", load_wycheproof_vectors(), ids=wycheproof_id)
    def test_encrypt(self, tv):
        cipher = AES.new(tv.key, MODE, nonce=tv.iv)
        cipher.update(tv.aad)
        ct, tag = cipher.encrypt_and_digest(tv.msg)
        if tv.valid:
            assert ct == tv.ct
            assert tag == tv.tag
        else:
            assert tag != tv.tag

    @pytest.mark.parametrize("tv", load_wycheproof_vectors(), ids=wycheproof_id)
    def test_decrypt(self, tv):
        cipher = AES.new(tv.key, MODE, nonce=tv.iv)
        cipher.update(tv.aad)
        if tv.valid:
            assert cipher.decrypt_and_verify(tv.ct, tv.tag) == tv.msg
        else:
            with pytest.raises(ValueError):
                cipher.decrypt_and_verify(tv.ct, tv.tag)


class TestGcmSiv:
    data = get_tag_random("data", 128)

    @pytest.mark.parametrize("key", [KEY_128, KEY_256])
    @pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 33, 128, 1000])
    def test_loopback(self, key, length):
        pt = get_tag_random("plaintext", length)

        cipher = AES.new(key, MODE, nonce=NONCE)
        cipher.update(self.data)
        ct, tag = cipher.encrypt_and_digest(pt)
        assert len(ct) == length
        assert len(tag) == 16

        cipher = AES.new(key, MODE, nonce=NONCE)
        cipher.update(self.data)
        assert cipher.decrypt_and_verify(ct, tag) == pt

    def test_positional_nonce(self):
        cipher1 = AES.new(KEY_128, MODE, NONCE)
        cipher2 = AES.new(KEY_128, MODE, nonce=NONCE)
        assert cipher1.encrypt_and_digest(self.data) == cipher2.encrypt_and_digest(self.data)

    def test_positional_too_many(self):
        with pytest.raises(TypeError):
            AES.new(KEY_128, MODE, NONCE, b"")

    def test_random_nonce(self):
        cipher1 = AES.new(KEY_128, MODE)
        cipher2 = AES.new(KEY_128, MODE)
        assert len(cipher1.nonce) == 12
        assert cipher1.nonce != cipher2.nonce

    def test_nonce_attribute(self):
        assert AES.new(KEY_128, MODE, nonce=bytearray(NONCE)).nonce == NONCE

    def test_nonce_reuse_only_reveals_identical_messages(self):
        ct1, tag1 = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)
        ct2, tag2 = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)
        assert (ct1, tag1) == (ct2, tag2)

        # The key stream depends on the message
        other = b"\x01" + self.data[1:]
        ct3, tag3 = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(other)
        assert tag3 != tag1
        assert ct3[1:] != ct1[1:]

    @pytest.mark.parametrize("nonce", [b"", bytes(11), bytes(13), bytes(16)])
    def test_nonce_length(self, nonce):
        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=nonce)

    @pytest.mark.parametrize("nonce", ["test12345678", 12])
    def test_nonce_type(self, nonce):
        with pytest.raises(TypeError):
            AES.new(KEY_128, MODE, nonce=nonce)

    @pytest.mark.parametrize("length", [0, 15, 17, 24, 33, 48, 64])
    def test_key_length(self, length):
        # In particular, AES-192 is not part of RFC 8452
        with pytest.raises(ValueError):
            AES.new(bytes(length), MODE, nonce=NONCE)

    def test_missing_key(self):
        from Crypto.Cipher._mode_gcm_siv import _create_gcm_siv_cipher

        with pytest.raises(TypeError):
            _create_gcm_siv_cipher(AES, nonce=NONCE)

    @pytest.mark.parametrize("param", ["mac_len", "unknown"])
    def test_unknown_parameters(self, param):
        with pytest.raises(TypeError):
            AES.new(KEY_128, MODE, nonce=NONCE, **{param: 16})

    def test_buffer_types(self):
        expected = AES.new(KEY_128, MODE, nonce=NONCE)
        expected.update(self.data)
        ct, tag = expected.encrypt_and_digest(self.data)

        for wrap in bytearray, memoryview:
            cipher = AES.new(wrap(KEY_128), MODE, nonce=wrap(NONCE))
            cipher.update(wrap(self.data))
            assert cipher.encrypt_and_digest(wrap(self.data)) == (ct, tag)

            cipher = AES.new(wrap(KEY_128), MODE, nonce=wrap(NONCE))
            cipher.update(wrap(self.data))
            assert cipher.decrypt_and_verify(wrap(ct), wrap(tag)) == self.data

    @pytest.mark.parametrize("value", ["text", 16, None])
    def test_wrong_types(self, value):
        for call in (
            lambda c: c.encrypt_and_digest(value),
            lambda c: c.decrypt_and_verify(value, bytes(16)),
            lambda c: c.decrypt_and_verify(b"", value),
            lambda c: c.update(value),
        ):
            with pytest.raises(TypeError):
                call(AES.new(KEY_128, MODE, nonce=NONCE))

    def test_wrong_type_does_not_consume_the_object(self):
        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        with pytest.raises(TypeError):
            cipher.encrypt_and_digest("text")
        assert cipher.encrypt_and_digest(self.data) == AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(
            self.data
        )

    @pytest.mark.parametrize("cut", [0, 1, 15, 16, 17, 64, 127, 128])
    def test_split_associated_data(self, cut):
        cipher1 = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher1.update(self.data)
        cipher2 = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher2.update(self.data[:cut])
        cipher2.update(self.data[cut:])
        assert cipher1.encrypt_and_digest(b"xyz") == cipher2.encrypt_and_digest(b"xyz")

    def test_associated_data_is_not_the_message(self):
        cipher1 = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher1.update(b"abc")
        tag1 = cipher1.encrypt_and_digest(b"")[1]
        tag2 = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(b"abc")[1]
        assert tag1 != tag2

    def test_padding_is_not_ambiguous(self):
        # Same padded input for POLYVAL: only the lengths tell them apart
        tag1 = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(b"\x11")[1]
        tag2 = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(b"\x11" + bytes(15))[1]
        assert tag1 != tag2

    def test_digest_only(self):
        # Without a message, it is the tag of an empty message
        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher.update(self.data)
        tag = cipher.digest()
        assert cipher.digest() == tag
        assert cipher.hexdigest() == tag.hex()

        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher.update(self.data)
        assert cipher.encrypt_and_digest(b"") == (b"", tag)

        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher.update(self.data)
        cipher.verify(tag)
        cipher.hexverify(tag.hex())

        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        with pytest.raises(ValueError):
            cipher.verify(tag)

    def test_digest_after_encryption(self):
        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        tag = cipher.encrypt_and_digest(self.data)[1]
        assert cipher.digest() == tag
        assert cipher.hexdigest() == tag.hex()

    def test_verify_after_decryption(self):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)
        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher.decrypt_and_verify(ct, tag)
        cipher.verify(tag)
        cipher.hexverify(tag.hex())
        with pytest.raises(ValueError):
            cipher.verify(bytes(16))

    def test_invalid_mixing_of_methods(self):
        for call in (
            lambda c: c.update(b""),
            lambda c: c.encrypt_and_digest(b""),
            lambda c: c.decrypt_and_verify(b"", bytes(16)),
            lambda c: c.verify(bytes(16)),
        ):
            cipher = AES.new(KEY_128, MODE, nonce=NONCE)
            cipher.encrypt_and_digest(self.data)
            with pytest.raises(TypeError):
                call(cipher)

        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)
        for call in (
            lambda c: c.update(b""),
            lambda c: c.encrypt_and_digest(b""),
            lambda c: c.decrypt_and_verify(ct, tag),
            lambda c: c.digest(),
        ):
            cipher = AES.new(KEY_128, MODE, nonce=NONCE)
            cipher.decrypt_and_verify(ct, tag)
            with pytest.raises(TypeError):
                call(cipher)

        # After the tag of an empty message, no message can follow
        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher.digest()
        with pytest.raises(TypeError):
            cipher.encrypt_and_digest(self.data)

    def test_no_incremental_processing(self):
        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        with pytest.raises(TypeError):
            cipher.encrypt(self.data)
        with pytest.raises(TypeError):
            cipher.decrypt(self.data)

    def test_modified_message(self):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)

        modified_ct = bytes([ct[0] ^ 1]) + ct[1:]
        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(modified_ct, tag)

        modified_tag = bytes([tag[0] ^ 1]) + tag[1:]
        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(ct, modified_tag)

        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=bytes(12)).decrypt_and_verify(ct, tag)

        with pytest.raises(ValueError):
            AES.new(bytes(16), MODE, nonce=NONCE).decrypt_and_verify(ct, tag)

        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher.update(b"associated")
        with pytest.raises(ValueError):
            cipher.decrypt_and_verify(ct, tag)

    @pytest.mark.parametrize("length", [0, 4, 15, 17, 32])
    def test_wrong_tag_length(self, length):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)
        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(ct, (tag + tag)[:length])

    def test_no_calls_after_failed_verification(self):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)
        empty_tag = AES.new(KEY_128, MODE, nonce=NONCE).digest()

        for wrong_tag in bytes(16), b"short":
            cipher = AES.new(KEY_128, MODE, nonce=NONCE)
            with pytest.raises(ValueError):
                cipher.decrypt_and_verify(ct, wrong_tag)

            # In particular, the tag must not be accepted for another message
            for attempt in tag, empty_tag:
                with pytest.raises(TypeError):
                    cipher.verify(attempt)
            with pytest.raises(TypeError):
                cipher.decrypt_and_verify(ct, tag)


class TestOutput:
    data = get_tag_random("data", 128)

    def test_encrypt(self):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)

        output = bytearray(len(self.data))
        assert AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data, output=output) == (None, tag)
        assert output == ct

        output = memoryview(bytearray(len(self.data)))
        AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data, output=output)
        assert output == ct

    def test_decrypt(self):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)

        output = bytearray(len(ct))
        assert AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(ct, tag, output=output) is None
        assert output == self.data

        output = memoryview(bytearray(len(ct)))
        AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(ct, tag, output=output)
        assert output == self.data

    def test_in_place(self):
        expected_ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)

        buffer = bytearray(self.data)
        AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(buffer, output=buffer)
        assert buffer == expected_ct

        AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(buffer, tag, output=buffer)
        assert buffer == self.data

    def test_tag_in_the_output_buffer(self):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)

        # Ciphertext and tag in one buffer, decrypted in place
        buffer = bytearray(ct + tag)
        view = memoryview(buffer)
        AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(
            view[:-16], view[-16:], output=view[-16 - len(ct) : -16]
        )
        assert buffer[:-16] == self.data

    @pytest.mark.parametrize("wrap", [bytearray, memoryview])
    def test_no_unauthenticated_plaintext(self, wrap):
        ct = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)[0]

        output = wrap(bytearray(b"\xaa" * len(ct)))
        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(ct, bytes(16), output=output)
        assert bytes(output) == bytes(len(ct))

    def test_output_is_untouched_with_a_tag_of_wrong_length(self):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)

        output = bytearray(b"\xaa" * len(ct))
        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(ct, tag[:8], output=output)
        assert output == b"\xaa" * len(ct)

    def test_wrong_output(self):
        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data)

        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data, output=bytearray(1))
        with pytest.raises(ValueError):
            AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(ct, tag, output=bytearray(1))
        with pytest.raises(TypeError):
            AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(self.data, output=bytes(len(ct)))


class TestLongData:
    @pytest.mark.parametrize("threads", [1, 2])
    def test_counter_wraps_around(self, threads):
        # The counter is 1 MiB away from the wrap around, in a message of 4 MiB
        blocks = 4 * 1024 * 1024 // 16
        start = 2**32 - 1024 * 1024 // 16
        tag = start.to_bytes(4, "little") + bytes(range(1, 12)) + b"\x7f"

        ecb = AES.new(KEY_128, AES.MODE_ECB)
        counter_blocks = b"".join(
            ((start + i) % 2**32).to_bytes(4, "little") + tag[4:15] + b"\xff" for i in range(blocks)
        )
        expected = ecb.encrypt(counter_blocks)

        cipher = AES.new(KEY_128, MODE, nonce=NONCE, threads=threads)
        cipher._enc_key = KEY_128
        assert cipher._create_ctr_cipher(tag).encrypt(bytes(blocks * 16)) == expected

    @pytest.mark.parametrize("threads", [2, 3, 0])
    @pytest.mark.parametrize("key", [KEY_128, KEY_256])
    def test_threads(self, threads, key):
        data = get_tag_random("long", 16 * 1024 * 1024 + 5)

        ct, tag = AES.new(key, MODE, nonce=NONCE).encrypt_and_digest(data)

        cipher = AES.new(key, MODE, nonce=NONCE, threads=threads)
        assert cipher.encrypt_and_digest(data) == (ct, tag)

        cipher = AES.new(key, MODE, nonce=NONCE, threads=threads)
        assert cipher.decrypt_and_verify(ct, tag) == data

    @pytest.mark.parametrize("threads", ["1", -1, True])
    def test_wrong_threads(self, threads):
        with pytest.raises((TypeError, ValueError)):
            AES.new(KEY_128, MODE, nonce=NONCE, threads=threads)

    def test_message_limit(self, monkeypatch):
        monkeypatch.setattr(_mode_gcm_siv, "_MAX_MSG_LEN", 16)

        ct, tag = AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(bytes(16))
        assert AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(ct, tag) == bytes(16)

        with pytest.raises(MessageTooLongError):
            AES.new(KEY_128, MODE, nonce=NONCE).encrypt_and_digest(bytes(17))
        with pytest.raises(MessageTooLongError):
            AES.new(KEY_128, MODE, nonce=NONCE).decrypt_and_verify(bytes(17), bytes(16))

    def test_associated_data_limit(self, monkeypatch):
        monkeypatch.setattr(_mode_gcm_siv, "_MAX_AAD_LEN", 16)

        cipher = AES.new(KEY_128, MODE, nonce=NONCE)
        cipher.update(bytes(10))
        cipher.update(bytes(6))
        with pytest.raises(MessageTooLongError):
            cipher.update(bytes(1))

    def test_actual_limits(self):
        assert _mode_gcm_siv._MAX_MSG_LEN == 2**36
        assert _mode_gcm_siv._MAX_AAD_LEN == 2**36
