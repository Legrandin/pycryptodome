# -*- coding: utf-8 -*-
#
#  SelfTest/PublicKey/test_import_DSA.py: Self-test for importing DSA keys
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

import unittest

from Crypto.PublicKey import DSA
from Crypto.SelfTest.st_common import *
from Crypto.Util.py3compat import *

from binascii import unhexlify

class ImportKeyTests(unittest.TestCase):

    y = 92137165128186062214622779787483327510946462589285775188003362705875131352591574106484271700740858696583623951844732128165434284507709057439633739849986759064015013893156866539696757799934634945787496920169462601722830899660681779448742875054459716726855443681559131362852474817534616736104831095601710736729L
    p = 162452170958135306109773853318304545923250830605675936228618290525164105310663722368377131295055868997377338797580997938253236213714988311430600065853662861806894003694743806769284131194035848116051021923956699231855223389086646903420682639786976554552864568460372266462812137447840653688476258666833303658691L
    q = 988791743931120302950649732173330531512663554851L
    g = 85583152299197514738065570254868711517748965097380456700369348466136657764813442044039878840094809620913085570225318356734366886985903212775602770761953571967834823306046501307810937486758039063386311593890777319935391363872375452381836756832784184928202587843258855704771836753434368484556809100537243908232L
    x = 540873410045082450874416847965843801027716145253L

    def setUp(self):

        # It is easier to write test vectors in text form,
        # and convert them to byte strigs dynamically here
        for mname, mvalue in ImportKeyTests.__dict__.items():
            if mname[:4] in ('der_', 'pem_', 'ssh_'):
                if mname[:4] == 'der_':
                    mvalue = unhexlify(tobytes(mvalue))
                mvalue = tobytes(mvalue)
                setattr(self, mname, mvalue)

    # 1. SubjectPublicKeyInfo
    der_public=\
    '308201b73082012b06072a8648ce3804013082011e02818100e756ee1717f4b6'+\
    '794c7c214724a19763742c45572b4b3f8ff3b44f3be9f44ce039a2757695ec91'+\
    '5697da74ef914fcd1b05660e2419c761d639f45d2d79b802dbd23e7ab8b81b47'+\
    '9a380e1f30932584ba2a0b955032342ebc83cb5ca906e7b0d7cd6fe656cecb4c'+\
    '8b5a77123a8c6750a481e3b06057aff6aa6eba620b832d60c3021500ad32f48c'+\
    'd3ae0c45a198a61fa4b5e20320763b2302818079dfdc3d614fe635fceb7eaeae'+\
    '3718dc2efefb45282993ac6749dc83c223d8c1887296316b3b0b54466cf444f3'+\
    '4b82e3554d0b90a778faaf1306f025dae6a3e36c7f93dd5bac4052b92370040a'+\
    'ca70b8d5820599711900efbc961812c355dd9beffe0981da85c5548074b41c56'+\
    'ae43fd300d89262e4efd89943f99a651b03888038185000281810083352a69a1'+\
    '32f34843d2a0eb995bff4e2f083a73f0049d2c91ea2f0ce43d144abda48199e4'+\
    'b003c570a8af83303d45105f606c5c48d925a40ed9c2630c2fa4cdbf838539de'+\
    'b9a29f919085f2046369f627ca84b2cb1e2c7940564b670f963ab1164d4e2ca2'+\
    'bf6ffd39f12f548928bf4d2d1b5e6980b4f1be4c92a91986fba559'

    def testImportKey1(self):
        key_obj = self.dsa.importKey(self.der_public)
        self.failIf(key_obj.has_private())
        self.assertEqual(self.y, key_obj.key.y)
        self.assertEqual(self.p, key_obj.key.p)
        self.assertEqual(self.q, key_obj.key.q)
        self.assertEqual(self.g, key_obj.key.g)

    def testExportKey1(self):
        tup = (self.y, self.g, self.p, self.q)
        key = self.dsa.construct(tup)
        encoded = key.exportKey('DER')
        self.assertEqual(self.der_public, encoded)

    # 2.
    pem_public="""\
-----BEGIN DSA PUBLIC KEY-----
MIIBtzCCASsGByqGSM44BAEwggEeAoGBAOdW7hcX9LZ5THwhRyShl2N0LEVXK0s/
j/O0Tzvp9EzgOaJ1dpXskVaX2nTvkU/NGwVmDiQZx2HWOfRdLXm4AtvSPnq4uBtH
mjgOHzCTJYS6KguVUDI0LryDy1ypBuew181v5lbOy0yLWncSOoxnUKSB47BgV6/2
qm66YguDLWDDAhUArTL0jNOuDEWhmKYfpLXiAyB2OyMCgYB539w9YU/mNfzrfq6u
NxjcLv77RSgpk6xnSdyDwiPYwYhyljFrOwtURmz0RPNLguNVTQuQp3j6rxMG8CXa
5qPjbH+T3VusQFK5I3AECspwuNWCBZlxGQDvvJYYEsNV3Zvv/gmB2oXFVIB0tBxW
rkP9MA2JJi5O/YmUP5mmUbA4iAOBhQACgYEAgzUqaaEy80hD0qDrmVv/Ti8IOnPw
BJ0skeovDOQ9FEq9pIGZ5LADxXCor4MwPUUQX2BsXEjZJaQO2cJjDC+kzb+DhTne
uaKfkZCF8gRjafYnyoSyyx4seUBWS2cPljqxFk1OLKK/b/058S9UiSi/TS0bXmmA
tPG+TJKpGYb7pVk=
-----END DSA PUBLIC KEY-----"""

    def testImportKey2(self):
        for pem in (self.pem_public, tostr(self.pem_public)):
            key_obj = self.dsa.importKey(pem)
            self.failIf(key_obj.has_private())
            self.assertEqual(self.y, key_obj.key.y)
            self.assertEqual(self.p, key_obj.key.p)
            self.assertEqual(self.q, key_obj.key.q)
            self.assertEqual(self.g, key_obj.key.g)

    def testExportKey2(self):
        tup = (self.y, self.g, self.p, self.q)
        key = self.dsa.construct(tup)
        encoded = key.exportKey('PEM')
        self.assertEqual(self.pem_public, encoded)

    # 3. OpenSSL/OpenSSH format
    der_private=\
    '308201bb02010002818100e756ee1717f4b6794c7c214724a19763742c45572b'+\
    '4b3f8ff3b44f3be9f44ce039a2757695ec915697da74ef914fcd1b05660e2419'+\
    'c761d639f45d2d79b802dbd23e7ab8b81b479a380e1f30932584ba2a0b955032'+\
    '342ebc83cb5ca906e7b0d7cd6fe656cecb4c8b5a77123a8c6750a481e3b06057'+\
    'aff6aa6eba620b832d60c3021500ad32f48cd3ae0c45a198a61fa4b5e2032076'+\
    '3b2302818079dfdc3d614fe635fceb7eaeae3718dc2efefb45282993ac6749dc'+\
    '83c223d8c1887296316b3b0b54466cf444f34b82e3554d0b90a778faaf1306f0'+\
    '25dae6a3e36c7f93dd5bac4052b92370040aca70b8d5820599711900efbc9618'+\
    '12c355dd9beffe0981da85c5548074b41c56ae43fd300d89262e4efd89943f99'+\
    'a651b038880281810083352a69a132f34843d2a0eb995bff4e2f083a73f0049d'+\
    '2c91ea2f0ce43d144abda48199e4b003c570a8af83303d45105f606c5c48d925'+\
    'a40ed9c2630c2fa4cdbf838539deb9a29f919085f2046369f627ca84b2cb1e2c'+\
    '7940564b670f963ab1164d4e2ca2bf6ffd39f12f548928bf4d2d1b5e6980b4f1'+\
    'be4c92a91986fba55902145ebd9a3f0b82069d98420986b314215025756065'

    def testImportKey3(self):
        key_obj = self.dsa.importKey(self.der_private)
        self.failUnless(key_obj.has_private())
        self.assertEqual(self.y, key_obj.key.y)
        self.assertEqual(self.p, key_obj.key.p)
        self.assertEqual(self.q, key_obj.key.q)
        self.assertEqual(self.g, key_obj.key.g)
        self.assertEqual(self.x, key_obj.key.x)

    def testExportKey3(self):
        tup = (self.y, self.g, self.p, self.q, self.x)
        key = self.dsa.construct(tup)
        encoded = key.exportKey('DER', pkcs8=False)
        self.assertEqual(self.der_private, encoded)

    # 4.
    pem_private="""\
-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDnVu4XF/S2eUx8IUckoZdjdCxFVytLP4/ztE876fRM4DmidXaV
7JFWl9p075FPzRsFZg4kGcdh1jn0XS15uALb0j56uLgbR5o4Dh8wkyWEuioLlVAy
NC68g8tcqQbnsNfNb+ZWzstMi1p3EjqMZ1CkgeOwYFev9qpuumILgy1gwwIVAK0y
9IzTrgxFoZimH6S14gMgdjsjAoGAed/cPWFP5jX8636urjcY3C7++0UoKZOsZ0nc
g8Ij2MGIcpYxazsLVEZs9ETzS4LjVU0LkKd4+q8TBvAl2uaj42x/k91brEBSuSNw
BArKcLjVggWZcRkA77yWGBLDVd2b7/4JgdqFxVSAdLQcVq5D/TANiSYuTv2JlD+Z
plGwOIgCgYEAgzUqaaEy80hD0qDrmVv/Ti8IOnPwBJ0skeovDOQ9FEq9pIGZ5LAD
xXCor4MwPUUQX2BsXEjZJaQO2cJjDC+kzb+DhTneuaKfkZCF8gRjafYnyoSyyx4s
eUBWS2cPljqxFk1OLKK/b/058S9UiSi/TS0bXmmAtPG+TJKpGYb7pVkCFF69mj8L
ggadmEIJhrMUIVAldWBl
-----END DSA PRIVATE KEY-----"""

    def testImportKey4(self):
        for pem in (self.pem_private, tostr(self.pem_private)):
            key_obj = self.dsa.importKey(pem)
            self.failUnless(key_obj.has_private())
            self.assertEqual(self.y, key_obj.key.y)
            self.assertEqual(self.p, key_obj.key.p)
            self.assertEqual(self.q, key_obj.key.q)
            self.assertEqual(self.g, key_obj.key.g)
            self.assertEqual(self.x, key_obj.key.x)

    def testExportKey4(self):
        tup = (self.y, self.g, self.p, self.q, self.x)
        key = self.dsa.construct(tup)
        encoded = key.exportKey('PEM', pkcs8=False)
        self.assertEqual(self.pem_private, encoded)

    # 5. PKCS8 (unencrypted)
    der_pkcs8=\
    '3082014a0201003082012b06072a8648ce3804013082011e02818100e756ee17'+\
    '17f4b6794c7c214724a19763742c45572b4b3f8ff3b44f3be9f44ce039a27576'+\
    '95ec915697da74ef914fcd1b05660e2419c761d639f45d2d79b802dbd23e7ab8'+\
    'b81b479a380e1f30932584ba2a0b955032342ebc83cb5ca906e7b0d7cd6fe656'+\
    'cecb4c8b5a77123a8c6750a481e3b06057aff6aa6eba620b832d60c3021500ad'+\
    '32f48cd3ae0c45a198a61fa4b5e20320763b2302818079dfdc3d614fe635fceb'+\
    '7eaeae3718dc2efefb45282993ac6749dc83c223d8c1887296316b3b0b54466c'+\
    'f444f34b82e3554d0b90a778faaf1306f025dae6a3e36c7f93dd5bac4052b923'+\
    '70040aca70b8d5820599711900efbc961812c355dd9beffe0981da85c5548074'+\
    'b41c56ae43fd300d89262e4efd89943f99a651b03888041602145ebd9a3f0b82'+\
    '069d98420986b314215025756065'

    def testImportKey5(self):
        key_obj = self.dsa.importKey(self.der_pkcs8)
        self.failUnless(key_obj.has_private())
        self.assertEqual(self.y, key_obj.key.y)
        self.assertEqual(self.p, key_obj.key.p)
        self.assertEqual(self.q, key_obj.key.q)
        self.assertEqual(self.g, key_obj.key.g)
        self.assertEqual(self.x, key_obj.key.x)

    def testExportKey5(self):
        tup = (self.y, self.g, self.p, self.q, self.x)
        key = self.dsa.construct(tup)
        encoded = key.exportKey('DER')
        self.assertEqual(self.der_pkcs8, encoded)
        encoded = key.exportKey('DER', pkcs8=True)
        self.assertEqual(self.der_pkcs8, encoded)

    # 6.
    pem_pkcs8="""\
-----BEGIN PRIVATE KEY-----
MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAOdW7hcX9LZ5THwhRyShl2N0LEVX
K0s/j/O0Tzvp9EzgOaJ1dpXskVaX2nTvkU/NGwVmDiQZx2HWOfRdLXm4AtvSPnq4
uBtHmjgOHzCTJYS6KguVUDI0LryDy1ypBuew181v5lbOy0yLWncSOoxnUKSB47Bg
V6/2qm66YguDLWDDAhUArTL0jNOuDEWhmKYfpLXiAyB2OyMCgYB539w9YU/mNfzr
fq6uNxjcLv77RSgpk6xnSdyDwiPYwYhyljFrOwtURmz0RPNLguNVTQuQp3j6rxMG
8CXa5qPjbH+T3VusQFK5I3AECspwuNWCBZlxGQDvvJYYEsNV3Zvv/gmB2oXFVIB0
tBxWrkP9MA2JJi5O/YmUP5mmUbA4iAQWAhRevZo/C4IGnZhCCYazFCFQJXVgZQ==
-----END PRIVATE KEY-----"""

    def testImportKey6(self):
        for pem in (self.pem_pkcs8, tostr(self.pem_pkcs8)):
            key_obj = self.dsa.importKey(pem)
            self.failUnless(key_obj.has_private())
            self.assertEqual(self.y, key_obj.key.y)
            self.assertEqual(self.p, key_obj.key.p)
            self.assertEqual(self.q, key_obj.key.q)
            self.assertEqual(self.g, key_obj.key.g)
            self.assertEqual(self.x, key_obj.key.x)

    def testExportKey6(self):
        tup = (self.y, self.g, self.p, self.q, self.x)
        key = self.dsa.construct(tup)
        encoded = key.exportKey('PEM')
        self.assertEqual(self.pem_pkcs8, encoded)
        encoded = key.exportKey('PEM', pkcs8=True)
        self.assertEqual(self.pem_pkcs8, encoded)

    # 7. OpenSSH/RFC4253
    ssh_pub="""ssh-dss AAAAB3NzaC1kc3MAAACBAOdW7hcX9LZ5THwhRyShl2N0LEVXK0s/j/O0Tzvp9EzgOaJ1dpXskVaX2nTvkU/NGwVmDiQZx2HWOfRdLXm4AtvSPnq4uBtHmjgOHzCTJYS6KguVUDI0LryDy1ypBuew181v5lbOy0yLWncSOoxnUKSB47BgV6/2qm66YguDLWDDAAAAFQCtMvSM064MRaGYph+kteIDIHY7IwAAAIB539w9YU/mNfzrfq6uNxjcLv77RSgpk6xnSdyDwiPYwYhyljFrOwtURmz0RPNLguNVTQuQp3j6rxMG8CXa5qPjbH+T3VusQFK5I3AECspwuNWCBZlxGQDvvJYYEsNV3Zvv/gmB2oXFVIB0tBxWrkP9MA2JJi5O/YmUP5mmUbA4iAAAAIEAgzUqaaEy80hD0qDrmVv/Ti8IOnPwBJ0skeovDOQ9FEq9pIGZ5LADxXCor4MwPUUQX2BsXEjZJaQO2cJjDC+kzb+DhTneuaKfkZCF8gRjafYnyoSyyx4seUBWS2cPljqxFk1OLKK/b/058S9UiSi/TS0bXmmAtPG+TJKpGYb7pVk="""

    def testImportKey7(self):
        for ssh in (self.ssh_pub, tostr(self.ssh_pub)):
            key_obj = self.dsa.importKey(ssh)
            self.failIf(key_obj.has_private())
            self.assertEqual(self.y, key_obj.key.y)
            self.assertEqual(self.p, key_obj.key.p)
            self.assertEqual(self.q, key_obj.key.q)
            self.assertEqual(self.g, key_obj.key.g)

    def testExportKey7(self):
        tup = (self.y, self.g, self.p, self.q)
        key = self.dsa.construct(tup)
        encoded = key.exportKey('OpenSSH')
        self.assertEqual(self.ssh_pub, encoded)

    # 8. Encrypted OpenSSL/OpenSSH
    pem_private_encrypted="""\
-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,70B6908939D65E9F2EB999E8729788CE

4V6GHRDpCrdZ8MBjbyp5AlGUrjvr2Pn2e2zVxy5RBt4FBj9/pa0ae0nnyUPMLSUU
kKyOR0topRYTVRLElm4qVrb5uNZ3hRwfbklr+pSrB7O9eHz9V5sfOQxyODS07JxK
k1OdOs70/ouMXLF9EWfAZOmWUccZKHNblUwg1p1UrZIz5jXw4dUE/zqhvXh6d+iC
ADsICaBCjCrRQJKDp50h3+ndQjkYBKVH+pj8TiQ79U7lAvdp3+iMghQN6YXs9mdI
gFpWw/f97oWM4GHZFqHJ+VSMNFjBiFhAvYV587d7Lk4dhD8sCfbxj42PnfRgUItc
nnPqHxmhMQozBWzYM4mQuo3XbF2WlsNFbOzFVyGhw1Bx1s91qvXBVWJh2ozrW0s6
HYDV7ZkcTml/4kjA/d+mve6LZ8kuuR1qCiZx6rkffhh1gDN/1Xz3HVvIy/dQ+h9s
5zp7PwUoWbhqp3WCOr156P6gR8qo7OlT6wMh33FSXK/mxikHK136fV2shwTKQVII
rJBvXpj8nACUmi7scKuTWGeUoXa+dwTZVVe+b+L2U1ZM7+h/neTJiXn7u99PFUwu
xVJtxaV37m3aXxtCsPnbBg==
-----END DSA PRIVATE KEY-----"""

    def testImportKey8(self):
        for pem in (self.pem_private_encrypted, tostr(self.pem_private_encrypted)):
            key_obj = self.dsa.importKey(pem, "PWDTEST")
            self.failUnless(key_obj.has_private())
            self.assertEqual(self.y, key_obj.key.y)
            self.assertEqual(self.p, key_obj.key.p)
            self.assertEqual(self.q, key_obj.key.q)
            self.assertEqual(self.g, key_obj.key.g)
            self.assertEqual(self.x, key_obj.key.x)

    def testExportKey8(self):
        tup = (self.y, self.g, self.p, self.q, self.x)
        key = self.dsa.construct(tup)
        encoded = key.exportKey('PEM', pkcs8=False, passphrase="PWDTEST")
        key = self.dsa.importKey(encoded, "PWDTEST")
        self.assertEqual(self.y, key.key.y)
        self.assertEqual(self.p, key.key.p)
        self.assertEqual(self.q, key.key.q)
        self.assertEqual(self.g, key.key.g)
        self.assertEqual(self.x, key.key.x)

    # 9. Encrypted PKCS8
    # pbeWithMD5AndDES-CBC
    pem_pkcs8_encrypted="""\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBcTAbBgkqhkiG9w0BBQMwDgQI0GC3BJ/jSw8CAggABIIBUHc1cXZpExIE9tC7
7ryiW+5ihtF2Ekurq3e408GYSAu5smJjN2bvQXmzRFBz8W38K8eMf1sbWroZ4+zn
kZSbb9nSm5kAa8lR2+oF2k+WRswMR/PTC3f/D9STO2X0QxdrzKgIHEcSGSHp5jTx
aVvbkCDHo9vhBTl6S3ogZ48As/MEro76+9igUwJ1jNhIQZPJ7e20QH5qDpQFFJN4
CKl2ENSEuwGiqBszItFy4dqH0g63ZGZV/xt9wSO9Rd7SK/EbA/dklOxBa5Y/VItM
gnIhs9XDMoGYyn6F023EicNJm6g/bVQk81BTTma4tm+12TKGdYm+QkeZvCOMZylr
Wv67cKwO3cAXt5C3QXMDgYR64XvuaT5h7C0igMp2afSXJlnbHEbFxQVJlv83T4FM
eZ4k+NQDbEL8GiHmFxzDWQAuPPZKJWEEEV2p/To+WOh+kSDHQw==
-----END ENCRYPTED PRIVATE KEY-----"""

    def testImportKey9(self):
        for pem in (self.pem_pkcs8_encrypted, tostr(self.pem_pkcs8_encrypted)):
            key_obj = self.dsa.importKey(pem, "PWDTEST")
            self.failUnless(key_obj.has_private())
            self.assertEqual(self.y, key_obj.key.y)
            self.assertEqual(self.p, key_obj.key.p)
            self.assertEqual(self.q, key_obj.key.q)
            self.assertEqual(self.g, key_obj.key.g)
            self.assertEqual(self.x, key_obj.key.x)

    # 10. Encrypted PKCS8
    # pkcs5PBES2 /
    # pkcs5PBKDF2 (rounds=1000, salt=D725BF1B6B8239F4) /
    # des-EDE3-CBC (iv=27A1C66C42AFEECE)
    #
    der_pkcs8_encrypted=\
    '30820196304006092a864886f70d01050d3033301b06092a864886f70d01050c'+\
    '300e0408d725bf1b6b8239f4020203e8301406082a864886f70d0307040827a1'+\
    'c66c42afeece048201505cacfde7bf8edabb3e0d387950dc872662ea7e9b1ed4'+\
    '400d2e7e6186284b64668d8d0328c33a9d9397e6f03df7cb68268b0a06b4e22f'+\
    '7d132821449ecf998a8b696dbc6dd2b19e66d7eb2edfeb4153c1771d49702395'+\
    '4f36072868b5fcccf93413a5ac4b2eb47d4b3f681c6bd67ae363ed776f45ae47'+\
    '174a00098a7c930a50f820b227ddf50f9742d8e950d02586ff2dac0e3c372248'+\
    'e5f9b6a7a02f4004f20c87913e0f7b52bccc209b95d478256a890b31d4c9adec'+\
    '21a4d157a179a93a3dad06f94f3ce486b46dfa7fc15fd852dd7680bbb2f17478'+\
    '7e71bd8dbaf81eca7518d76c1d26256e95424864ba45ca5d47d7c5a421be02fa'+\
    'b94ab01e18593f66cf9094eb5c94b9ecf3aa08b854a195cf87612fbe5e96c426'+\
    '2b0d573e52dc71ba3f5e468c601e816c49b7d32c698b22175e89aaef0c443770'+\
    '5ef2f88a116d99d8e2869a4fd09a771b84b49e4ccb79aadcb1c9'

    def testImportKey10(self):
        key_obj = self.dsa.importKey(self.der_pkcs8_encrypted, "PWDTEST")
        self.failUnless(key_obj.has_private())
        self.assertEqual(self.y, key_obj.key.y)
        self.assertEqual(self.p, key_obj.key.p)
        self.assertEqual(self.q, key_obj.key.q)
        self.assertEqual(self.g, key_obj.key.g)
        self.assertEqual(self.x, key_obj.key.x)

    def testExportKey10(self):
        tup = (self.y, self.g, self.p, self.q, self.x)
        key = self.dsa.construct(tup)
        randfunc = BytesIO(unhexlify(b("27A1C66C42AFEECE") + b("D725BF1B6B8239F4"))).read
        key._randfunc = randfunc
        encoded = key.exportKey('DER', pkcs8=True, passphrase="PWDTEST")
        self.assertEqual(self.der_pkcs8_encrypted, encoded)

    # ----

    def testImportError1(self):
        self.assertRaises(ValueError, self.dsa.importKey, self.der_pkcs8_encrypted, "wrongpwd")

    def testExportError2(self):
        tup = (self.y, self.g, self.p, self.q, self.x)
        key = self.dsa.construct(tup)
        self.assertRaises(ValueError, key.exportKey, 'DER', pkcs8=False, passphrase="PWDTEST")

class ImportKeyTestsSlow(ImportKeyTests):
    def setUp(self):
        ImportKeyTests.setUp(self)
        self.dsa = DSA.DSAImplementation(use_fast_math=0)

class ImportKeyTestsFast(ImportKeyTests):
    def setUp(self):
        ImportKeyTests.setUp(self)
        self.dsa = DSA.DSAImplementation(use_fast_math=1)

if __name__ == '__main__':
    unittest.main()

def get_tests(config={}):
    tests = []
    try:
        from Crypto.PublicKey import _fastmath
        tests += list_test_cases(ImportKeyTestsFast)
    except ImportError:
        pass
    tests += list_test_cases(ImportKeyTestsSlow)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

