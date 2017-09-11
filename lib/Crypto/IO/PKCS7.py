#
#  PublicKey/PKCS7.py : PKCS#7 functions
#
# ===================================================================
#
# Copyright (c) 2017, Christoph Egger <egger@cs.fau.de>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

from Crypto.Util.asn1 import BerSequence, DerObjectId, BerObject, DerSetOf, DerSequence, DerOctetString, DerNull, DerObject
from Crypto.Util.py3compat import *
from Crypto.Cipher import PKCS1_v1_5, AES

#__all__ = ['import_message', 'PKCS7', ]


from pprint import pprint

def myhexlify(bstring):
    return " ".join(["%02x" % b for b in bstring])


## AlgorithmIdentifier ::= SEQUENCE {
##   algorithm       OBJECT IDENTIFIER,
##   parameters      ANY OPTIONAL
## }
class Algorithm(object):
    def decode_parameters(self):
        pass


    def decode(self, original_message):
        self._algorithmIdentifier = DerSequence().decode(original_message)
        self._algorithm = DerObjectId().decode(self._algorithmIdentifier[0])
        self.decode_parameters()
        return self


    def encode(self):
        pass


    def decrypt(self, key, message):
        pass



class AlgorithmAesGcm(Algorithm):
    def decode_parameters(self):
        self._parameters = DerSequence().decode(self._algorithmIdentifier[1])
        self._nonce = DerOctetString().decode(self._parameters[0])
        self._ivlen = self._parameters[1]


    def decrypt(self, key, message):
        aes = AES.new(key, AES.MODE_GCM, nonce=self._nonce.payload)
        return aes.decrypt(message)



class AlgorithmAesCbc(Algorithm):
    def __init__(self, **kwargs):
        if not len(kwargs) == 0:
            self._iv = kwargs['iv']
        else:
            self._iv = None


    def decode_parameters(self):
        self._iv = DerOctetString().decode(self._algorithmIdentifier[1]).payload


    def encode(self):
        return DerSequence([
            self.oid,
            DerOctetString(value=self._iv)
        ])


    def decrypt(self, key, message):
        aes = AES.new(key, AES.MODE_CBC, iv=self._iv)
        return aes.decrypt(message)


    def encrypt(self, key, message):
        aes = AES.new(key, AES.MODE_CBC, iv=self._iv)
        print(repr(message))
        result = aes.encrypt(message)
        print("AES", result)
        return result


    @property
    def oid(self):
        return DerObjectId('2.16.840.1.101.3.4.1.2')



class AlgorithmRsaEncryption(Algorithm):
    def decode_parameters(self):
        self._parameters = DerNull().decode(self._algorithmIdentifier[1])


    def decrypt(self, key, message):
        pkcs1 = PKCS1_v1_5.new(key)
        return pkcs1.decrypt(message, b'\0\0\0\0')


    def encrypt(self, key, message):
        pkcs1 = PKCS1_v1_5.new(key)
        return pkcs1.encrypt(message)


    def encode(self):
        return DerSequence([
            self.oid,
            DerNull()
        ])


    @property
    def oid(self):
        return DerObjectId('1.2.840.113549.1.1.1')



class PKCS7(object):
    """ Represents The (Encrypted) Content Info structure from PKCS7"""
    def __init__(self, encrypted=False):
        self._encrypted = encrypted


    def decode_content(self):
        pass


    def decode(self, original_message, encrypted=False):
        self._encrypted = encrypted
        self._contentInfo = BerSequence().decode(original_message)
        self._contentType = DerObjectId().decode(self._contentInfo[0])
        if encrypted == True:
            self._algorithm = import_algorithm(self._contentInfo[1])
            self._content = BerObject().decode(self._contentInfo[2])
        else:
            self._content = BerObject().decode(self._contentInfo[1])

        self.decode_content()
        return self


    def encode(self):
        seq = []
        seq.append(self.oid)

        if self._encrypted:
            print("Why, oh why!")
            seq.append(self._algorithm.encode())

        seq.append(self.encode_content().encode())

        asn1 = DerSequence(seq)
        return asn1.encode()


    def encode_content(self):
        pass


class PKCS7Data(PKCS7):
    def __init__(self, **kwargs):
        PKCS7.__init__(self, **kwargs)
        self._key = b'\0' * 16
        self._data = b'a'



    def _pad(self, original_message):
        length = 16 - len(original_message) % 16
        print("LENGTH", length)
        return original_message + bchr(length) * length


    def set_data(self, data):
        self._data = data


    @property
    def data(self):
        return self._data


    def decode_content(self):
        length = self._content.payload[1]
        print(length) # hack, needs proper BER support for a clean solution
        self._data = DerOctetString().decode(self._content.payload[:length + 2]).payload
        print(myhexlify(self._data))


    def encode_content(self):
        self.encrypt()
#        return self._ciphertext
#        self._ciphertext = self._algorithm.encrypt(self._key, self._data)
#        print(DerObject(asn1Id=0x0, payload=self._ciphertext, implicit=0, constructed=False).encode())
        return DerObject(asn1Id=0x0, payload=self._ciphertext, implicit=0, constructed=False)


    def encrypt(self):
        self._ciphertext = self._algorithm.encrypt(self._key, self._pad(self._data))


    @property
    def oid(self):
        return DerObjectId('1.2.840.113549.1.7.1')


class PKCS7SignedData(PKCS7):
    pass


class PKCS7EnvelopedData(PKCS7):
    def __init__(self):
        self._recipients = set()
        self._encrypted = False
        self._encryptedContentInfo = PKCS7Data(encrypted=True)
        self._encryptedContentInfo._algorithm = AlgorithmAesCbc(iv=b'\0' * 16)


    def set_key(self, key):
        self._key = key


    def _unpad(self, original_message):
        length = original_message[-1]
        padding = original_message[len(original_message) - length:]
        message = original_message[:len(original_message) - length]

        if padding != original_message[-1:] * length:
            print("Error", message[-1:] * length)
            return None

        return message


    def decode_recipient_infos(self):
        for sequence in self._recipientInfos:

            recinfo = DerSequence().decode(sequence)
            assert(recinfo[0] == 0) #RFC 2315 only has Version 0 for RecipientInfo
            info = dict()
            info['encryptedKey'] = DerOctetString().decode(recinfo[3])
            info['keyEncryptionAlgorithm'] = import_algorithm(recinfo[2])

            info['contentKey'] = info['keyEncryptionAlgorithm'].decrypt(self._key, info['encryptedKey'].payload)
            self._info = info


    def encode_recipient_infos(self):
        encoded_infos = set()
        encoded_infos.add(
            DerSequence([
                0,
                DerSequence([
                    DerSequence([
                        DerSetOf([
                            DerSequence([
                                DerObjectId('2.5.4.3'),
                                DerObject(asn1Id=0x13, payload=b"TEST")
                            ])
                        ])
                    ]),
                    1337
                ]),
                AlgorithmRsaEncryption().encode(),
                DerOctetString(value=AlgorithmRsaEncryption().encrypt(self._key, b'\0' * 16))
            ])
        )
        return DerSetOf(encoded_infos)


    def decode_content(self):
        envelopedData = BerSequence().decode(self._content.payload)

        # RFC 2315 only has Version 0 for EnvelopedData
        assert(envelopedData[0] == 0)
        self._recipientInfos = DerSetOf().decode(envelopedData[1])
        self._encryptedContentInfo = PKCS7Data().decode(envelopedData[2], True)


    def decrypt(self):
        self.decode_recipient_infos()
        plaintext = self._encryptedContentInfo._algorithm.decrypt(self._info['contentKey'], self._encryptedContentInfo.data)
        return self._unpad(plaintext)


    def encode_content(self):
        self._encryptedContentInfo.encrypt()
        content = DerSequence(implicit=0)
        content.append(DerSequence([
            0,
            self.encode_recipient_infos(),
            self._encryptedContentInfo.encode()
        ]))
        return content



    @property
    def oid(self):
        return DerObjectId('1.2.840.113549.1.7.3')



class PKCS7SignedAndEnvelopedData(PKCS7):
    pass


class PKCS7DigestedData(PKCS7):
    pass


class PKCS7EncryptedData(PKCS7):
    pass





def import_algorithm(external_message):
    algorithm = Algorithm().decode(external_message)
    identifier = tuple(algorithm._algorithm.value.split('.'))
    if identifier[:7] == ('2', '16', '840', '1', '101', '3', '4'): #NIST Algorithms
        if identifier[7:] == ('1', '6'): # AES 128 GCM
            return AlgorithmAesGcm().decode(external_message)
        elif identifier[7:] == ('1', '2'): # AES 128 CBC
            return AlgorithmAesCbc().decode(external_message)

    if identifier[:5] == ('1', '2', '840', '113549', '1'): # PKCS
        if identifier[5:] == ('1', '1'):
            return AlgorithmRsaEncryption().decode(external_message)

    print(identifier)


def import_message(external_message):
    pkcs = PKCS7().decode(external_message)
    identifier = pkcs._contentType.value

    if not identifier.startswith('1.2.840.113549.1.7.'):
        print("not a PKCS.7 structure")
        return

    identifier = identifier.split('.')
    if not len(identifier) == 7:
        print("strange identifier, too long")
        return


    print(repr(identifier[6]))
    if int(identifier[6]) == 3:
        return PKCS7EnvelopedData().decode(external_message)
