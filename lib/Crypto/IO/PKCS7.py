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

from Crypto.Util.asn1 import BerSequence, DerObjectId, BerObject, DerSetOf, DerSequence, DerOctetString, DerNull
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
    def decode_parameters(self):
        self._iv = DerOctetString().decode(self._algorithmIdentifier[1])

    def decrypt(self, key, message):
        aes = AES.new(key, AES.MODE_CBC, iv=self._iv.payload)
        return aes.decrypt(message)


class AlgorithmRsaEncryption(Algorithm):
    def decode_parameters(self):
        self._parameters = DerNull().decode(self._algorithmIdentifier[1])


    def decrypt(self, key, message):
        pkcs1 = PKCS1_v1_5.new(key)
        return pkcs1.decrypt(message, b'\0\0\0\0')


class PKCS7(object):
    """ Represents The (Encrypted) Content Info structure from PKCS7"""
    def __init__(self):
        pass


    def decode_content(self):
        pass


    def decode(self, original_message, encrypted=False):
        self._contentInfo = BerSequence().decode(original_message)
        self._contentType = DerObjectId().decode(self._contentInfo[0])
        if encrypted == True:
            self._algorithm = import_algorithm(self._contentInfo[1])
            self._content = BerObject().decode(self._contentInfo[2])
        else:
            self._content = BerObject().decode(self._contentInfo[1])

        self.decode_content()
        return self


class PKCS7Data(PKCS7):
    def decode_content(self):
        length = self._content.payload[1]
        print(length) # hack, needs proper BER support for a clean solution
        self._data = DerOctetString().decode(self._content.payload[:length + 2])
        print(myhexlify(self._content.payload))
        print(myhexlify(self._data.payload))


class PKCS7SignedData(PKCS7):
    pass


class PKCS7EnvelopedData(PKCS7):
    def __init__(self):
        self._recipients = set()



    def set_key(self, key):
        if not key.has_private():
            print("ERROR")

        self._key = key


    def decode_recipient_infos(self):
        for sequence in self._recipientInfos:

            recinfo = DerSequence().decode(sequence)
            assert(recinfo[0] == 0) #RFC 2315 only has Version 0 for RecipientInfo
            info = dict()
            info['encryptedKey'] = DerOctetString().decode(recinfo[3])
            info['keyEncryptionAlgorithm'] = import_algorithm(recinfo[2])

            info['contentKey'] = info['keyEncryptionAlgorithm'].decrypt(self._key, info['encryptedKey'].payload)
            pprint(info)
            self._info = info


    def decode_content(self):
        envelopedData = BerSequence().decode(self._content.payload)

        # RFC 2315 only has Version 0 for EnvelopedData
        assert(envelopedData[0] == 0)
        self._recipientInfos = DerSetOf().decode(envelopedData[1])
        self.decode_recipient_infos()
        self._encryptedContentInfo = PKCS7Data().decode(envelopedData[2], True)


    def decrypt(self):
        plaintext = self._encryptedContentInfo._algorithm.decrypt(self._info['contentKey'], self._encryptedContentInfo._data.payload)
        print(plaintext)
        return plaintext



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
