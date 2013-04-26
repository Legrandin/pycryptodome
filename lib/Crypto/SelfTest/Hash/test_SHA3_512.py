# -*- coding: utf-8 -*-
#
# SelfTest/Hash/test_SHA3_512.py: Self-test for the SHA-3/512 hash function
#
# Written in 2013 by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>
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

"""Self-test suite for Crypto.Hash.SHA3_512"""

__revision__ = "$Id$"


# This is a list of (expected_result, input[, description]) tuples.
test_data = [
# Test vectors from ``Keccak: Known-answer and Monte Carlo test results'',
# Version 3.0, January 14, 2011 <http://keccak.noekeon.org/KeccakKAT-3.zip>
    ('0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304'
    +'c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e',
     '',
     'Empty string'),
     
     
    ('8630c13cbd066ea74bbe7fe468fec1dee10edc1254fb4c1b7c5fd69b646e44160'
    +'b8ce01d05a0908ca790dfb080f4b513bc3b6225ece7a810371441a5ac666eb9',
     '\xcc',
     '1 byte message'),

    ('9a7688e31aaf40c15575fc58c6b39267aad3722e696e518a9945cf7f7c0fea84c'
    +'b3cb2e9f0384a6b5dc671ade7fb4d2b27011173f3eeeaf17cb451cf26542031',
     '\xde\x8f\x1b?\xaaKp@\xedEc\xc3\xb8\xe5\x98%1x\xe8~M\r\xf7'
    +'^O\xf2\xf2\xde\xddZ\x0b\xe0F',
     '33 bytes message'),

     ('aa52587d84586317028fb7d3c20892e0288bfe2feabd76d7f89155ffe9ccbf1a'
     +'09fa0ffb0553e83f79ae58bd30a35fa54892b6aba0093a012427ddab71cdf819',
      '\x94\xf7\xca\x8e\x1aT#LmS\xccsK\xb3\xd3\x15\x0c\x8b\xa8\xc5\xf8\x80'
     +'\xea\xb8\xd2_\xed\x13y:\x97\x01\xeb\xe3 P\x92\x86\xfd\x8eB.\x93\x1d'
     +'\x99\xc9\x8d\xa4\xdf~p\xaeD{\xab\x8c\xff\xd9#\x82\xd8\xa7w`\xa2Y\xfc'
     +'O\xbdr',
      '70 byte (block size - 2) message'),
     
     ('48fc282f37a3e1fb5df4d2da1f7197ec899ae573ca08df550e61ee847eeb1d24c'
     +'074ff46bcaee224ec7d8cea4256154f0c4d434e682834f6d827bfbdf75112f5',
      '\x13\xbd(\x11\xf6\xed+o\x04\xff8\x95\xac\xee\xd7\xbe\xf8\xdc\xd4^'
     +'\xb1!y\x1b\xc1\x94\xa0\xf8\x06 k\xff\xc3\xb9(\x1c+0\x8b\x1ar\x9c'
     +'\xe0\x08\x11\x9d\xd3\x06n\x93x\xac\xdc\xc5\n\x98\xa8. s\x88\x00'
     +'\xb6\xcd\xdb\xe5\xfe\x96\x94\xadm',
      '71 byte (block size - 1) message'),
     
     ('6b4b0f126863552a6f40f45e295dc79b9ba2a88ea7c3b2f607ac1a8431a97844'
     +'c2a7b664443fb23c05739df5494fe9824db80b7f3e67872142f17e2c5544e1ef',
      '\x1e\xed\x9c\xba\x17\x9a\x00\x9e\xc2\xecU\x08w=\xd3\x05G|\xa1\x17'
      +'\xe6\xd5i\xe6k_d\xc6\xbcd\x80\x1c\xe2Z\x84$\xceJ&\xd5u\xb8\xa6\xfb'
      +'\x10\xea\xd3\xfd\x19\x92\xed\xdd\xee\xc2\xeb\xe7\x15\r\xc9\x8fc'
      +'\xad\xc3#~\xf5{\x919z\xa8\xa7',
     '72 byte (block size) message'),

    ('e5d53e81866283179012d9239340b0cbfb8d7aebce0c824dc6653a652bb1b54e08'
    +'83991be2c3e39ad111a7b24e95daf6f7d9a379d884d64f9c2afd645e1db5e2',
     '\x94\xb7\xfa\x0b\xc1\xc4N\x94\x9b\x1dv\x17\xd3\x1bG \xcb\xe7\xcaW'
    +'\xc6\xfaO@\x94\xd4v\x15g\xe3\x89\xec\xc6Oih\xe4\x06M\xf7\r\xf86\xa4'
    +'}\x0cq36\xb5\x02\x8b5\x93\r)\xebz\x7f\x9aZ\xf9\xad\\\xf4At[\xae\xc9'
    +'\xbb\x01L\xee\xffZA\xba\\\x1c\xe0\x85\xfe\xb9\x80\xba\xb9\xcfy\xf2'
    +'\x15\x8e\x03\xef~c\xe2\x9c8\xd7\x81j\x84\xd4\xf7\x1e\x0fT\x8b\x7f\xc3'
    +'\x16\x08Z\xe3\x8a\x06\x0f\xf9\xb8\xde\xc3o\x91\xad\x9e\xbc\n[l3\x8c'
    +'\xbb\x8ffY\xd3B\xa2Ch\xcf',
     '142 byte (2*block size - 2) message'),

    ('5da83b7e221933cd67fa2af8c9934db74ce822212c99e0ee01f5220b4fe1e9b038'
    +'8e42e328a1d174e6368f5773853042543a9b493a94b625980b73df3f3fccbb',
     '\xea@\xe8<\xb1\x8b:$,\x1e\xccl\xcd\x0bxS\xa49\xda\xb2\xc5i\xcf\xc6\xdc'
     +'8\xa1\x9f\\\x90\xac\xbfv\xae\xf9\xea7B\xff;T\xef}6\xeb|\xe4\xff\x1c\x9a'
     +'\xb3\xbc\x11\x9c\xffk\xe9<\x03\xe2\x08x35\xc0\xab\x817\xbe[\x10\xcd\xc6'
     +'o\xf3\xf8\x9a\x1b\xdd\xc6\xa1\xee\xd7OPL\xber\x90i\x0b\xb2\x95\xa8r\xb9'
     +'\xe3\xfe,\xee\x9elg\xc4\x1d\xb8\xef\xd7\xd8c\xcf\x10\xf8@\xfea\x8ey6'
     +'\xda=\xca\\\xa6\xdf\x93?$\xf6\x95K\xa0\x80\x1a\x12\x94\xcd\x8d~f\xdf\xaf'
     +'\xec',
     '143 byte (2*block size - 1) message'),
     
    ('72de9184beb5c6a37ea2c395734d0d5412991a57cffcc13ff9b5fa0f2046ee87c61'
    +'811fe8ef2470239d5066c220173de5ebe41885ed8acae397fb395e6ca9aee',
     '\x15}[~E\x07\xf6m\x9a&tv\xd381\xe7\xbbv\x8dM\x04\xcc48\xda\x12\xf9\x01'
     +'\x02c\xea_\xca\xfb\xde%y\xdb/kX\xf9\x11\xd5\x93\xd5\xf7\x9f\xb0_\xe3'
     +'Yn?\xa8\x0f\xf2\xf7a\xd1\xb0\xe5p\x80\x05\\\x11\x8cS\xe5<\xdbc\x05Ra'
     +'\xd7\xc9\xb2\xb3\x9b\xd9\n\xcc2R\x0c\xbb\xdb\xda,O\xd8\x85m\xbc\xee'
     +'\x1712\xa2g\x91\x98\xda\xf80\x07\xa9\xb5\xc5\x15\x11\xaeIvly*)R\x03\x88'
     +'DN\xbe\xfe(%o\xb3=B`C\x9c\xbas\xa9G\x9e\xe0\x0cc',
     '144 byte (2*block size) message'),
     
    ('b678fa7655584970dedbbc73a16d7840935b104d06dcb468ddd9814d6cf443fa6f92'
    +'45824dbff3ab5fffef24b29cb2978796f37e7b49b1682d59f79e3c169e81',
     '\x83k4\xb5\x15Goa?\xe4G\xa4\xe0\xc3\xf3\xb8\xf2\t\x10\xac\x89\xa3\x97pU'
    +'\xc9`\xd2\xd5\xd2\xb7+\xd8\xac\xc7\x15\xa9\x03S!\xb8g\x03\xa4\x11\xdd'
    +'\xe0FmX\xa5\x97ig*\xa6\n\xd5\x87\xb8H\x1d\xe4\xbb\xa5R\xa1dWyx\x95\x01'
    +'\xecS\xd5@\xb9\x04\x82\x1f2\xb0\xbd\x18U\xb0NHH\xf9\xf8\xcf\xe9\xeb\xd8'
    +'\x91\x1b\xe9W\x81\xa7Y\xd7\xad\x97$\xa7\x10-\xbeWgv\xb7\xc62\xbc9\xb9'
    +'\xb5\xe1\x90W\xe2&U*Y\x94\xc1\xdb\xb3\xb5\xc7\x87\x1a\x11\xf5Sp\x11\x04'
    +'LS',
     '145 byte (2*block size + 1) message'),

    ('b77fb79669ea52c738e58a9ef3ed1501bbe7974478afb5a8bed44549d6232ff8d7aa9'
    +'eeeaf02f6755327951093243110d7bcfc0e51299db793856b57a77e8420',
     '|yS\xd8\x1c\x8d \x8f\xd1\xc9v\x81\xd4\x8fI\xdd\x004V\xde`G[\x84\x07'
    +'\x0e\xf4\x84|3;tW[\x1f\xc8\xd2\xa1\x86\x96D\x85\xa3\xb8cO\xea\xa3YZ'
    +'\xaa\x1a/E\x95\xa7\xd6\xb6\x155c\xde\xe3\x1b\xba\xc4C\xc8\xa3>\xedm]'
    +'\x95j\x98\nh6l%\'\xb5P\xee\x95\x02P\xdf\xb6\x91\xea\xcb\xd5\xd5j\xe1K'
    +'\x97\x06h\xbe\x17L\x89\xdf/\xeaC\xaeR\xf11Bc\x9c\x88O\xd6*6\x83\xc0'
    +'\xc3y/\x0f$\xab\x13\x18\xbc\xb2~!\xf4s\x7f\xabb\xc7~\xa3\x8b\xc8\xfd'
    +'\x1c\xf4\x1f}\xabd\xc1?\xeb\xe7\x15+\xf5\xbbz\xb5\xa7\x8fSF\xd4<\xc7A'
    +'\xcbor\xb7\xb8\x98\x0f&\x8bh\xbfb\xab\xdf\xb1WzRC\x8f\xe1KY\x14\x98'
    +'\xcc\x95\xf0q"\x84`\xc7\xc5\xd5\xce\xb4\xa7\xbd\xe5\x88\xe7\xf2\x1c',
     '214 byte (3*block size - 2) message'),

    ('caca0ff43107f730a7fbe6869fba5af1e626c96303be3bc95155164199c8892219451'
    +'1b24c48911186f647ca246427f2ce7ba747271cd8d7c5e1d127c21f1eaa',
     'zjOO\xdcY\xa1\xd2#8\x1a\xe5\xafI\x8dt\xb7%.\xcfY\xe3\x89\xe4\x910\xc7'
    +'\xea\xeebn{\xd9\x89~\xff\xd9 \x17\xf4\xcc\xdef\xb0D\x04b\xcd\xed\xfd'
    +'5-\x81S\xe6\xa4\xc8\xd7\xa0\x81/p\x1c\xc77\xb5\x17\x8c%V\xf0q\x11 '
    +'\x0e\xb6\'\xdb\xc2\x99\xca\xa7\x92\xdf\xa5\x8f5\x93R\x99\xfa:5\x19'
    +'\xe9\xb01f\xdf\xfa\x15\x91\x03\xff\xa3^\x85w\xf7\xc0\xa8lkF\xfe\x13'
    +'\xdb\x8e,\xdd\x9d\xcf\xba\x85\xbd\xdd\xcc\xe0\xa7\xa8\xe1U\xf8\x1fq-'
    +'\x8e\x9f\xe6F\x15=="\xc8\x11\xbd9\xf80C;"\x13\xddF0\x19A\xb5\x92\x93'
    +'\xfd\n3\xe2\xb6:\xdb\xd9R9\xbc\x011\\F\xfd\xb6x\x87[<\x81\xe0S\xa4'
    +'\x0fX\x1c\xfb\xec$\xa1@K\x16q\xa1\xb8\x8am\x06\x12\x02)Q\x8f\xb1:t'
    +'\xca\n\xc5\xae',
     '215 byte (3*block size - 1) message'),
     
    ('e5106b2a0d49d6d1e13e3323232101cea5da71caa24e70efcac57e0ccf156cdf4c24'
    +'92b03ce0e13437018dab76b9c989883bea69e849f33bb937a397b84ada6a',
     "\xd9\xfa\xa1L\xeb\xe9\xb7\xdeU\x1bl\x07e@\x9a3\x93\x85b\x01;^\x8e\x0e"
    +"\x1e\nd\x18\xdfs\x99\xd0\xa6\xa7q\xfb\x81\xc3\xca\x9b\xd3\xbb\x8e)Q"
    +"\xb0\xbcy%%\xa2\x94\xeb\xd1\x086\x88\x80o\xe5\xe7\xf1\xe1\x7f\xd4\xe3"
    +"\xa4\x1d\x00\xc8\x9e\x8f\xcfJ6<\xae\xdb\x1a\xcbU\x8e=V/\x13\x02\xb3\xd8;"
    +"\xb8\x86\xed'\xb7`3y\x811\xda\xb0[B\x178\x1e\xaa\xa7\xba\x15\xec\x82"
    +"\x0b\xb5\xc1;Qm\xd6@\xea\xecZ'\xd0_\xdf\xca\x0f5\xb3\xa51!F\x80kL\x02u"
    +"\xbc\xd0\xaa\xa3\xb2\x01\x7f4iu\xdbVo\x9bM\x13\x7fN\xe1\x06D\xc2\xa2"
    +"\xdaf\xde\xec\xa54.#d\x95\xc3\xc6(\x05(\xbf\xd3.\x90\xafL\xd9\xbb\x90"
    +"\x8f4\x01+R\xb4\xbcV\xd4\x8c\xc8\xa6\xb5\x9b\xab\x01I\x88\xea\xbd\x12"
    +"\xe1\xa0\xa1\xc2\xe1p\xe7",
     '216 byte (3*block size) message'),
    
    ('faee462e4bced12ad54d3757d644396ed9203037741661aea32bccadae568c4bdc925'
    +'eda76610e964fbe3fb26b33bc0bc123ddf9b528715317ce5c92e00ac96f',
     '-\x84\'C=\x0ca\xf2\xd9l\xfe\x80\xcf\x1e\x93"e\xa1\x916\\;a\xaa\xa3'
    +'\xd6\xdc\xc09\xf6\xba*\xd5*j\x8c\xc3\x0f\xc1\x0fp^kw\x05\x10Yw\xfa'
    +'Il\x1cp\x8a\'z\x12C\x04\xf1\xfc@\x91\x1etA\xd1\xb5\xe7{\x95\x1a\xad'
    +'{\x01\xfd]\xb1\xb3w\xd1e\xb0[\xbf\x89\x80B\xe3\x96`\xca\xf8\xb2y\xfe'
    +'R)\xd1\xa8\xdb\x86\xc0\x99\x9e\xd6^S\xd0\x1c\xcb\xc4\xb41s\xcc\xf9'
    +'\x92\xb3\xa1E\x86\xf6\xbaB\xf5\xfe0\xaf\xa8\xae@\xc5\xdf)\x96o\x93F'
    +'\xda_\x8b5\xf1j\x1d\xe3\xabm\xe0\xf4w\xd8\xd8f\t\x18\x06\x0e\x88\xb9'
    +'\xb9\xe9\xcajB\x07\x03;\x87\xa8\x12\xdb\xf5TM9\xe4\x88 \x10\xf8+l\xe0'
    +'\x05\xf8\xe8\xffo\xe3\xc3\x80k\xc2\xb7<+\x83\xaf\xb7\x044V)0O\x9f'
    +'\x865\x87\x12\xe9\xfa\xe3\xca>',
     '217 byte (3*block size + 1) message'),
    
    ('3d370dc850bc7e159cee3f24d9e915b5b1306ff403c32c7a3a3844f3fc8d90e35'
    +'f56d83bdd9c637bc45e440e1f27ccd56b6b3872ec19101bbe31845108dce929',
     "19\x84\x0b\x8a\xd4\xbc\xd3\x90\x92\x91o\xd9\xd0\x17\x98"
    +"\xffZ\xa1\xe4\x8f4p,r\xdf\xe7K\x12\xe9\x8a\x11N1\x8c\xdd-G"
    +"\xa9\xc3 \xff\xf9\x08\xa8\xdb\xc2\xa5\xb1\xd8rg\xc8\xe9\x83"
    +"\x82\x98a\xa5gU\x8b7\xb2\x92\xd4W^ \r\xe9\xf1\xdeEu_\xaf\xf9"
    +"\xef\xae4\x96NC6\xc2Y\xf1\xe6e\x99\xa7\xc9\x04\xec\x02S\x9f"
    +"\x1a\x8e\xab\x87\x06\xe0\xb4\xf4\x8fr\xfe\xc2yI\t\xeeJ{\t-`a"
    +"\xc7D\x81\xc9\xe2\x1b\x932\xdc|nH-\x7f\x9c\xc3!\x0b8\xa6\xf8"
    +"\x8fy\x18\xc2\xd8\xc5^d\xa4(\xce+h\xfd\x07\xabW*\x8b\n#\x88fO"
    +"\x99H\x9f\x04\xebT\xdf\x13v'\x18\x10\xe0\xe7\xbc\xe3\x96\xf5"
    +"(\x07q\x0e\r\xea\x94\xebI\xf4\xb3g'\x12`\xc3Ek\x98\x18\xfc"
    +"zr#Nk\xf2 _\xf6\xa3eF P\x15\xeb\xd7\xd8\xc2Rz\xa40\xf5\x8e\x0e"
    +"\x8a\xc9z{ky<\xd4\x03\xd5\x17\xd6b\x95\xf3z4\xd0\xb7\xd2\xfa{"
    +"\xc3E\xac\x04\xca\x1e&d\x80\xde\xec9\xf5\xc8\x86A\xc9\xdc\x0b"
    +"\xd15\x81X\xfd\xec\xdd\x96h[\xbb\xb5\xc1\xfe^\xa8\x9d,\xb4\xa9"
    +"\xd5\xd1+\xb8\xc8\x93(\x1f\xf3\x8e\x87\xd6\xb4\x84\x1f\x06P\t"
    +"-D~\x01? \xea\x93N\x18", 
     '319 bytes message'),
     
# Test vectors from http://www.di-mgt.com.au/sha_testvectors.html
    ('18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d'
    +'0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96',
     'abc',
     '"abc", the bit string (0x)616263 of length 24 bits.'),
     
    ('6aa6d3669597df6d5a007b00d09c20795b5c4218234e1698a944757a488ecdc09'
    +'965435d97ca32c3cfed7201ff30e070cd947f1fc12b9d9214c467d342bcba5d',
     'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
     ' "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (length 448 bits).'),
     
    ('ac2fb35251825d3aa48468a9948c0a91b8256f6d97d8fa4160faff2dd9dfcc24f'
    +'3f1db7a983dad13d53439ccac0b37e24037e7b95f80f59f37a2f683c4ba4682',
     'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh'
     +'ijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
     '896 bits message'),
     
    ('5cf53f2e556be5a624425ede23d0e8b2c7814b4ba0e4e09cbbf3c2fac7056f61e'
    +'048fc341262875ebc58a5183fea651447124370c1ebf4d6c89bc9a7731063bb',
     'a' * 1000000,
     'one million (1,000,000) repetitions of the character "a" (0x61).'),

]

# Data for Monte Carlo Test (MCT) from ``Keccak: Known-answer and
# Monte Carlo test results'', Version 3.0, January 14, 2011
# <http://keccak.noekeon.org/KeccakKAT-3.zip>
#
# This is a tuple (seed, checkpoints, iterations)
# See ``Description of Known Answer Test (KAT) and Monte Carlo Test
# (MCT) for SHA-3 Candidate Algorithm Submissions''
# <http://csrc.nist.gov/groups/ST/hash/documents/SHA3-KATMCT1.pdf>
# for a description of the methodology
mct_data = (
    "6cd4c0c5cb2ca2a0f1d1aecebac03b52e64ea03d1a1654372936545b92b"
    "bc5484a59db74bb60f9c40ceb1a5aa35a6fafe80349e14c253a4e8b1d77"
    "612ddd81ace926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9"
    "bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1c"
    "b40439d835a724e2fae7",
    [
        'ad95cc492ff544de932ab3048f4cfe61f36ab4df489794ebca3da9c50e2b6aeb10e9ff115a8d984ad873029af95a93bff0446c5ca44b6127fdd6f0127d23b170',
        '6d0d0c16ce7958688752231e935be817fa2ced1693f9f2f669b7661a46c0aeabc85029cdbbd4697d7261af638800d194b5ed07967b71b1f4eb8d7673ed177373',
        '172207143dcdca4f13125c38d90185375e85b0a7f26cabc314e432a3ce53b26d64ae73d0c4cf81de1490d0f672c44b2c38efc65d2ca3513cb63f32511613614f',
        '65a1964f00c53fbce870d19060d75eadd997b520291275f117d524937ba0e06ebfe590a20169aad96189735789ce20d9cd7d02d9f0b0bdb040a5e4c31ddfb711',
        '26a2cb3c21c94f4f8907d1564fe7299f7b413bd4a3d2244ba36f90425c8ef6a22305890424d842e5d500d0baed259cab1b65c77e93bf69bab51172e87febcdea',
        '7784168deae400b973b471581594a9014cf3b7ce2149b76cda634e49c981a5205313804cd37d4dd2b332bec50b20fc5bd4e9fb024fc7070d3aaa4e439859de8c',
        '713faeae41a7980dea985a3a016fa888edacc41741d63e03b953dcff865631996e6ad98c59107b729583e06beb5f77bb024fc470f7b0c1d67da9f0a7e4437f05',
        '6de8c5ae9435713a6664f034db0fe07cf52d781c100b39cd077b4f47e78e54339fd3313237de8e643b7e8e3b1956cb92ea04f47e2e0c211cf58596e581986dbc',
        '32643b4de4b919ee749c12feb2c5f4328545758358996ba2a0ba0a55f0b9f1e7d99e3810bdbe323f3c1a880c992b43ba9859f6af5c4762091758f6feef86e9c2',
        'de9b81e572c5aba89916db4fec67f767af7e1dc9719e3a1abd3c2e91c8ce3f107b8b2af50c24ab39bb4ea742ef0eec6388e70b0872280cf2fd958b25e595dea3',
        'b143872add6e701f562641109f4fac5ed1cbd60fc9e405d409d2aa71ef245274e8c46b509529610a04fc84200c4d483879df805ba44611f1c3f125d916630659',
        '55276291e43b809003ac2c693be83182833391654f5a9373e2c90436d1fbfd422b2d444b5e7b0a9e2bea9e71abd3a43eee4e8ba931b4b331cc18f031fb20c3c9',
        '010b5c222eb29b1fdbd9cf85603165f81072418cd681282c80c3adaba4d9bcd42f4335d6ccc13bf1eb8720d658a2c9423a8eff5f5d15096cf2c2dd2f0bc9bd11',
        'e126165bbc854301e76905835d210ce73a6f9c7c0b504d00cdc712251384161b7ac45a2ecc8f89c3ec4775df11ae9ff51826543f6152f13dbe247cd27cff10c7',
        '808df70dc15d4a4d5b9cdd15c3840861543b329912e8a2334484d807eacf411ee09e47c3b160cda6ceca85fbcaadd19fe1c845f017e313e288120dae4c36e75f',
        'cc2f16a8ee40ad52fa1f7ea4c7231cb4e301b8c03cdab4e621439179bebbed17c85d23e31d498b62da9bbb05cc58d58e14103b938ae1a0c0f4890b8f88ad6b38',
        'f80c6408f43a0573dccd8cdc6812e9be0fe2d936cbd0df2ea2371f89c10ca9426a6c00df1f25ebeeefb8926ba18d941667dffddeb52424975bd7527ca1c66d66',
        'ad38f133d81205ddd7c296844d6feddf1d5221a591eefdbd254f1e80ff4dd6d1d5d3ec3cbd6db2dcfdef1eeb87181bc0f10c3e0711a5f5830155c530d00ee37e',
        '927875136bb62268f1beabc0a58b1ab04253ef464f07ddf010c16d4e9c1527c96e74cbba35f379214ed52e6526021e228dbd15b102a9969030cf3b67789d1dd3',
        '6d312bf744a69569772e1df5e0362247f2d541999b48fbccfcd148317e42aed2ecc47ea554259704ea36f2cda780d75edc90c281bf59a298f8c9ab1e46d03ede',
        'd188e3c5347ada2b449059a9aed53f2ff635aa980dba5ba0d68019facfc53a68b9f242b451836834deb5f1aa203b87058c9d08352d87e60ef6a1694d2c2e1786',
        'a5d8a03f7b8c46b79983bdf9cc78acdfa4a54a8759209453cdc11d7f3d7824ea07ebb7f92f8256cbc849422e01d6d3cfe50ae58a22aa9eeac5cb3b440a344bfe',
        'f8ca8b5154b6c03841265c23148ed48defc65834849f4367e7c09b57ba87ace574eac36987f29c7c67183dd69b64ecacb36f0cd0c976b58254f06f1bf85d7c71',
        '6579ff9aa09708a4a2cba5b4df304ab5f44eda1f8cd06871077a213f1ecc733c64d3360d0fac61425d8aab05a952e537c510460b206a44e648340f06a5c9bcaa',
        '9d112c70ef6d392694d483b1211d5a9abc59b12995edb425d490e3c9cb1e7e74777f41c596d38415a9795b9507255f5dcf95d423998574c81e636753723f324f',
        '2ba36f54e3e62f6ed12e7da511ca68af954cfab4f8cb4bbca327efd55a09e5aff0c478167e3a59c8131197aecc1eff647c23fcba65c8a3030fd643795ff70fe0',
        'd1d140907a86c01aecc33b574ad010221a7df07561f6b53f3b64e4db01d084c4c0f3c7c7956860460380c9c72aba403ada2f9045d71068a630c8ffbd3a378c76',
        '0533d248bd26949417cce0a4af896dc1dc5d143316fc61780b5c2d7520d324b52dd0c802b1c3507f800dc60efb1666c4cc76cbdf2d550383a69997912476eeec',
        '2a82ff411fe996b12b4f3c02b5234fe178d315aaea0435decda3785a885cef5cd357b4b0db9e32e83feed0c4c80201cce773abfbaa1471f2aa97794e19106f9d',
        '23c2b8a325d44192ea002bdb777325e3e87c93f7180b20de3108f298af0a0949f5df59c012d821365372515bc575277adea0dc7ca9652b9cd692bb217a564544',
        'e9d67628126d0ad0869ddc755e355e9b1e4bdaa2ed7f1f1f76bed0d8107996250d401f2a73574ec96e755a2990a89a40d76aa618ec6e1ccd049350938e01a09c',
        '3d00699beba5cde6ab9043204e756a917c6b969d0ff96c33654aaddbad5996ddf23a8e0e17fd59230156158ffd891ac9b769d3179091592e220d406057804b15',
        '6037e1317605792433ea05946545befc711f9e4c9b857fee78622d48ef25f5cf5a38f2fcf191c64d6fd0e21e093b8e102dbebe4c0e0700f546ee84970d417b2f',
        '6a97496fbcccd94733bdbfa874940951ef0420e06c5e86162f219b3a954be1ec9caecb939b063c938c6186618d6399eb1ff08516de1a973040ffdbc5dbde1a13',
        'efcbad8f9ec906888528d365fb6aee80d3eb0276ba703b33971075da6d493fdacc88b8b84f49d7d399e263600ab61125fa44d1a5efa8051b828e7a8a4e2e3924',
        '5fad0c080fc9689c16c1eb12fa59e701861314d34662f75767fee4633327b19b03d97f2ce065b9c9bc6084e40a02224ec8ef7595f8281d81deb33fc7eed50d11',
        'c2fb97d60062b1303af4c691d529c598205525fb675c607fa4a98ee489e5c859201f228b9a1f071268c1c05a090d656caa0c82dd1f34b5f1eba5a05d1c855d12',
        '2b15e51e795c64b5826007449a01a6e13ac61c4ae494061c6e622ca624d99c4b616d87070eafebe18d37e9b84c272de4484a9717c711d1700d1efab324671852',
        '838613099b7d18bf7324b735f8fcb91c566c91596ce43284d49223785659667cede6db6477b91eafb52590ae6ce3a110b38c4a988b29acb933f11f68ffd320c0',
        '76f2f049bceae3130de2d3ebbedbe9d2d84ef7026518dd1807c126e5c184d30f133b464f0f99aec1d697887b3bd444ff91ad4f9fb2cd32a9c1a7e73980215f7b',
        'd97a85cd3ff4c55883a8c258e81e03eb7911892db0f7f8baebb5fc97ae6ae59301c7f0e6b8614f2d096af4a61636b6ba01132be3953f15b918833c8b435a6760',
        '77edf23359fe3abcb970f38cea63ba0b68e5826f1a7b2d29994ac1b9e482d2eaa34f2278505dfeaf95bbe34b77ed83858bfc851cadf3d81117f820a8cead5666',
        '62c269860ca2a16bb10fb1a30c8d0c3ef29c4836fdd744687354ef1777c798f235237e8f2053253f0f4e274170ee3a02f027ef3e016cdc83c7e70f7441ae69d4',
        '3f577dc3a2b5b62c6f0b1e2924245e6842bc0f67596fd72452aaabfeef206ec71b2ba2781151d21fa0e059d7c5e1dd8e2c9ff22ead832487842c9055f5542523',
        'f9608ed78c9a4ec403ab405e82b680c5c7d8a3b6c0cb91e5326ff3be3bec34a3ec6c87369fbd430f414411563a3ddb9920bf492e7f66bf54c46019063ddd84b9',
        '77274f4d0311366a0085aebb3a4091254a6c56a25df2d57ab081e2a2843226b24130494e15bd6b3b393038a5d00fb37372604c14e0bc63ae2a6d38a24c5d206c',
        '9557648455c929712fd1a340baffa7303f19541263a3bc95fedc19116d0e2505c2e353807ee5e15c59b9eca5b1706ae8fba9e1790d7647353653ebe23818392e',
        'd6cb9ce49d5fc88496d1d603b9d73a47f61ed1fb9457d9f0c47828af9c7fa8b2822e09784dca1934be4a56b9c71fb639dcd4bd0f5c036272d018a0576184545b',
        '55a71f0c8ae1076ddd4aed47e32ba3235ddd9e73670ea9c63e779a720ea5600c987704dc4b4fb8aa65817d8e63283d8fbbbe084c11a1aa7f5591c8c60cd5b90d',
        '297fc65766c4192a12b667eb0668f4aaf5ccc3a997cefae7b0deeb3769a6a8cb0827427c6e50b9f493917b9d66753b9b0a4c6dadabaf0e7ef65f747459dafdb5',
        'ba47b8a755645e4f279296931a1950fea30403da9b0837d5e0abe65d03a64f569f32d67a135ef98467494bcd7e17942a54b3d1c961326eacd6658ae0c4be4fd4',
        'd20fe2efa9d3b119f7950861a10a91ea41cfe2ad2e46664441583b89f8f76be309c9d26a94f2019b2370a61759b35d471914babe91cb69432aecbd34e104d3ec',
        '15b0bb9834131d82e1bbd373f20b500e50ce29c42cd6e8689766bb4f4d17eed6c7272c817569be60f3deb591e1d6a77f20469ee68fac8d52f5aba56c6b7d2774',
        '231256c6d8603471f517ce9d4ce1c94d8302aa77ee160c3d633262bb94ba4124078be1259970331b963632f004865bc118c335ed44aed6e80efdaa91b3c45d86',
        'bb1b8f93300363f7919da574a255a414582ffd7ca04e4f1e4b561ed40c73dc2a888b997da0f99e3b73d2543acfa579bcb8a987069c7e7de67dd0b70ec1715fbf',
        'b3a907dde7b426ba46f279f18fabb641f88437c12f25f410c346efe946faa73b913b25cb9c7f4337684e676decbc39dc1e8d9c401c95b1bfeadbc486da2827ac',
        'e33a78f597a2ffe9473a528638609ceb2266fb6a4cf315b950a6104d1c0cae65251660cec9bc683d2396fc8234b5a5be3564aef9e0cc723b69ec9a7c06b6e53d',
        '9828844b3fe82a32a516931a5699332800848a70073ae416c38bc16d8ba699a5f48468f5ef48291260fc47fe983bd54a1093f8cf50440914a9eca5a2599fe567',
        '7e7c66145e4cf1038dc212645653f5dd2de5b978cdac275ae83ab8fa1f9c28ee645ffa0880009b26df8b04bab38925f991e3b75d65d91285601f4f4402e174f6',
        'b8ac30dea9cc75f59b0ad66b4470c63900f83d4064e416ed5f5b9bc9ce675f37bbf37b60727ed3ea40a87a1df58c32462c4b67ca19ae7cef1404179bceecf914',
        '9c54ae58fcdc948c8ada58777e857232e6dc0fdce48d65688305f4d84dcde2dc97441dc8ca67101b9d1962807cd4d757bf7e1b309cd26d36ee47247b8143006b',
        'aa6ecd46e8dfccce29cd92b15bb960fb20cab731e9a07e32d8933dbd8e758de924ee99d40579bc5f023be384c238858fa8988139e4006e1dd3c77be6dd7f3064',
        'f60d4d3e6d7737f094c3b6f1acbb03601fa756e665e2363cd3015df3f5bf6ce9ae2f758f2f60915770bfdf1a18f469793e3a2172774a6876264716c289ac1d69',
        'b49789a0170377eb4653a42ca671133289265d74b0b204f466391cafb935332be9fcc12d16d4e54d916b2ad34a8e3b306c5d12bb3bb824b3dcc229af52a1c1c9',
        '1160f0f40c94410373bb8d053d1af257c63f34a0437b937d3979dab2530b85c6eea58d15429f1b8a6676dae79ef27cddac7c2f80ebc7107a2f0348e1328445ca',
        '4d01dc66a87b785ccac49784b3be37346b16a946984fe0f9b9819c49b10a46c25d538c52b8edb5a27efa71e05e3df70d20c8e224ae3d9e2b7dc18ae1957bc22e',
        'dabe8947ea4ac7297f6e5145ad7ff3b9f55e2705e5a94a1ee14a6a046b649c20ac971b44a9a1cb7a73c3a3c7d198bf873deeffbc26754e4570b791f7337f8428',
        'b09de539726a3bd622fe16f98abe4b327fa519e81644f69891a7d2d6a1de87bb61ac4f7fce210899615ed27d86bdb4f188cc7c4642682fd60cdde63e2c3ef46d',
        'c950a5f21cf19504dec4891b3d7d2b69a8c864fd803f5f344f1be027c5fec4e058cb03a541979ea5d806feedd4ef6c5a081f9c7bc9c94c69d896f8f0ffc5051e',
        '0686ebe1c49279e7e2372f14f89f6a4e4d94b9d689de8f8d9eacf4ab3d8d7b2acff5caf6de318c2cfa2fee2bfc510bc8d9c68b3c75c995f793a00458d2778010',
        'a0a7247942898449e5b85a5f8e1d65d211e00d172701e4dda111bc21557994699b9f063bca31dd75ef5a367f12a946ad216ff7f9e5c10c04cf2258f8ce0fb520',
        '23e2d952d6f365f85bd1a4f56f91848b717ef435f91caf801efc93ea078722de6555573aa4ac6251c809dfef1be1bd0eb00c2c43d40b1e0f59072848a38896ef',
        'a1dd55470b136d51fa08a5cae9d9623b0b04f1a223cf75bfd4c0339d3cc6071236ea2a1968935aa800ef1fcbe7324d658461394091f5532cdefc7965b37ef3a6',
        '4b1e4f19ce12eed0ab9190e14c9e31d396d83c2e9d1d04d7b044464c77e30b9c45ffd1ec5e88fc0e938ec21c525a14b5d4c5132c6b1ba10d2271ea8cccf41ffd',
        '39b2ad6757a18324051591672bfda4301902956a95c60e75354b364dc74f9f43308aec43bf838a9a2de83f3ed2dae7c2ef49a2d1e6017f39079e2f6a8c051830',
        '696b6c04f8bd8ce5d437cc09ff1e8ed2ba4761f0894f79b40fe8fff55a83f5cd7a9039db694425ced91357faf7e0aa785e41afe6ca53b1974592651b275ad631',
        'aef85cbc4bf822464a3b067a0b53ac75b4fee8c473ab2334e87c0e64b1f01c774a512dcde166731be585937284c5447c2db2d2d53c7475d6917bd0a224a5329b',
        '31c8971c75e7f1369c5aff60934146fe97857435b531dd9a1c7406614b49f9c56bc1e7cf3ae799f6486dcc96b4cd0dd655ea3180ae8460972cf4bbffd0d573a7',
        '57e1bcffcce8fbe3c8e321d7743d594efa2ef6c15008bc2ef300e1036c77e281df6942da05674523d467581fcb9a0fc2dde00bc4e97679880de394181f096466',
        '27e57491f2e547bab89bff1478a0f9a7243204524f7c165683ffb6ba21fda9f09af8d65cef174c65e28231b4e15dcdfca9abdcf1a1d2ad58d8494dc1400885eb',
        '8f9fb752858952a157cb2bbeb70548de019ecd8bbca29272df7d5ce338f61aba8d7b8e26c83208d99398b97cd07867a1b9c752ef473cef391973c5c2f7e5d285',
        '8866330bd0d4fa248eb8f1012e079d325ec3f5f56a9fb7e61d15a1a78d9e1aec7eca4b3053420cf90fd789130d30bea6c285ebd8d011f28c4451fcd9d484576e',
        '8456cb6c15777f2f70577b5bbcd2e72e0dd621fb2baf7893f7419d335cc97551202886204ce63f5badd49432e50dafa9b4286ebdf7f6df1df337154eae4bfbd1',
        '3233761e56d2297a307f12ba6b47895254695404cab0b87dd99942ddd53f8f5ee34a412f1e17f5291a7d15292934fb77d96c97f17435f8d148509238953f1f2b',
        '4937c28761e900c090ca54ea21cf7690d859143c78cabd43d193fafcf21bb7b2e03b3ae364f090c5a0382dc960aca740f528d792d2a4760a7190244241e5b4c7',
        '483a883d12ff2fad59301138062842f71f59c2fb9e182f3eb3616f74ae1f4a5e470c49f4b67a310427ca411c3589c8f98504f8b0b3f271fcdb23122325ddf92f',
        'abd3bc1a43a381447307698c90f5045d5ca75ab0ee6e261185a5ce7f3baac3415df040f4d88d3dcd4d5bee7106807aa202b01bcf2647efb4e17617830e50b8cb',
        '121b8445d1e31c49b357fecbaa5f628d9a1bcd8c2ebff46e53db56dc64ac352a4bee366a09a9c73713cecc20dd22136a304ac7cdbc3866d214abdfeb4f28bfc1',
        '75a696f43046179dd59f1a525d408d38f40d79ded4b0c82d4631c2ff0bac22c9c083aa4079f4825e7e131761aa7cd9084d146ba2e80533786df8f64697a1f7d7',
        '0a482602bd78f451a064c8455463eb721647413507d52de772f1fb628db3a65792a69139981c4bb3de45405fb5d0436a9fd10c25b3786504359f0aa9b021af99',
        '41ad2e206564a0aabe6eff2b4c8f0c55609c1f6f44905a030e47053bfd5f530e985d2e211753d5079b5bb1db39145c113fecfb8d79ae19d52760c025ef3d8bbb',
        'b4e4c71343d19eeb087699b4a16ae0f827a3e3d43722037be77de0e4351b01f9f01f4f532ff7e2fe8845c155b4c6a2d1bfc4c5e6d8eab9f083f192d9f551f93e',
        '6cb7168e712fb206d137c4f3914790aa6f8c6190275e1a37b4bc72ab5523f6a9b8a2e845c6084b32b8d58bfa51c1667c22a2410359b87ad34d8927c3b0706121',
        'f3cc81da59ea17931e5739d235923c3d1a16be70e4833c3dfa32f41cc6e59b8bdd3c06600b581e7d1d4586e872dfcd563bc029eed67b33867f9bf23ab97e65b2',
        '3ce1ac64bbc5d6a5a649a3597721323e7900d5f4699096abdb5f2d6537eb360d8babb1498d038082d1ebc65ebc92d8f8b190517f94aba694cb971627bb821e8c',
        '855fd9a16ed2fcb0a539ee53498e4a9527a9e9853bb7c9a07daf3e221dc799cdc0aa72ebe0e79ea4672c931500f4a11c639a62a30082f6a986c7c499d9251ddb',
        '0b286e2b47ff261f097da1f8c0919fef6b518f0e78ff2143d05c7413f3850d379fc1adf69ed3725829557fb184a0cc74fbb7dad0eb7beb3b7a01fabe19fd8320',
        'ac005b07f79e827e6b0597bf30ffa8fd6777ec2064200f758170e2750339b7c752eeb55d6dd891e9d3af495b6a8178c4d9560a49be5717355e64e5b2a2e3e294',
        '0a8ed76577a6d80cc8a060581f68453bd88b446a7aab4854f97067b8e7f02eb1613d46f626aaca001cec4033c2e29b1671a0bdd098e4e7544bd72d5c7320cbac',
        'd1f517577f4b503344935cb725a6effaf523a543eafeee127fcb852d6bef33e04876afd5504999ed63ca7f026f60f1a30df2eda36c5c6282957e150f03e60671',
    ],
    1000
)

def get_tests(config={}):
    from Crypto.Hash import SHA3_512
    from common import make_hash_tests
    return make_hash_tests(SHA3_512, "SHA3_512", test_data,
        digest_size=SHA3_512.digest_size,
        oid="*-not yet assigned-*",
        mct_data = mct_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
