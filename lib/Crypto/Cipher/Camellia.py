# -*- coding: utf-8 -*-
#
# Cipher/Camelly.py : Camellia
#

import sys

from Crypto.Cipher import _create_cipher
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib, 
                                  VoidPointer, SmartPointer,
                                  c_uint8_ptr, c_size_t)


MODE_ECB = 1        #: Electronic Code Book (:ref:`ecb_mode`)
MODE_CBC = 2        #: Cipher-Block Chaining (:ref:`cbc_mode`)
MODE_CFB = 3        #: Cipher Feedback (:ref:`cfb_mode`)
MODE_OFB = 5        #: Output Feedback (:ref:`ofb_mode`)
MODE_CTR = 6        #: Counter mode (:ref:`ctr_mode`)
MODE_OPENPGP = 7    #: OpenPGP mode (:ref:`openpgp_mode`)
MODE_CCM = 8        #: Counter with CBC-MAC (:ref:`ccm_mode`)
MODE_EAX = 9        #: :ref:`eax_mode`
MODE_SIV = 10       #: Synthetic Initialization Vector (:ref:`siv_mode`)
MODE_GCM = 11       #: Galois Counter Mode (:ref:`gcm_mode`)
MODE_OCB = 12       #: Offset Code Book (:ref:`ocb_mode`)
MODE_KW = 13        #: Key Wrap (:ref:`kw_mode`)
MODE_KWP = 14       #: Key Wrap with Padding (:ref:`kwp_mode`)

block_size = 16
key_sizes = (16, 24, 32)

_cdecl = """
    int Camellia_start_operation(const uint8_t key[],
                                 size_t key_len,
                                 void **presult);
    int Camellia_encrypt(const void *state,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t data_len);
    int Camellia_decrypt(const void *state,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t data_len);
    int Camellia_stop_operation(void *state);
"""

raw_camellia_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_camellia", _cdecl)


def _create_base_cipher(dict_parameters):
    try:
        key = dict_parameters.pop("key")
    except KeyError:
        raise TypeError("Missing 'key' parameter")
    
    if len(key) not in key_sizes:
        raise ValueError("Incorrect Camellia key length (%d) bytes, must be 16, 24, or 32." % len(key))
    
    start_operation = raw_camellia_lib.Camellia_start_operation
    stop_operation = raw_camellia_lib.Camellia_stop_operation

    cipher = VoidPointer()
    result = start_operation(c_uint8_ptr(key),
                             c_size_t(len(key)),
                             cipher.address_of())
    
    if result:
        raise ValueError("Error %X while instantiating the Camellia cipher"
                         % result)
    return SmartPointer(cipher.get(), stop_operation)


def new(key, mode, *args, **kwargs):
    """

    """
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)