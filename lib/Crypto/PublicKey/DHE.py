# -*- coding: utf-8 -*-
# ===================================================================
#
# Copyright (c) 2017, DeadPix3l <skylerr.curtis@gmail.com>
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

"""Diffie Hellman Key Exchange

DHE `(Diffie Hellman Ephemeral)`__ is a secure internet key exchange (IKE) that
negotiates a symetric key between two parties and provides perfect
forward secrecy (PFS).

DHE is a widely accepted algorithm and is very common in modern crypto. This
module was created to help you negotiate symmetric keys securely between two
parties.

This module does NOT handle:

    - Conversion: This module returns an integer as your symettric key.
    Your algoritm likely requires a string. You can hash it, take the ascii
    representation, whatever you want to do. Just do it consistently. If you
    are interfacing with another implementation, make sure to do what they do,
    or you will end up with differing keys.

    - Authentication (Currently): Diffie Hellman is susceptiblee to MITM
    attacks, and is usually coupled with RSA or DSA for signing. This signing
    will not currently be done for you in this module. I recommend using
    pyCrypto or pyCryptodome.

    - Multiple Parties: Diffie Hellman only allows for two participants, but
    by performing several iterations of DHE, it is possible to securely
    negotiate a key between several parties. This has not been tested and while
    it may work, it is not supported at this time.

As an example, local key exchange can be done as follows:

    >>> import DHE
    >>>
    >>> Alice = DHE.new()
    >>> Bob = DHE.new()
    >>>
    >>> aliceFinal = Alice.update(Bob.getPublicKey())
    >>> bobFinal = Bob.update(Alice.getPublicKey())
    >>>
    >>> (aliceFinal == bobFinal)
    True

An example of the negotiate() function:

    >>> import socket
    >>> import DHE
    >>>
    >>> sock = socket.socket()
    >>> sock.connect(('localhost', 1234))
    >>>
    >>> alice = DHE.new(18)
    >>> key = alice.negotiate(sock)

You can also handle the transmission manually if you have special
circumstances using the getPublicKey() and update() functions.


:DHE.groups: a dictionary where the key is a group number per RFC 3526,
             and the value is a tuple of (g,p) for the specified group

..RFC 3526: https://www.ietf.org/rfc/rfc3526.txt
.. __: https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange
.. PFS: https://en.wikipedia.org/wiki/Forward_secrecy
"""

# imports here
from Crypto.Random.random import randint
from Crypto.Util.number import long_to_bytes, bytes_to_long

from DHE_groups import groups


class DHE(object):
    """ DHE object

    __init__(group=14, randInt=randint):
        - initializes the object and generates the local secret (a)

        group: a group number as per RFC 3526 (default: 14 - 2048 bits)
        randInt: a callable that returns random numbers.

    getPublicKey():
        - returns your public key (i.e. g**a % p)

    update(B):
        - accepts the public key (B) from remote party,
        generates, and returns final shared key ( i.e. B**a % p)

    getFinalKey():
        - returns final shared key
        REQUIRES update() to be called prior.
        otherwise, throws ValueError

    negotiate(sock):
        - sends Public key via sock.send()
        receives other party's Public key via sock.recv(1024)
        calls update() and returns value

    """

    def __init__(self, group=14, randInt=randint):
        self.group = group
        self.g = groups[group][0]
        self.p = groups[group][1]

        self.a = randInt(1, self.p - 1)
        self.public = pow(self.g, self.a, self.p)  # g**a % p
        self.key = 0

    def getPublicKey(self):
        return self.public

    def update(self, B):
        self.key = pow(B, self.a, self.p)  # B**a % p == g**ba % p
        return self.key

    def getFinalKey(self):
        if self.key:
            return self.key

        raise ValueError(
            "Incomplete Key: please call update() with public key")

    def negotiate(self, sock):
        sock.send(long_to_bytes(self.getPublicKey()))
        B = sock.recv(1024)  # 8192 bits
        return self.update(bytes_to_long(B))


def new(*args, **kwargs):
    """ Return a DHE object """
    return DHE(*args, **kwargs)
