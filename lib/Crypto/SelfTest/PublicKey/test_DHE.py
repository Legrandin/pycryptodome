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

""" Unit Tests for DHE """

import unittest
import socket
from Crypto.Util.number import bytes_to_long, long_to_bytes

from Crypto.PublicKey import DHE

HOST = ("localhost", 12345)


class DiffieHellmanTests(unittest.TestCase):

    def test_Alice_Bob_Same_Key(self):
        for i in range(100):
            # 100 iterations should test well despite randomness?
            alice = DHE.new()
            bob = DHE.new()
            alice.update(bob.getPublicKey())
            bob.update(alice.getPublicKey())

            self.assertEqual(bob.getFinalKey(),
                             alice.getFinalKey(),
                             "Alice and Bob have different keys"
                             )

    def test_Forgot_update(self):
        alice = DHE.new()
        self.assertRaises(ValueError, alice.getFinalKey)

    def test_negotiate(self, group=14):

        client = socket.socket()
        client.connect(HOST)

        alice = DHE.new(group)
        local_key = alice.negotiate(client)
        remote_key = bytes_to_long(client.recv(1024))
        client.close()

        self.assertEqual(local_key, remote_key, "keys do not match")


def negotiate_server(group=14):
    server = socket.socket()
    server.bind(HOST)
    server.listen(5)
    conn, _ = server.accept()

    bob = DHE.new(group)
    local_key = bob.negotiate(conn)

    conn.send(long_to_bytes(local_key))
    conn.close()


if __name__ == '__main__':
    unittest.main()

