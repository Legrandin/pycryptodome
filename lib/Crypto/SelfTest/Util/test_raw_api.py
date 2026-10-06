# ===================================================================
#
# Copyright (c) 2026, Legrandin <helderijs@gmail.com>
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

"""Self-test suite for Crypto.Util._raw_api"""

import sys
import threading

import pytest

from Crypto.Hash import keccak
from Crypto.Util import _raw_api


class TestLoadLib:
    def test_same_declarations_twice(self):
        # The second load must not declare the functions again
        lib1 = _raw_api.load_pycryptodome_raw_lib("Crypto.Hash._keccak", keccak._keccak_cdecl)
        lib2 = _raw_api.load_pycryptodome_raw_lib("Crypto.Hash._keccak", keccak._keccak_cdecl)
        assert lib1 is not None and lib2 is not None

    @pytest.mark.skipif(_raw_api.backend != "cffi", reason="Only cffi keeps track of declarations")
    def test_same_declarations_from_threads(self):
        """Several threads load libraries with the same, new declarations.
        Without a lock, two of them may both pass them to ffi.cdef(),
        and the second call fails."""

        n_threads = 8
        old_interval = sys.getswitchinterval()
        # Switch threads as often as possible, to make the race likely
        sys.setswitchinterval(1e-6)
        try:
            for trial in range(30):
                # Declarations seen for the first time (the functions are never called)
                cdecl = "".join("int not_called_%d_%d(void);" % (trial, i) for i in range(50))
                barrier = threading.Barrier(n_threads)
                errors = []

                def worker():
                    barrier.wait()
                    try:
                        _raw_api.load_pycryptodome_raw_lib("Crypto.Hash._keccak", cdecl)
                    except Exception as e:
                        errors.append(e)

                threads = [threading.Thread(target=worker) for _ in range(n_threads)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                assert errors == []
        finally:
            sys.setswitchinterval(old_interval)
