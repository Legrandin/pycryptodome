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

"""pytest plugin for the PyCryptodome self-tests (command line options and markers)"""

import pytest

from Crypto.SelfTest import st_common

pytest.register_assert_rewrite("Crypto.SelfTest.Cipher.common", "Crypto.SelfTest.Hash.common")


def pytest_addoption(parser):
    group = parser.getgroup("pycryptodome")
    group.addoption("--skip-slow-tests", action="store_true", help="Skip slow tests")
    group.addoption(
        "--wycheproof-warnings", action="store_true", help="Report Wycheproof test vectors with warnings"
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: slow test, deselected with --skip-slow-tests")
    st_common.options["wycheproof_warnings"] = config.getoption("wycheproof_warnings")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("skip_slow_tests"):
        return
    deselected = [item for item in items if item.get_closest_marker("slow")]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [item for item in items if not item.get_closest_marker("slow")]
