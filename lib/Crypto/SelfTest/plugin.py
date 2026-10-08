# SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

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
