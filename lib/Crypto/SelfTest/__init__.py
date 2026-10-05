#
#  SelfTest/__init__.py: Self-test for PyCrypto
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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

"""Self tests

The tests are run with pytest, for instance with ``python -m Crypto.SelfTest``.
"""

import sys


class SelfTestError(Exception):
    def __init__(self, message, result):
        Exception.__init__(self, message, result)
        self.message = message
        self.result = result


# Load the plugin with our command line options; the tests may also be
# installed in a read-only location, so do not write a cache
_PYTEST_ARGS = ["-p", "Crypto.SelfTest.plugin", "-p", "no:cacheprovider"]


def main(args=()):
    """Run the self-tests with pytest, passing it the given command line arguments.

    Return the pytest exit code.
    """

    try:
        import pytest
    except ImportError:
        sys.stderr.write("The self-tests require pytest (pip install pytest)\n")
        return 4

    return pytest.main([*_PYTEST_ARGS, "--pyargs", __name__, *args])


def run(module=None, verbosity=0, config=None):
    """Execute self-tests.

    This raises SelfTestError if any test is unsuccessful.

    You may optionally pass in a sub-module of SelfTest (or its name) if you
    only want to perform some of the tests.  For example, the following would
    test only the hash modules:

        Crypto.SelfTest.run("Crypto.SelfTest.Hash")

    """

    import pytest

    if config is None:
        config = {}
    if module is None:
        module = __name__
    elif not isinstance(module, str):
        module = module.__name__
    args = [*_PYTEST_ARGS, "--pyargs", module]
    # Map the verbosity levels of unittest to pytest
    if verbosity == 0:
        args.append("-q")
    elif verbosity > 1:
        args.append("-" + "v" * (verbosity - 1))
    if not config.get("slow_tests"):
        args.append("--skip-slow-tests")
    if config.get("wycheproof_warnings"):
        args.append("--wycheproof-warnings")

    exit_code = pytest.main(args)
    if exit_code != 0:
        raise SelfTestError("Self-test failed", exit_code)
    return exit_code
