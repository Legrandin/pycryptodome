#
#  SelfTest/st_common.py: Common functions for SelfTest modules
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

"""Common functions for SelfTest modules"""

import binascii

# Options of the current test session, set from the command line by conftest.py
options = {"slow_tests": True, "wycheproof_warnings": False}


def slow_tests():
    """Return True if slow tests must be run"""
    return options["slow_tests"]


def wycheproof_warnings():
    """Return True if Wycheproof test vectors marked with warnings must be reported"""
    return options["wycheproof_warnings"]


def strip_whitespace(s):
    """Remove whitespace from a text or byte string"""
    if isinstance(s, str):
        return "".join(s.split()).encode("latin-1")
    else:
        return b"".join(s.split())


def a2b_hex(s):
    """Convert hexadecimal to binary, ignoring whitespace"""
    return binascii.a2b_hex(strip_whitespace(s))


def b2a_hex(s):
    """Convert binary to hexadecimal"""
    # For completeness
    return binascii.b2a_hex(s)


# vim:set ts=4 sw=4 sts=4 expandtab:
