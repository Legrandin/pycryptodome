#
#  Util/Counter.py : Fast counter for use with CTR-mode ciphers
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

from __future__ import annotations

from typing import TypedDict


class CounterParams(TypedDict):
    """The description of a CTR mode counter, as returned by :func:`new`."""

    counter_len: int
    prefix: bytes
    suffix: bytes
    initial_value: int
    little_endian: bool


def new(
    nbits: int,
    prefix: bytes = b"",
    suffix: bytes = b"",
    initial_value: int = 1,
    little_endian: bool = False,
    allow_wraparound: bool = False,
) -> CounterParams:
    """Describe the counter blocks for a cipher in CTR mode.

    Each counter block is made up by three parts:

    +------+--------------+-------+
    |prefix| counter value|postfix|
    +------+--------------+-------+

    The cipher increments the counter value by 1 for each block.
    The result of this function does not change while the cipher
    is in use, and the cipher does not reveal the current counter value.

    Args:
      nbits (integer):
        Length of the desired counter value, in bits. It must be a multiple of 8.
      prefix (byte string):
        The constant prefix of the counter block. By default, no prefix is
        used.
      suffix (byte string):
        The constant postfix of the counter block. By default, no suffix is
        used.
      initial_value (integer):
        The initial value of the counter. Default value is 1
        (a cipher in CTR mode without the ``counter`` parameter starts at 0 instead).
        Its length in bits must not exceed the argument ``nbits``.
      little_endian (boolean):
        If ``True``, the counter number will be encoded in little endian format.
        If ``False`` (default), in big endian format.
      allow_wraparound (boolean):
        This parameter is ignored.
        The counter can wrap around to zero, but the cipher always raises
        :class:`Crypto.MessageTooLongError` (which is also an ``OverflowError``)
        before it would repeat a counter value.
    Returns:
      A dictionary with these parameters, to pass with the :data:`counter`
      parameter to a cipher in CTR mode.

    It must hold that *len(prefix) + nbits//8 + len(suffix)* matches the
    block size of the underlying block cipher.
    """

    if (nbits % 8) != 0:
        raise ValueError("'nbits' must be a multiple of 8")

    iv_bl = initial_value.bit_length()
    if iv_bl > nbits:
        raise ValueError(
            "Initial value takes %d bits but it is longer than the counter (%d bits)" % (iv_bl, nbits)
        )

    # Ignore wraparound
    return {
        "counter_len": nbits // 8,
        "prefix": prefix,
        "suffix": suffix,
        "initial_value": initial_value,
        "little_endian": little_endian,
    }
