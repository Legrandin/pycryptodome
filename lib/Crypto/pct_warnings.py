# -*- coding: ascii -*-
#
#  pct_warnings.py : PyCrypto warnings file
#
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# =======================================================================
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =======================================================================

#
# Base classes.  All our warnings inherit from one of these in order to allow
# the user to specifically filter them.
#

class CryptoWarning(Warning):
    """Base class for PyCrypto warnings"""

class CryptoDeprecationWarning(DeprecationWarning, CryptoWarning):
    """Base PyCrypto DeprecationWarning class"""

class CryptoRuntimeWarning(RuntimeWarning, CryptoWarning):
    """Base PyCrypto RuntimeWarning class"""

#
# Warnings that we might actually use
#

class RandomPool_DeprecationWarning(CryptoDeprecationWarning):
    """Issued when Crypto.Util.randpool.RandomPool is instantiated."""

class ClockRewindWarning(CryptoRuntimeWarning):
    """Warning for when the system clock is found to be non-monotonic."""

# By default, we want this warning to be shown every time we compensate for
# clock rewinding.
import warnings as _warnings
_warnings.filterwarnings('always', category=ClockRewindWarning, append=1)

# vim:set ts=4 sw=4 sts=4 expandtab:
