# ===================================================================
#
# Copyright (c) 2026, Helder Eijs <helderijs@gmail.com>
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

"""Helpers for the objects that process long data on several threads
(the ``threads`` parameter).

The C functions release the GIL, so several of them can run at the same
time, each one on a different range of the data."""

from __future__ import annotations

import threading
from typing import Callable, TypeVar

from Crypto.Util._cpu_features import available_cores

# The type of the values that the workers of run_in_threads() return
T = TypeVar("T")


def threads_param(threads: int) -> int:
    """Check the ``threads`` parameter, and return the maximum number of
    threads to use (0 means as many as the CPU cores available)."""

    if not isinstance(threads, int) or isinstance(threads, bool):
        raise TypeError("'threads' must be an integer")
    if threads < 0:
        raise ValueError("'threads' must be a non-negative integer")
    if threads == 0:
        return available_cores()
    return threads


def range_boundaries(data_length: int, parts: int, block_size: int = 1) -> list[int]:
    """Given a piece of data of a certain length in bytes (``data_length``),
    split it into ``parts`` intervals, and return the position
    of the first byte of each interval, plus the end position.
    (The data can also be counted in units other than bytes, like the leaves of
    KangarooTwelve).

    - each interval (but the last) is made up of a whole number of blocks,
      where each block is ``block_size`` bytes long.
    - intervals are roughly equal, all with the same number of blocks,
      although some intervals may have one block more
      (the last interval is then always one of them).
    - the last interval also gets the left-over bytes,
      whenever ``block_size`` doesn't divide ``data_length`` exactly.

    :return: ``parts + 1`` positions: interval ``i`` goes from item ``i``
      (included) to item ``i + 1`` (excluded). The first item is always 0,
      the last is always ``data_length``.

    For instance, 160 bytes are exactly 10 blocks of 16 bytes. They do not
    divide evenly into 4 intervals, so two of the intervals (including the
    last) get one block more than the others: 2 blocks (32 bytes), 3 blocks
    (48 bytes), 2 blocks (32 bytes) and 3 blocks (48 bytes)::

        >>> range_boundaries(160, 4, 16)
        [0, 32, 80, 112, 160]

    With 15 more bytes (175 bytes), there are still 10 whole blocks,
    split in the same way, and the left-over 15 bytes go to the last interval,
    which becomes 3 blocks plus 15 bytes (63 bytes)::

        >>> range_boundaries(175, 4, 16)
        [0, 32, 80, 112, 175]
    """

    blocks = data_length // block_size
    return [block_size * (blocks * i // parts) for i in range(parts)] + [data_length]


def run_in_threads(worker: Callable[[int], T], count: int) -> list[T]:
    """Create ``count-1`` threads, each with a unique number from 1 to
    ``count-1``.

    Each thread runs the ``worker`` with the unique number as parameter.

    ``worker`` is also called by the current thread with number 0.

    It returns when all workers have finished, even if some of them raised
    an exception: it then raises the first one.

    :return: the list of the values returned by each call
    """

    # Each thread stores its result under its own key
    results: dict[int, T] = {}
    errors: list[BaseException] = []

    def run(i: int) -> None:
        try:
            results[i] = worker(i)
        except Exception as e:
            errors.append(e)

    workers = [threading.Thread(target=run, args=(i,), daemon=True) for i in range(1, count)]
    for t in workers:
        t.start()

    # The calling thread does its share, while the others run
    try:
        run(0)
    finally:
        for t in workers:
            t.join()

    if errors:
        raise errors[0]
    return [results[i] for i in range(count)]
