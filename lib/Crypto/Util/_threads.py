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
from typing import Any, Callable, List

from Crypto.Util._cpu_features import available_cores


def threads_param(threads: Any) -> int:
    """Check the ``threads`` parameter, and return the maximum number of
    threads to use (0 means as many as the CPU cores available)."""

    if not isinstance(threads, int) or isinstance(threads, bool):
        raise TypeError("'threads' must be an integer")
    if threads < 0:
        raise ValueError("'threads' must be a non-negative integer")
    if threads == 0:
        return available_cores()
    return threads


def range_boundaries(length: int, parts: int, unit: int = 1) -> List[int]:
    """Split ``length`` into ``parts`` contiguous ranges that start at
    a multiple of ``unit``, and differ by at most one unit.

    :return: the ``parts + 1`` boundaries: range ``i`` goes from
      item ``i`` to item ``i + 1``. The first item is 0, the last is ``length``
      (the last range also gets what is left beyond the last whole unit).
    """

    units = length // unit
    return [unit * (units * i // parts) for i in range(parts)] + [length]


def run_in_threads(worker: Callable[[int], Any], count: int) -> List[Any]:
    """Call ``worker(i)`` for each ``i`` in ``range(count)``, in parallel:
    ``worker(0)`` in the calling thread, the others in new threads.

    It returns when all calls have finished, even if some of them raised
    an exception: it then raises the first one.

    :return: the list of the values returned by each call
    """

    results: List[Any] = [None] * count
    errors: List[BaseException] = []

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
    return results
