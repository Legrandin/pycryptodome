"""Tests of the helpers for the ``threads`` parameter"""

import threading

import pytest

from Crypto.Util._cpu_features import available_cores
from Crypto.Util._threads import range_boundaries, run_in_threads, threads_param


def test_threads_param():
    assert threads_param(1) == 1
    assert threads_param(7) == 7
    assert threads_param(0) == available_cores()
    for threads in (1.0, "2", None, True, False):
        with pytest.raises(TypeError):
            threads_param(threads)
    for threads in (-1, -8):
        with pytest.raises(ValueError):
            threads_param(threads)


@pytest.mark.parametrize("unit", (1, 16, 8192))
def test_range_boundaries(unit):
    for length in (0, 1, unit - 1, unit, unit + 1, 5 * unit, 5 * unit + 3, 1000 * unit + 7):
        for parts in (1, 2, 3, 8):
            bounds = range_boundaries(length, parts, unit)
            assert len(bounds) == parts + 1
            assert bounds[0] == 0
            assert bounds[-1] == length
            assert bounds == sorted(bounds)
            # Ranges start at a multiple of the unit, and differ by at most one unit
            assert all(b % unit == 0 for b in bounds[:-1])
            sizes = [(bounds[i + 1] - bounds[i]) // unit for i in range(parts - 1)]
            sizes.append((length // unit * unit - bounds[-2]) // unit)
            assert max(sizes) - min(sizes) <= 1


def test_run_in_threads():
    callers = {}

    def worker(i):
        callers[i] = threading.current_thread()
        return i * 10

    assert run_in_threads(worker, 5) == [0, 10, 20, 30, 40]
    # The first call runs in the calling thread, the others in new threads
    assert callers[0] is threading.current_thread()
    assert len({id(callers[i]) for i in range(5)}) == 5

    assert run_in_threads(worker, 1) == [0]


@pytest.mark.parametrize("failing", (0, 1, 3))
def test_run_in_threads_error(failing):
    # All calls finish before the exception is raised
    done = []

    def worker(i):
        if i == failing:
            raise KeyError(i)
        threading.Event().wait(0.05)
        done.append(i)

    with pytest.raises(KeyError):
        run_in_threads(worker, 4)
    assert sorted(done) == [i for i in range(4) if i != failing]
