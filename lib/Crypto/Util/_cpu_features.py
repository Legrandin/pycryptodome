# SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

import os

from Crypto.Util._raw_api import load_pycryptodome_raw_lib

_raw_cpuid_lib = load_pycryptodome_raw_lib(
    "Crypto.Util._cpuid_c",
    """
                                           int have_aes_ni(void);
                                           int have_clmul(void);
                                           int have_avx2(void);
                                           int have_bmi1(void);
                                           int have_bmi2(void);
                                           """,
)


def have_aes_ni() -> int:
    return _raw_cpuid_lib.have_aes_ni()


def have_clmul() -> int:
    return _raw_cpuid_lib.have_clmul()


def have_avx2() -> int:
    return _raw_cpuid_lib.have_avx2()


def have_bmi1() -> int:
    return _raw_cpuid_lib.have_bmi1()


def have_bmi2() -> int:
    return _raw_cpuid_lib.have_bmi2()


def available_cores() -> int:
    """Return the number of CPU cores this process can run on."""

    count: int | None
    # Python 3.13+: it takes into account CPU affinity and -X cpu_count
    if hasattr(os, "process_cpu_count"):
        count = os.process_cpu_count()
    elif hasattr(os, "sched_getaffinity"):
        count = len(os.sched_getaffinity(0))
    elif hasattr(os, "cpu_count"):
        count = os.cpu_count()
    else:
        import multiprocessing

        try:
            count = multiprocessing.cpu_count()
        except NotImplementedError:
            count = None
    return count or 1
