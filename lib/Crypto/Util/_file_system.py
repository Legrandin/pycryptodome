# SPDX-FileCopyrightText: 2016 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

import os


def pycryptodome_filename(dir_comps: list[str], filename: str) -> str:
    """Return the complete file name for the module

    dir_comps : list of string
        The list of directory names in the PyCryptodome package.
        The first element must be "Crypto".

    filename : string
        The filename (inclusing extension) in the target directory.
    """

    if dir_comps[0] != "Crypto":
        raise ValueError("Only available for modules under 'Crypto'")

    dir_comps = list(dir_comps[1:]) + [filename]

    util_lib, _ = os.path.split(os.path.abspath(__file__))
    root_lib = os.path.join(util_lib, "..")

    return os.path.join(root_lib, *dir_comps)
