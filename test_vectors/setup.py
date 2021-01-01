# ===================================================================
#
# Copyright (c) 2021, Legrandin <helderijs@gmail.com>
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

import os
from setuptools import setup, find_packages

project_name = "pycryptodome-test-vectors"
project_dir = "pycryptodome_test_vectors"

with open(os.path.join(project_dir, "__init__.py")) as init_root:
    for line in init_root:
        if line.startswith("__version__"):
            version_string = eval(line.split("=")[1])

longdesc = """
This package contains an extensive set of test vectors
to verify the PyCryptodome cryptographic library.

PyCryptdome can be installed with either the ``pycryptodome``
package (``Crypto`` namespace) or
the ``pycryptodomex`` package (``Cryptodome`` namespace).

For more information, see the `homepage`_.

.. _`homepage`: http://www.pycryptodome.org
"""

setup(
    name=project_name,
    version=version_string,
    description='Test vectors for PyCryptodome',
    url='https://www.pycryptodome.org',
    author='Helder Eijs',
    author_email="helderijs@gmail.com",
    platforms='Posix; MacOS X; Windows',
    zip_safe=False,
    packages=find_packages(),
    include_package_data=True,
    license="BSD, Apache",
    long_description=longdesc,
    options={'bdist_wheel':{'universal':True}},
)
