Installation
------------

You install PyCryptodome with::

    pip install pycryptodome

All modules are installed under the ``Crypto`` package.
You can test everything is right with::

    pip install pytest pycryptodome-test-vectors
    python -m Crypto.SelfTest

This runs the complete test suite, which takes a few minutes.
Add ``--skip-slow-tests`` for a quicker check that skips the most
time-consuming test vectors.

One must avoid having both PyCrypto and PyCryptodome installed
at the same time, as they will interfere with each other.
This is not a problem if your application is deployed in a ``virtualenv``.

.. note::
    Starting with version 4.0, the ``pycryptodomex`` project
    (``Cryptodome`` package) is no longer released.

The procedures below go a bit more in detail, by explaining
how to setup the environment for compiling the C extensions
for each OS.

Compiling in Linux Ubuntu
~~~~~~~~~~~~~~~~~~~~~~~~~

For Python 3.x::

        $ sudo apt-get install build-essential python3-dev
        $ pip install pycryptodome
        $ pip install pytest pycryptodome-test-vectors
        $ python3 -m Crypto.SelfTest

For PyPy::

        $ sudo apt-get install build-essential pypy-dev
        $ pip install pycryptodome
        $ pip install pytest pycryptodome-test-vectors
        $ pypy -m Crypto.SelfTest

Compiling in Linux Fedora
~~~~~~~~~~~~~~~~~~~~~~~~~

For Python 3.x::

        $ sudo yum install gcc python3-devel
        $ pip install pycryptodome
        $ pip install pytest pycryptodome-test-vectors
        $ python3 -m Crypto.SelfTest

For PyPy::

        $ sudo yum install gcc pypy-devel
        $ pip install pycryptodome
        $ pip install pytest pycryptodome-test-vectors
        $ pypy -m Crypto.SelfTest


Windows (from sources)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows does not come with a C compiler like most Unix systems.
The simplest way to compile the *PyCryptodome* extensions from
source code is to install the minimum set of Visual Studio
components freely made available by Microsoft.

#. **[Once only]** Download `Build Tools for Visual Studio 2019 <https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019>`_.
   In the installer, select the *C++ build tools*, the *Windows 10 SDK*, and the latest version of *MSVC v142 x64/x86 build tools*.

#. Compile and install PyCryptodome::

        > pip install pycryptodome --no-binary :all:

#. To make sure everything work fine, run the test suite::

        > pip install pytest pycryptodome-test-vectors
        > python -m Crypto.SelfTest

Documentation
~~~~~~~~~~~~~

Project documentation is written in reStructuredText and it is stored under ``Doc/src``.
To publish it as HTML files, you need to install `sphinx <http://www.sphinx-doc.org/en/stable/>`_ and
use::

    > make -C Doc/ html

It will then be available under ``Doc/_build/html/``.

PGP verification
~~~~~~~~~~~~~~~~

All source packages and wheels on PyPI are cryptographically signed.
They can be verified with the following PGP key::

 -----BEGIN PGP PUBLIC KEY BLOCK-----
 
 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
 =DpoI
 -----END PGP PUBLIC KEY BLOCK-----

.. _pypi: https://pypi.python.org/pypi/pycryptodome
.. _get-pip.py: https://bootstrap.pypa.io/get-pip.py
