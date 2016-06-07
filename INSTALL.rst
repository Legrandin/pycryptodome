Installation
------------

The installation procedure depends on the package you want the library in.
PyCryptodome can be used as:

 #. **a drop-in replacement for the old PyCrypto library**.
    You install it with::

        pip install pycryptodome
   
    In this case, all modules are installed under the ``Crypto`` package.
    You can test everything is right with::
		
         python -m Crypto.SelfTest
   
    One must avoid having both PyCrypto and PyCryptodome installed
    at the same time, as they will interfere with each other.

    This option is therefore recommended only when you are sure that
    the whole application is deployed in a ``virtualenv``.

 #. **a library independent of the old PyCrypto**.
    You install it with::

        pip install pycryptodomex
   
    You can test everything is right with::
		
        python -m Cryptodome.SelfTest
  
    In this case, all modules are installed under the ``Cryptodome`` package.
    PyCrypto and PyCryptodome can coexist.

The procedures below go a bit more in detail, by explaining
how to setup the environment for compiling the C extensions
for each OS, and how to install the GMP library.

All instructions to follow install PyCryptodome as the ``Cryptodome`` package
(option #2). Change ``pycryptodomex`` to ``pycryptodome`` if you prefer
option #1 (``Crypto`` package).

Linux Ubuntu
~~~~~~~~~~~~

For Python 2.x::

        $ sudo apt-get install build-essential libgmp3-dev python-dev
        $ pip install pycryptodomex
        $ python -m Cryptodome.SelfTest

For Python 3.x::

        $ sudo apt-get install build-essential libgmp3-dev python3-dev
        $ pip install pycryptodomex
        $ python3 -m Cryptodome.SelfTest

For PyPy::

        $ sudo apt-get install build-essential libgmp3-dev pypy-dev
        $ pip install pycryptodomex
        $ pypy -m Cryptodome.SelfTest

Linux Fedora
~~~~~~~~~~~~

For Python 2.x::

        $ sudo yum install gcc gmp python-devel 
        $ pip install pycryptodomex
        $ python -m Cryptodome.SelfTest

For Python 3.x::

        $ sudo yum install gcc gmp python3-devel
        $ pip install pycryptodomex
        $ python3 -m Cryptodome.SelfTest

For PyPy::

        $ sudo yum install gcc gmp pypy-devel
        $ pip install pycryptodomex
        $ pypy -m Cryptodome.SelfTest

Windows (pre-compiled)
~~~~~~~~~~~~~~~~~~~~~~

#. Install PyCryptodome as a `wheel <http://pythonwheels.com/>`_::

        > pip install pycryptodomex

#. To make sure everything works fine, run the test suite::

        > python -m Cryptodome.SelfTest

Windows (from sources, Python 2.x, Python <=3.2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows does not come with a C compiler like most Unix systems.
The simplest way to compile the *Pycryptodome* extensions from
source code is to install the minimum set of Visual Studio
components freely made available by Microsoft.

#. Run Python from the command line and note down its version
   and whether it is a 32 bit or a 64 bit application.

   For instance, if you see::

        Python 2.7.2+ ... [MSC v.1500 32 bit (Intel)] on win32

   you clearly have Python 2.7 and it is a 32 bit application.

#. **[Only once]** In order to speed up asymmetric key algorithms like RSA,
   it is recommended to install the MPIR_ library (a fork of the popular
   GMP_ library, more suitable for the Windows environment).
   For convenience, I made available pre-compiled *mpir.dll* files to match
   the various types of Python one may have:
    
     - Python 2.x, 3.1, 3.2 (VS2008 runtime)
       
       - `32 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2008_32/mpir.dll>`_
       - `64 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2008_64/mpir.dll>`_
     
     - Python 3.3 and 3.4 (VS2010 runtime)
       
       - `32 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2010_32/mpir.dll>`_
       - `64 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2010_64/mpir.dll>`_

     - Python 3.5 (VS2015 runtime)

       - `32 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2015_32/mpir.dll>`_
       - `64 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2015_64/mpir.dll>`_

   Download the correct *mpir.dll* and drop it into the Python interpreter
   directory (for instance ``C:\Python34``). *Pycryptodome* will
   automatically make use of it.

#. **[Only once]** Install `Virtual Clone Drive`_.

#. **[Only once]** Download the ISO image of the `MS SDK for Windows 7 and . NET Framework 3.5 SP1`_.
   It contains the Visual C++ 2008 compiler.
   
   There are three ISO images available: you will need ``GRMSDK_EN_DVD.iso`` if your
   Windows OS is 32 bits or ``GRMSDKX_EN_DVD.iso`` if 64 bits.

   Mount the ISO with *Virtual Clone Drive* and install the C/C++ compilers and the
   redistributable only.

#. If your Python is a 64 bit application, open a command prompt and perform the following steps::

        > cd "C:\Program Files\Microsoft SDKs\Windows\v7.0"
        > cmd /V:ON /K Bin\SetEnv.Cmd /x64 /release
        > set DISTUTILS_USE_SDK=1
   
   Replace ``/x64`` with ``/x86`` if your Python is a 32 bit application.

#. Compile and install PyCryptodome::

        > pip install pycryptodomex --no-use-wheel

#. To make sure everything work fine, run the test suite::

        > python -m Cryptodome.SelfTest

Windows (from sources, Python 3.3 and 3.4)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows does not come with a C compiler like most Unix systems.
The simplest way to compile the *Pycryptodome* extensions from
source code is to install the minimum set of Visual Studio
components freely made available by Microsoft.

#. Run Python from the command line and note down its version
   and whether it is a 32 bit or a 64 bit application.

   For instance, if you see::

        Python 2.7.2+ ... [MSC v.1500 32 bit (Intel)] on win32

   you clearly have Python 2.7 and it is a 32 bit application.

#. **[Only once]** In order to speed up asymmetric key algorithms like RSA,
   it is recommended to install the MPIR_ library (a fork of the popular
   GMP_ library, more suitable for the Windows environment).
   For convenience, I made available pre-compiled *mpir.dll* files to match
   the various types of Python one may have:
    
     - Python 2.x, 3.1, 3.2 (VS2008 runtime)
       
       - `32 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2008_32/mpir.dll>`_
       - `64 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2008_64/mpir.dll>`_
     
     - Python 3.3 and 3.4 (VS2010 runtime)
       
       - `32 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2010_32/mpir.dll>`_
       - `64 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2010_64/mpir.dll>`_

     - Python 3.5 (VS2015 runtime)

       - `32 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2015_32/mpir.dll>`_
       - `64 bits <https://github.com/Legrandin/mpir-windows-builds/blob/master/mpir-2.6.0_VS2015_64/mpir.dll>`_

   Download the correct *mpir.dll* and drop it into the Python interpreter
   directory (for instance ``C:\Python34``). *Pycryptodome* will
   automatically make use of it.

#. **[Only once]** Install `Virtual Clone Drive`_.

#. **[Only once]** Download the ISO image of the `MS SDK for Windows 7 and . NET Framework 4`_.
   It contains the Visual C++ 2010 compiler.
   
   There are three ISO images available: you will need ``GRMSDK_EN_DVD.iso`` if your
   Windows OS is 32 bits or ``GRMSDKX_EN_DVD.iso`` if 64 bits.

   Mount the ISO with *Virtual Clone Drive* and install the C/C++ compilers and the
   redistributable only.

#. If your Python is a 64 bit application, open a command prompt and perform the following steps::

        > cd "C:\Program Files\Microsoft SDKs\Windows\v7.1"
        > cmd /V:ON /K Bin\SetEnv.Cmd /x64 /release
        > set DISTUTILS_USE_SDK=1
   
   Replace ``/x64`` with ``/x86`` if your Python is a 32 bit application.

#. Compile and install PyCryptodome::

        > pip install pycryptodomex --no-use-wheel

#. To make sure everything work fine, run the test suite::

        > python -m Cryptodome.SelfTest

Windows (from sources, Python 3.5 and newer)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows does not come with a C compiler like most Unix systems.
The simplest way to compile the *Pycryptodome* extensions from
source code is to install the minimum set of Visual Studio
components freely made available by Microsoft.

#. **[Once only]** Download `MS Visual Studio 2015`_ (Community Edition) and install the C/C++
   compilers and the redistributable only.

#. Perform all steps from the section *Windows (pre-compiled)* but add the ``--no-use-wheel``
   parameter when calling ``pip``::

        > pip install pycryptodomex --no-use-wheel

.. _pypi: https://pypi.python.org/pypi/pycryptodome
.. _get-pip.py: https://bootstrap.pypa.io/get-pip.py
.. _MS Windows SDK for Windows 7 and .NET Framework 3.5 SP1: http://www.microsoft.com/en-us/download/details.aspx?id=18950
.. _MS Windows SDK for Windows 7 and .NET Framework 4: https://www.microsoft.com/en-us/download/details.aspx?id=8442
.. _Virtual Clone Drive: http://www.slysoft.com/it/virtual-clonedrive.html
.. _MPIR: http://mpir.org
.. _GMP: http://gmplib.org
.. _MS Visual Studio 2015: https://www.visualstudio.com/en-us/downloads/download-visual-studio-vs.aspx
