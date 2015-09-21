Installation
------------

The procedures below all perform the same actions:

#. Install ``virtualenv`` and ``pip``
#. Create a virtual environment
#. Download PyCryptodome from `pypi`_
#. *(In Unix only)* Compile the C extensions of PyCryptodome
#. Install PyCryptodome in the virtual environment
#. Run the test suite to verify that all algorithms work correctly

.. note::

        PyCryptodome resides in the same namespace of PyCrypto (``Crypto``).
        In order to avoid any possible conflict, these instructions do not
        install PyCryptodome at the system level.

Linux Ubuntu
~~~~~~~~~~~~

For Python 2.x::

        $ sudo apt-get install build-essential libgmp3c2
        $ sudo apt-get install python-virtualenv python-dev
        $ virtualenv -p /usr/bin/python2 MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ python -m Crypto.SelfTest

For Python 3.x::

        $ sudo apt-get install build-essential libgmp3c2
        $ sudo apt-get install python-virtualenv python3-dev
        $ virtualenv -p /usr/bin/python3 MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ python3 -m Crypto.SelfTest

For PyPy::

        $ sudo apt-get install build-essential libgmp3c2
        $ sudo apt-get install python-virtualenv pypy-dev
        $ virtualenv -p /usr/bin/pypy MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ pypy -m Crypto.SelfTest

Linux Fedora
~~~~~~~~~~~~

For Python 2.x::

        $ sudo yum install gcc gmp
        $ sudo yum install python-virtualenv python-devel 
        $ virtualenv -p /usr/bin/python2 MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ python -m Crypto.SelfTest

For Python 3.x::

        $ sudo yum install gcc gmp
        $ sudo yum install python3-virtualenv python3-devel
        $ virtualenv -p /usr/bin/python3 MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ python3 -m Crypto.SelfTest

For PyPy::

        $ sudo yum install gcc gmp
        $ sudo yum install python-virtualenv pypy-devel
        $ virtualenv -p /usr/bin/pypy MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ pypy -m Crypto.SelfTest

Windows (pre-compiled)
~~~~~~~~~~~~~~~~~~~~~~

#. Make sure that the ``PATH`` environment variable contains
   the directory of your Python interpreter and its subdirectory ``Scripts``.

   Typically, that means typing something like this
   at the command prompt::

       > set PATH=%PATH%;C:\Python27;C:\Python27\Scripts

   or::

       > set PATH=%PATH%;C:\Python34;C:\Python34\Scripts

#. Run Python from the command line and note down its version
   and whether it is a 32 bit or a 64 bit application.

   For instance, if you see::

        Python 2.7.2+ ... [MSC v.1500 32 bit (Intel)] on win32

   You clearly have Python 2.7 and it is a 32 bit application.

#. **[Only once. Skip if you have Python 3.4 or newer]**
   Install ``pip`` by downloading and executing the Python
   script `get-pip.py`_::

        > python get-pip.py

#. **[Only once]** Install ``virtualenv`` with::

        > pip install virtualenv

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

#. Create a virtual environment for your project::

        > cd %USERPROFILE%
        > virtualenv MyProject
        > cd MyProject
        > Scripts\activate

#. Install PyCryptodome as a `wheel <http://pythonwheels.com/>`_::

        > pip install pycryptodome

#. To make sure everything works fine, run the test suite::

        > python -m Crypto.SelfTest

Windows (from sources, Python 2.x, Python <=3.2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows does not come with a C compiler like most Unix systems.
The simplest way to compile the *Pycryptodome* extensions from
source code is to install the minimum set of Visual Studio
components freely made available by Microsoft.

#. Perform all steps from the previous section and stop
   before executing ``pip install pycryptodome``.

#. **[Only once]** Install `Virtual Clone Drive`_.

#. **[Only once]** Download the ISO image of the `Microsoft SDK for Windows 7 and . NET Framework 3.5 SP1`_.
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

#. Enter the virtual environment for your project::

        > cd %USERPROFILE%
        > cd MyProject
        > Scripts\activate

#. Compile and install PyCryptodome::

        > pip install pycryptodome --no-use-wheel

#. To make sure everything work fine, run the test suite::

        > python -m Crypto.SelfTest

Windows (from sources, Python 3.3 and 3.4)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows does not come with a C compiler like most Unix systems.
The simplest way to compile the *Pycryptodome* extensions from
source code is to install the minimum set of Visual Studio
components freely made available by Microsoft.

#. Perform all steps from the previous section and stop
   before executing ``pip install pycryptodome``.

#. **[Only once]** Install `Virtual Clone Drive`_.

#. **[Only once]** Download the ISO image of the `Microsoft SDK for Windows 7 and . NET Framework 4`_.
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

#. Enter the virtual environment for your project::

        > cd %USERPROFILE%
        > cd MyProject
        > Scripts\activate

#. Compile and install PyCryptodome::

        > pip install pycryptodome --no-use-wheel

#. To make sure everything work fine, run the test suite::

        > python -m Crypto.SelfTest

Windows (from sources, Python 3.5 and newer)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows does not come with a C compiler like most Unix systems.
The simplest way to compile the *Pycryptodome* extensions from
source code is to install the minimum set of Visual Studio
components freely made available by Microsoft.

#. **[Once only]** Download `MS Windows Studio 2015`_ (Community Edition) and install the C/C++
   compilers and the redistributable only.

#. Perform all steps from the section *Windows (pre-compiled)* but add the ``--no-use-wheel``
   parameter when calling ``pip``.

        > pip install pycryptodome --no-use-wheel

.. _pypi: https://pypi.python.org/pypi/pycryptodome
.. _get-pip.py: https://bootstrap.pypa.io/get-pip.py
.. _MS Windows SDK for Windows 7 and .NET Framework 3.5 SP1: http://www.microsoft.com/en-us/download/details.aspx?id=18950
.. _MS Windows SDK for Windows 7 and .NET Framework 4: https://www.microsoft.com/en-us/download/details.aspx?id=8442
.. _Virtual Clone Drive: http://www.slysoft.com/it/virtual-clonedrive.html
.. _MPIR: http://mpir.org
.. _GMP: http://gmplib.org
.. _MS Visual Studio 2015: https://www.visualstudio.com/en-us/downloads/download-visual-studio-vs.aspx
