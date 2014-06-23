Installation
------------

The procedures below all perform the same actions, just in different operating systems:

#. Install ``virtualenv``
#. Install a C compiler
#. Create a virtual environment (and install ``pip`` in it)
#. Download PyCryptodome from ``pypi``
#. Compile the C extensions of PyCryptodome
#. Install PyCryptodome in the virtual environment
#. Run the test suite to verify that all algorithms work correctly

.. note::

        PyCryptodome resides in the same namespace of PyCrypto (``Crypto``).
        In order to avoid any possible conflict, these instructions do not
        install PyCryptodome at the system level.

Linux Ubuntu
~~~~~~~~~~~~

For Python 2.x::

        $ sudo apt-get install build-essential libgmp3-dev
        $ sudo apt-get install python-virtualenv python-dev
        $ virtualenv -p /usr/bin/python2 MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ python -m Crypto.SelfTest

For Python 3.x::

        $ sudo apt-get install build-essential libgmp3-dev
        $ sudo apt-get install python-virtualenv python3-dev
        $ virtualenv -p /usr/bin/python3 MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ python3 -m Crypto.SelfTest

For PyPy::

        $ sudo apt-get install build-essential libgmp3-dev
        $ sudo apt-get install python-virtualenv pypy-dev
        $ virtualenv -p /usr/bin/pypy MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ pypy -m Crypto.SelfTest

Linux Fedora
~~~~~~~~~~~~

For Python 2.x::

        $ sudo yum install gcc gmp-devel
        $ sudo yum install python-virtualenv python-devel 
        $ virtualenv -p /usr/bin/python2 MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ python -m Crypto.SelfTest

For Python 3.x::

        $ sudo yum install gcc gmp-devel
        $ sudo yum install python-virtualenv python3-devel 
        $ virtualenv -p /usr/bin/python3 MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ python3 -m Crypto.SelfTest

For PyPy::

        $ sudo apt-get install build-essential libgmp3-dev
        $ sudo apt-get install python-virtualenv pypy-devel
        $ virtualenv -p /usr/bin/pypy MyProject
        $ cd MyProject
        $ . bin/activate
        $ pip install pycryptodome
        $ pypy -m Crypto.SelfTest

Windows
~~~~~~~

.. note::

        Installing a Python package with C extensions (like PyCryptodome)
        is clearly very complicated on Windows.      
        In the future, pre-compiled binaries will be made available
        as `Python wheels <http://pythonwheels.com/>`_ on ``pypi``.

#. Make sure the directory where your Python is installed and its subdirectory ``Scripts``
   are included in your ``PATH`` environmental variable.

#. You need to know exactly the version of Python you have and
   whether it is a 32 bit or a 64 bit application.
   You can easily discover that by running the interpreter from the command
   prompt. Look at the very first line it prints.

   For instance, if you see::

        Python 2.7.2+ ... [MSC v.1500 32 bit (Intel)] on win32

   You clearly have Python 2.7 and it is a 32 bit application.

#. **[Skip if you have Python 3.4 or newer]** Install ``pip`` by downloading and executing
   the Python script `get-pip.py`_::

        > python get-pip.py

#. Install ``virtualenv`` with::

        > pip install virtualenv

#. Install a Visual Studio C++ (MSVC) compiler that matches the runtime your Python
   is linked to. The good news is that the compilers can be found inside some Microsoft SDKs
   that are available free of charge from the Microsoft website.
   The bad news is that you need to download between 500MB and 1.4GB of data that mostly you will not need.

   The specific Microsoft SDK to download depends on the version of Python you have:

   * For Python 3.2 or older (including all 2.x), you need Visual C++ Compiler **2008** from the `MS Windows SDK for Windows 7 and .NET Framework 3.5 SP1`_.
   * For Python 3.3 or newer, you need Visual C++ Compiler **2010** from the `MS Windows SDK for Windows 7 and .NET Framework 4`_.

   In either case, you will be given the possibility to download three different ISO files.
   Most probably, these days you have a 64 bit version of a Windows OS so you can just
   select the file ``GRMSDKX_EN_DVD.iso`` (the other two ISOs are for 32 bit x86 and for IA).
   Mount the ISO (for instance by means of `Virtual Clone Drive`_) and install just
   the compiler and the redistributables.

#. If you have installed Visual C++ **2008** and your Python is a 64 bit application, perform the following steps::

        > cd "C:\Program Files\Microsoft SDKs\Windows\v7.0"
        > cmd /V:ON /K Bin\SetEnv.Cmd /x64 /release
        > set DISTUTILS_USE_SDK=1

   For other combinations, the steps need to be slightly adjusted:

   * If you have installed Visual C++ **2010** you must replace ``v7.0`` with ``v7.1``.
   * If your Python is a 32 bit application you must replace ``/x64`` with ``/x32``.

#. Create a virtual environment for your project::

        > virtualenv MyProject
        > cd MyProject
        > Scripts\activate

#. Congratulations. You should be able to install PyCryptodome with::

        > pip install pycryptodome

#. To make sure everything work fine, run the test suite::

        > python -m Crypto.SelfTest

.. _get-pip.py: https://bootstrap.pypa.io/get-pip.py
.. _MS Windows SDK for Windows 7 and .NET Framework 3.5 SP1: http://www.microsoft.com/en-us/download/details.aspx?id=18950
.. _MS Windows SDK for Windows 7 and .NET Framework 4: https://www.microsoft.com/en-us/download/details.aspx?id=8442
.. _Virtual Clone Drive: http://www.slysoft.com/it/virtual-clonedrive.html
