Installation
------------

Linux/Unix
~~~~~~~~~~

Set up your environment so that you can compile Python C extensions via ``pip``.
It is also recommeded you install ``virtualenv`` and the development libraries for the GMP library.

On a platform like Ubuntu, for Python 2.x, that can be done with::

	$ sudo apt-get install build-essential libgmp3-dev python-virtualenv
        $ sudo apt-get install python-pip python-dev

For Python 3.x::

        $ sudo apt-get install build-essential libgmp3-dev python-virtualenv
	$ sudo apt-get install python3-pip python3-dev

Once the (virtual) environment is in place, proceed with::

	$ pip install pycryptodome

Windows
~~~~~~~

First, unless you have Python 3.4 or newer, install ``pip`` as explained on
the `official installation page <https://pip.pypa.io/en/latest/installing.html>`_.
Python 3.4 ships with ``pip`` by default.

Second, install a Visual Studio C++ compiler that matches the runtime your Python
is linked to.

That means:

 * For Python 3.2 or older (including all 2.x), Visual C++ Compiler 2008 from the `MS Windows SDK for Windows 7 and .NET Framework 3.5 SP1 <http://www.microsoft.com/en-us/download/details.aspx?id=18950>`_.
 * For Python 3.3 or newer, Visual C++ Compiler 2010 from the `MS Windows SDK for Windows 7 and .NET Framework 4 <https://www.microsoft.com/en-us/download/details.aspx?id=8442>`_.

For 32 bit versions of Python, download the file ``GRMSDK_EN_DVD.iso``, open a command
prompt and execute the following steps::

        > "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
        > set MSSdk=1
        > setenv /x86 /release
        > set DISTUTILS_USE_SDK=1

replace *9.0* with *10.0* depending on the version of Visual Studio.

For 64 bit version of Python, download the file ``GRMSDKX_EN_DVD.iso``, open a command
prompt and execute the following steps::

        > "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\bin\vcvars64.bat"
        > set MSSdk=1
        > setenv /x64 /release
        > set DISTUTILS_USE_SDK=1

Again, replace *9.0* with *10.0* depending on the version of Visual Studio.

At the end of all of this, you should be able to install PyCryptodome in your
(virtual) environment with::

        > pip install pycryptodome


