"""This file (which is sourced, not imported) checks the version of the
"versioncheck" package. It is also an example of how to format your own
_checkversion.py file"""

import pyversioncheck

_PACKAGE="Crypto"
_VERSION="1.1a2"
_URL="http://starship.skyport.net/crew/amk/versions/pct.txt"

try:
	_myverbose=VERBOSE
except NameError:
	_myverbose=1
	
pyversioncheck.versioncheck(_PACKAGE, _URL, _VERSION, verbose=_myverbose)
