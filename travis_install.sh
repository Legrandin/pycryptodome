#!/bin/bash

set -x

sudo apt-get install libgmp10

if [ x${PYTHON_INTP} = "x" ]; then
	echo "Undefined python implementation"
	exit 1
fi

if [ ${PYTHON_INTP} = "pypy" ]; then
	sudo add-apt-repository -y ppa:pypy/ppa
	sudo apt-get -y update
	sudo apt-get install -y --force-yes pypy pypy-dev
elif [ x$(which ${PYTHON_INTP}) = "x" ]; then
	sudo add-apt-repository -y ppa:fkrull/deadsnakes
	sudo apt-get -y update
	sudo apt-get install ${PYTHON_INTP} ${PYTHON_INTP}-dev
fi

${PYTHON_INTP} -V

PYV=$(${PYTHON_INTP} -V 2>&1 | head -1 | sed -n 's/\w\+ \([23]\)\.\([0-9]\).*/\1\2/p')

export PYTHONPATH=${PWD}/custom_packages
mkdir ${PYTHONPATH}

# Ctypes was only included in python 2.5, so it needs to be installed if we target python 2.4.
# We do not rely on pypi because it refers us to sourceforge, not the most available site around.
# Instead, we mirror ctypes on github.
if [ ${PYV} -eq 24 ]; then
	(
	cd /tmp
	git clone https://github.com/Legrandin/ctypes
	cd ctypes
	${PYTHON_INTP} setup.py build
	cp -r build/lib*/* ${PYTHONPATH}
	)
fi

# Why bother with pip/virtualenv complexity when we can just do this
install_from_pypi() {
	if [ "$2" = "latest" ]; then
		target_version=".info.version"
	else
		target_version=\"$2\"
	fi
	URL=$(curl -s https://pypi.python.org/pypi/$1/json | jq '.releases['$target_version']' | jq -r 'map(select(.python_version == "source"))[0].url')
	wget -q -O - $URL | tar -xzC /tmp
	(
	cd /tmp/$1-*
	${PYTHON_INTP} setup.py build
	cp -r build/lib*/* ${PYTHONPATH}
	)
}

if [ x${CFFI} = "xyes" -a ${PYTHON_INTP} != "pypy" ]; then
	if [ ${PYV} -lt 30 -o ${PYV} -gt 33 ]; then
		install_from_pypi setuptools latest
	else
		# setuptools 19.5 does not support Python 3.2 anymore
		install_from_pypi setuptools 19.4
	fi
	install_from_pypi cffi latest
fi
