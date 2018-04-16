#!/bin/bash

set -x

sudo apt-get install libgmp10

install_from_pypi() {
	if [ "$2" = "latest" ]; then
		target_version=".info.version"
	else
		target_version=\"$2\"
	fi
	URL=$(curl -s https://pypi.org/pypi/$1/json | jq '.releases['$target_version']' | jq -r 'map(select(.python_version == "source"))[0].url')
	(
	cd /tmp
	wget -q "$URL"
	FILENAME="$(basename ${URL})"
	EXT="${FILENAME:(-3)}"
	echo "Filename:" "$FILENAME" "(ext:${EXT})"
	if [ "${EXT}" = "zip" ]; then
		unzip "$FILENAME"
	else
		tar -xzf "$FILENAME"
	fi
	cd /tmp/$1-*
	$3 setup.py build
	cp -r build/lib*/* ${PYTHONPATH}
	)
}

if [ x${OLDPY} != x ]; then
	export PYTHON=${OLDPY}
	sudo add-apt-repository -y ppa:deadsnakes/ppa
	sudo apt-get -y update
	sudo apt-get install ${PYTHON} ${PYTHON}-dev
	mkdir ${PWD}/custom_packages
	export PYTHONPATH=${PWD}/custom_packages
	install_from_pypi setuptools 19.4 ${PYTHON}
	if [ x${CFFI} == xyes ]; then
		install_from_pypi cffi latest ${PYTHON}
	fi
else
	export PYTHON=python
	PYV=$(python --version)
	pip install setuptools
	if [ x${CFFI} == xyes ] && [[ ${PYV} != *"PyPy"* ]]; then
		pip install cffi
	fi
fi
