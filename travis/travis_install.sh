#!/bin/bash

set -x

sudo apt-get install libgmp10

PYV=$(python --version)
pip install setuptools
if [ x${CFFI} == xyes ] && [[ ${PYV} != *"PyPy"* ]]; then
	pip install cffi
fi
