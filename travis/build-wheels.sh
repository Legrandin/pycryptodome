#!/bin/bash
set -e -x

# Install a system package required by our library
yum install -y gmp

WH=/io/wheelhouse/$(uname -p)

# Compile wheels
for PYBIN in /opt/python/*/bin; do
#    "${PYBIN}/pip" install -r /io/dev-requirements.txt
    "${PYBIN}/pip" wheel /io/ -w ${WH}
done

# Bundle external shared libraries into the wheels
for whl in ${WH}/*.whl; do
    auditwheel repair "$whl" -w ${WH}
done

# Install packages and test
for PYBIN in /opt/python/*/bin/; do
    "${PYBIN}/pip" install pycryptodome --no-index -f ${WH}
    "${PYBIN}/python" -m Crypto.SelfTest
done
