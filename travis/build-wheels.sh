#!/bin/bash
set -e -x

# Left-overs from previous builds may be binary incompatible
rm -fr /io/build

# Install a system package required by our library
yum install -y gmp

if [ -f /io/.separate_namespace ]; then
    PKG_NAME=pycryptodomex
    NAMESPACE=Cryptodome
else
    PKG_NAME=pycryptodome
    NAMESPACE=Crypto
fi

WH=/io/wheelhouse/${PACKAGE_NAME}/$(uname -p)

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
    "${PYBIN}/pip" install ${PKG_NAME} --no-index -f ${WH}
    "${PYBIN}/python" -m ${NAMESPACE}.SelfTest --skip-slow-tests
done
