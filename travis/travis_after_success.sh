#!/bin/bash
set -e -x

printenv

if [[ !(${TRAVIS_PYTHON_VERSION} == 2.7 && ${CFFI} == yes) ]]; then
    exit 1
fi

# Only builds Linux wheels for tagged commits
if [ "${TRAVIS_TAG}"x == x ]; then
    exit 2
fi

DOCKER_IMAGE_1=quay.io/pypa/manylinux1_x86_64
DOCKER_IMAGE_2=quay.io/pypa/manylinux1_i686

docker pull $DOCKER_IMAGE_1
docker run --rm -v `pwd`:/io $DOCKER_IMAGE_1 /io/travis/build-wheels.sh

docker pull $DOCKER_IMAGE_2
docker run --rm -v `pwd`:/io $DOCKER_IMAGE_2 linux32 /io/travis/build-wheels.sh

ls wheelhouse/

# Keep only manylinux files
find wheelhouse -type f -name '*-linux_*' -delete
