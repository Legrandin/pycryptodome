#!/bin/bash
set -e -x

printenv
ARCH=`uname -m`

# On Arm64, only build wheels in the Python 3.8 job
if [[ "$ARCH" = "aarch64" ]]; then
	if [[ !(${TRAVIS_PYTHON_VERSION} == 3.8 && ${CFFI} == yes) ]]; then
		exit 1;
	fi
# On Arm64, only build wheels in the Python 2.7 job
elif [[ "$ARCH" = "x86_64" ]]; then
	if [[ !(${TRAVIS_PYTHON_VERSION} == 2.7 && ${CFFI} == yes) ]]; then
		exit 1
	fi
fi

# Only builds Linux wheels for tagged commits
if [ "${TRAVIS_TAG}"x == x ]; then
    exit 2
fi

if [ "$ARCH" = "aarch64" ]; then
	DOCKER_IMAGE=quay.io/pypa/manylinux2014_aarch64

	docker pull $DOCKER_IMAGE
	docker run --rm -v `pwd`:/io $DOCKER_IMAGE /io/travis/build-wheels.sh
else
	DOCKER_IMAGE_1=quay.io/pypa/manylinux1_x86_64
	DOCKER_IMAGE_2=quay.io/pypa/manylinux1_i686

	docker pull $DOCKER_IMAGE_1
	docker run --rm -v `pwd`:/io $DOCKER_IMAGE_1 /io/travis/build-wheels.sh

	docker pull $DOCKER_IMAGE_2
	docker run --rm -v `pwd`:/io $DOCKER_IMAGE_2 linux32 /io/travis/build-wheels.sh
fi

ls wheelhouse/

# Keep only manylinux files
sudo find wheelhouse -type f -name '*-linux_*' -delete
