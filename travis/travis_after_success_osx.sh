#!/bin/bash
set -e -x

printenv

# Only builds OSX wheels for tagged commits
if [ "${TRAVIS_TAG}"x == x ]; then
    exit 2
fi

pip2 install --user cibuildwheel==0.10.1
cibuildwheel --output-dir wheelhouse
ls wheelhouse
