#!/bin/bash
set -e -x

printenv

# Only builds OSX wheels for tagged commits
if [ "${TRAVIS_TAG}"x == x ]; then
    exit 2
fi

cibuildwheel --output-dir wheelhouse
ls wheelhouse
