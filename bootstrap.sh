#!/bin/sh
# Generates ./src/config.h.in and ./configure

set -e
aclocal --force -I m4
autoconf --force
autoheader --force

# The following line is needed to generate build-aux/*, but it will fail
# because we have no Makefile.am
mkdir -p build-aux
echo "** You can ignore the following error about a missing Makefile.am"
automake --add-missing --copy || true
