#!/bin/sh
# Generates ./src/config.h.in and ./configure

set -e
aclocal
autoheader
autoconf
