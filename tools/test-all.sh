#!/bin/bash
# Script used to build PyCrypto under all Python versions
# Edit it to suit your needs.
# by Dwayne Litzenberger
#
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

set -e
PREFIX=${PREFIX:-$(dirname "$(readlink -f "$0")")/py}

export -n PREFIX    # unexport

find "$PREFIX"/pythons/python* -maxdepth 0 -type d -print0 | sort -z | while IFS= read -d '' -r pythondir
do
    echo "=== `basename $pythondir` ==="
    "$pythondir"/bin/python?.? setup.py -q build
    "$pythondir"/bin/python?.? setup.py -q test
done
