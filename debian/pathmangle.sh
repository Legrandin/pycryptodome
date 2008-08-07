#! /bin/sh
#
# This script is used to mangle things like /usr/local/bin/python into
# something more in line with Debian's Python policy.

set -e

CMD=$1
DIR=$2

grep -E -l -r '/usr/local(/bin)?/python' "$DIR" |
    while read f; do
        printf ",s:/usr/local\\\\(/bin\\\\)\\\\?/python:$CMD:g\nw\n" | ed -s "$f"
        if [ "$(head -c2 $f)" = "#!" ]; then
            chmod 755 "$f"
        fi
    done
