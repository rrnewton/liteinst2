#!/bin/sh
# Supplied-metadata retired observer component; no archive, guest or owner credit.
# Caller imposes the unchanged 5 CPU/15 wall/512 MiB/16 MiB bounds.
set -eu
test "$#" -eq 3
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "${LI2_PYTHON:-python3}" -I -S -B "$fixture/prepare.py" "$1" "$2" "$3" "${LI2_CC:-cc}"
