#!/bin/bash
set -e -x

export CFLAGS="-Wconversion"

PYVERSION=$(python -V 2>&1)
echo ${PYVERSION}

python -c "import cffi" 2>/dev/null && echo CFFI is installed || true

if [ x${CFFI} = "xyes" ]; then
	python -c"import cffi"
fi

if [ x${CFFI} != "xyes" ]; then
	! python -c"import cffi" 2>/dev/null
fi

MAJOR=$(echo ${PYVERSION} | cut -f2 -d' ' | cut -f1 -d'.')

if [ "${MAJOR}" -ge 3 ]; then
	xflags="$xflags -bb"
fi

if [[ ${PYVERSION} != *"PyPy"* ]] || [ "${MAJOR}" -lt 3 ]; then
	xflags="$xflags -tt"
fi

echo "Custom Python flags:" \"${xflags:-none}\"

python $xflags setup.py build
python $xflags setup.py test
