#!/bin/bash
set -e -x

export CFLAGS="-Wconversion"

if [ x${OLDPY} == x ]; then
	PYTHON=python
else
	PYTHON=${OLDPY}
	export PYTHONPATH=${PWD}/custom_packages
fi

echo ${PYTHON}

PYVERSION=$(${PYTHON} -V 2>&1)
echo ${PYVERSION}

${PYTHON} -c "import cffi" 2>/dev/null && echo CFFI is installed || true

if [ x${CFFI} = "xyes" ]; then
	${PYTHON} -c"import cffi"
fi

if [ x${CFFI} != "xyes" ]; then
	! ${PYTHON} -c"import cffi" 2>/dev/null
fi

MAJOR=$(echo ${PYVERSION} | cut -f2 -d' ' | cut -f1 -d'.')

if [ "${MAJOR}" -ge 3 ]; then
	xflags="$xflags -bb"
fi

if [[ ${PYVERSION} != *"PyPy"* ]] || [ "${MAJOR}" -lt 3 ]; then
	xflags="$xflags -tt"
fi

echo "Custom Python flags:" \"${xflags:-none}\"

${PYTHON} $xflags setup.py build
${PYTHON} $xflags setup.py test
