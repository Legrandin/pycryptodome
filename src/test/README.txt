In order to compile and run the tests you need cmake.

In Linux, do::

	cmake -B build -DSSE=1
	make -C build -j 8 all test

In Windows, do::

	cmake -B build -G "NMake Makefiles"
	cd build
	nmake all test
