CPPFLAGS += -I.. $(shell python -c "import sys; print '-DPYCRYPTO_' + sys.byteorder.upper() + '_ENDIAN'")
CPPFLAGS += -DHAVE_POSIX_MEMALIGN -DHAVE_STDINT_H
CPPFLAGS += -DSTATIC=""
CFLAGS += -O3 -g -fstrict-aliasing -Wall -Werror

TAPPS:=tests_addmul128_32 tests_addmul128_64 tests_square_w_32 tests_square_w_64 tests_product tests_addmul test_endianess\
       test_poly1305_reduce test_poly1305_load_r test_poly1305_load_m test_poly1305_multiply test_poly1305_accumulate\
	   test_mont

ifneq (,$(filter $(shell uname -m),x86_64 i386 i686))
CPPFLAGS += -DHAVE_X86INTRIN_H
CFLAGS += -msse2
TAPPS += test_clmul
endif

ifeq (64bit, $(shell python -c "import platform; print platform.architecture()[0]"))
CPPFLAGS += -DHAVE_UINT128
endif

CPPFLAGS += $(UNDEFS)

TGTS:=$(foreach t,$(TAPPS),build/$t)

test: build ${TGTS}
	set -e && for t in ${TGTS}; do $$t; done

build:
	mkdir build

all: ${$TGTS}

clean:
	rm -fr build

# addmul

build/tests_addmul128.c: make_tests_addmul128.py
	python $^ > $@

build/tests_addmul128_32: build/tests_addmul128.c ../multiply_32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

build/tests_addmul128_64: build/tests_addmul128.c ../multiply_64.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

# square_w

build/tests_square_w.c: make_tests_square_w.py
	python $^ > $@

build/tests_square_w_32: build/tests_square_w.c ../multiply_32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

build/tests_square_w_64: build/tests_square_w.c ../multiply_64.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

# product

build/tests_product.c: make_tests_product.py
	python $^ > $@

build/modexp.o: ../modexp.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -c

build/tests_product: build/tests_product.c build/modexp.o ../multiply_32.c ../modexp_utils.c ../siphash.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

# endianess

build/test_endianess: test_endianess.c ../common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $<

# clmul

build/clmul.o: ../ghash_clmul.c
	$(CC) $(CFLAGS) -mssse3 -mpclmul $(CPPFLAGS) -o $@ $< -c

build/test_clmul: test_clmul.c ../common.h build/clmul.o
	$(CC) $(CFLAGS) -mssse3 -mpclmul $(CPPFLAGS) -o $@ $^

# Poly1305

build/poly1305.o: ../poly1305.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -c

build/test_poly1305_reduce.c: make_tests_poly1305_reduce.py
	python $^ > $@

build/test_poly1305_load_r.c: make_tests_poly1305_load_r.py
	python $^ > $@

build/test_poly1305_load_m.c: make_tests_poly1305_load_m.py
	python $^ > $@

build/test_poly1305_multiply.c: make_tests_poly1305_multiply.py
	python $^ > $@

build/test_poly1305_accumulate.c: make_tests_poly1305_accumulate.py
	python $^ > $@

build/test_poly1305_reduce: build/test_poly1305_reduce.c ../common.h build/poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

build/test_poly1305_load_r: build/test_poly1305_load_r.c ../common.h build/poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

build/test_poly1305_load_m: build/test_poly1305_load_m.c ../common.h build/poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

build/test_poly1305_multiply: build/test_poly1305_multiply.c ../common.h build/poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

build/test_poly1305_accumulate: build/test_poly1305_accumulate.c ../common.h build/poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

# Montgomery

build/mont.o: ../mont.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

build/test_mont: test_mont.c ../common.h build/mont.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

build/tests_addmul.c: make_tests_addmul.py
	python $^ > $@

build/tests_addmul: build/tests_addmul.c build/mont.o ../multiply_32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^
