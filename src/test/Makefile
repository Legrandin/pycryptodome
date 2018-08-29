# CPPFLAGS = -DHAVE_X86INTRIN_H
CPPFLAGS += -I.. $(shell python -c "import sys; print '-DPYCRYPTO_' + sys.byteorder.upper() + '_ENDIAN'")
CPPFLAGS += -DHAVE_POSIX_MEMALIGN
CFLAGS += -O3 -g -fkeep-static-functions -fkeep-inline-functions -fstrict-aliasing -Wall
CFLAGS += -msse2

test: all
	./tests_addmul128_32
	./tests_square_w_32
	./tests_addmul128_64
	./tests_square_w_64
	./tests_product
	./tests_addmul
	./test_endianess
	./test_clmul
	./test_poly1305_reduce
	./test_poly1305_load_r
	./test_poly1305_load_m
	./test_poly1305_multiply

all: tests_addmul128_32 tests_addmul128_64 tests_square_w_32 tests_square_w_64 tests_product tests_addmul test_endianess test_clmul\
	 test_poly1305_reduce test_poly1305_load_r test_poly1305_load_m test_poly1305_multiply

clean:
	rm -f tests_addmul* tests_square_w* tests_product* montgomery* test_endianess clmul* test_clmul poly1305* test_poly*

tests_addmul128.c: make_tests_addmul128.py
	python $^ > $@

tests_square_w.c: make_tests_square_w.py
	python $^ > $@

tests_product.c: make_tests_product.py
	python $^ > $@

tests_addmul.c: make_tests_addmul.py
	python $^ > $@

tests_addmul128_32: tests_addmul128.c ../multiply_32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

tests_square_w_32: tests_square_w.c ../multiply_32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

tests_addmul128_64: tests_addmul128.c ../multiply_64.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

tests_square_w_64: tests_square_w.c ../multiply_64.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

montgomery.o: ../montgomery.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -c

montgomery2.o: montgomery.o
	objcopy --globalize-symbol=product --globalize-symbol=addmul $^ $@

tests_product: tests_product.c montgomery2.o ../multiply_32.c ../montgomery_utils.c ../siphash.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

tests_addmul: tests_addmul.c montgomery2.o ../multiply_32.c ../montgomery_utils.c ../siphash.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

test_endianess: test_endianess.c ../common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $<

clmul.o: ../ghash_clmul.c
	$(CC) $(CFLAGS) -mssse3 -mpclmul $(CPPFLAGS) -o $@ $< -c

clmul2.o: clmul.o
	objcopy $(foreach x, multx swap clmult reduce, --globalize-symbol=$x) $^ $@

test_clmul: test_clmul.c ../common.h clmul2.o
	$(CC) $(CFLAGS) -mssse3 -mpclmul $(CPPFLAGS) -o $@ $^

# Poly1305

poly1305.o: ../poly1305.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -c

test_poly1305_reduce.c: make_tests_poly1305_reduce.py
	python $^ > $@

test_poly1305_load_r.c: make_tests_poly1305_load_r.py
	python $^ > $@

test_poly1305_load_m.c: make_tests_poly1305_load_m.py
	python $^ > $@

test_poly1305_multiply.c: make_tests_poly1305_multiply.py
	python $^ > $@

test_poly1305_reduce: test_poly1305_reduce.c ../common.h poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

test_poly1305_load_r: test_poly1305_load_r.c ../common.h poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

test_poly1305_load_m: test_poly1305_load_m.c ../common.h poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

test_poly1305_multiply: test_poly1305_multiply.c ../common.h poly1305.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^
