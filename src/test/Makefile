# CPPFLAGS = -DHAVE_X86INTRIN_H
CPPFLAGS += -I.. $(shell python -c "import sys; print '-DPYCRYPTO_' + sys.byteorder.upper() + '_ENDIAN'")

test: all
	./tests_addmul128_32
	./tests_square_w_32
	./tests_addmul128_64
	./tests_square_w_64
	./tests_product
	./tests_addmul
	./test_endianess

all: tests_addmul128_32 tests_addmul128_64 tests_square_w_32 tests_square_w_64 tests_product tests_addmul test_endianess

clean:
	rm -f tests_addmul* tests_square_w* tests_product* montgomery* test_endianess

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

