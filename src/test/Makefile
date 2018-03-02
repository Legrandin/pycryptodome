# CPPFLAGS = -DHAVE_X86INTRIN_H
CPPFLAGS += -I.. $(shell python -c "import sys; print '-DPY_' + sys.byteorder.upper() + '_ENDIAN'")

test: all
	./tests_addmul128
	./tests_square_w

all: tests_addmul128 tests_square_w

clean:
	rm -f tests_addmul128.c tests_addmul128 tests_square_w.c tests_square_w

tests_addmul128.c: make_tests_addmul128.py
	python $^ > $@

tests_square_w.c: make_tests_square_w.py
	python $^ > $@

tests_addmul128: tests_addmul128.c ../multiply_32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

tests_square_w: tests_square_w.c ../multiply_32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^
