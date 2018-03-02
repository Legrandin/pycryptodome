CPPFLAGS := -I.. $(shell python -c "import sys; print '-DPY_' + sys.byteorder.upper() + '_ENDIAN'")

test: all
	./test_addmul128

all: test_addmul128

clean:
	rm -f test_addmul128.c test_addmul128

test_addmul128.c: make_tests_addmul128.py
	python $^ > $@

test_addmul128: test_addmul128.c ../multiply_32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^
