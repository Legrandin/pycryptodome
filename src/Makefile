CPPFLAGS=-DHAVE_STDINT_H -DHAVE_POSIX_MEMALIGN -DHAVE_UINT128 -DMAIN
CFLAGS=-Werror -Wall -O3 -g

ec_ws: ec_ws.c mont.o multiply_64.o
	gcc $(CFLAGS) $(CPPFLAGS) -o $@ $^

clean::
	rm -f ec_ws mont.o multiply_64.o
