CPPFLAGS=-DHAVE_STDINT_H -DHAVE_POSIX_MEMALIGN -DHAVE_UINT128
CFLAGS=-Werror -Wall -O3 -g

ec_ws: ec_ws.c mont.o multiply_64.o
	gcc $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DMAIN

modexp: modexp.c mont.o multiply_64.o modexp_utils.c siphash.c
	gcc $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DPROFILE

clean::
	rm -f ec_ws mont.o multiply_64.o
