CPPFLAGS=-DHAVE_STDINT_H -DHAVE_POSIX_MEMALIGN -DHAVE_UINT128
CFLAGS=-Werror -Wall -O3 -g

all:: modexp ec_ws

ec_ws: ec_ws.c mont.c modexp_utils.c siphash.c
	gcc $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=64 -DMAIN

modexp: modexp.c mont.c modexp_utils.c siphash.c
	gcc $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=64 -DPROFILE

clean::
	rm -f ec_ws mont.o modexp
