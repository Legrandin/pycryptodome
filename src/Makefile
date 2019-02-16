CPPFLAGS=-DHAVE_STDINT_H -DHAVE_POSIX_MEMALIGN -DPYCRYPTO_LITTLE_ENDIAN
CFLAGS=-Werror -Wall -O3 -g -m32

all:: modexp ec_ws

ec_ws: ec_ws.c mont.c modexp_utils.c siphash.c
	gcc $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=32 -DMAIN

modexp: modexp.c mont.c modexp_utils.c siphash.c
	gcc $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=32 -DPROFILE

clean::
	rm -f ec_ws mont.o modexp
