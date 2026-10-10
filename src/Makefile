CPPFLAGS=-DHAVE_STDINT_H -DHAVE_POSIX_MEMALIGN -DPYCRYPTO_LITTLE_ENDIAN -DHAVE_X86INTRIN_H -DUSE_SSE2 -DHAVE_UINT128
CPPFLAGS += -DSTATIC=""
CFLAGS=-Werror -Wall -O3 -g -Wno-unused-const-variable -Wconversion -Wsign-conversion # -m32 -msse2

CFLAGS += -fanalyzer

all:: modexp ed25519_perf curve25519_perf

ed25519_perf: ed25519_perf.c multiply_64.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=64 -DMAIN

modexp_in: modexp.c mont.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=64 -DMAIN

modexp: modexp.c mont.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=64 -DPROFILE

curve25519_perf: curve25519.c multiply_64.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=64 -DPROFILE

clean::
	rm -f mont.o modexp x25519 ed25519_perf curve25519_perf
