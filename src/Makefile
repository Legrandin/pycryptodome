CPPFLAGS=-DHAVE_STDINT_H -DHAVE_POSIX_MEMALIGN -DPYCRYPTO_LITTLE_ENDIAN -DHAVE_X86INTRIN_H -DUSE_SSE2 -DHAVE_UINT128
CPPFLAGS += -DSTATIC=""
CFLAGS=-Werror -Wall -O3 -g -Wno-unused-const-variable -Wconversion -Wsign-conversion # -m32 -msse2

CFLAGS += -fanalyzer

all:: ed25519_perf curve25519_perf

ed25519_perf: ed25519_perf.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=64 -DMAIN

curve25519_perf: curve25519.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -DSYS_BITS=64 -DPROFILE

clean::
	rm -f x25519 ed25519_perf curve25519_perf
