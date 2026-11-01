/*
 * SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/**
 * The portable SHA-2 compression function, for hash_SHA2_template.c,
 * as defined in FIPS 180-4.
 *
 * This file is not a module: it is included by hash_SHA2_template.c
 * when no CPU-specific version is selected, after the definitions
 * of sha2_word_t, SCHEDULE_SIZE and K[].
 */

/** Equivalent to the FIPS 180-4 definitions, with fewer operations **/
#define CH(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ(x,y,z)      (((x) & (y)) | ((z) & ((x) | (y))))

#define ROTR32(n, x)    (((x)>>(n)) | ((x)<<(32-(n))))
#define ROTR64(n, x)    (((x)>>(n)) | ((x)<<(64-(n))))
#define SHR(n,x)        ((x)>>(n))

#if WORD_SIZE==4

#define SIGMA_0_256(x)    (ROTR32(2,x)  ^ ROTR32(13,x) ^ ROTR32(22,x))
#define SIGMA_1_256(x)    (ROTR32(6,x)  ^ ROTR32(11,x) ^ ROTR32(25,x))
#define sigma_0_256(x)    (ROTR32(7,x)  ^ ROTR32(18,x) ^ SHR(3,x))
#define sigma_1_256(x)    (ROTR32(17,x) ^ ROTR32(19,x) ^ SHR(10,x))

#define SCHEDULE(t) (W[(t)&15] += sigma_1_256(W[((t)-2)&15]) + W[((t)-7)&15] + sigma_0_256(W[((t)-15)&15]))

#define CYCLE(a,b,c,d,e,f,g,h,t) \
    h += SIGMA_1_256(e) + CH(e,f,g) + K[t]  + WT(t); \
    d += h; \
    h += SIGMA_0_256(a) + MAJ(a,b,c);

#elif WORD_SIZE==8

#define SIGMA_0_512(x)    (ROTR64(28,x) ^ ROTR64(34,x) ^ ROTR64(39,x))
#define SIGMA_1_512(x)    (ROTR64(14,x) ^ ROTR64(18,x) ^ ROTR64(41,x))
#define sigma_0_512(x)    (ROTR64(1,x)  ^ ROTR64(8,x)  ^ SHR(7,x))
#define sigma_1_512(x)    (ROTR64(19,x) ^ ROTR64(61,x) ^ SHR(6,x))

#define SCHEDULE(t) (W[(t)&15] += sigma_1_512(W[((t)-2)&15]) + W[((t)-7)&15] + sigma_0_512(W[((t)-15)&15]))

#define CYCLE(a,b,c,d,e,f,g,h,t) \
    h += SIGMA_1_512(e) + CH(e,f,g) + K[t]  + WT(t); \
    d += h; \
    h += SIGMA_0_512(a) + MAJ(a,b,c);

#endif

/**
 * Message word for round t, with the schedule kept in a rolling window of 16 words.
 * t is always a constant, so the test is resolved at compile time.
 **/
#define WT(t)   ((t) < 16 ? W[(t)&15] : SCHEDULE(t))

/**
 * Compress one block, already decoded into sixteen words.
 * h_out[] may be the same array as h_in[] or M[].
 */
static void sha_compress_words(const sha2_word_t h_in[8], sha2_word_t h_out[8], const sha2_word_t M[16])
{
    sha2_word_t a, b, c, d, e, f, g, h;
    sha2_word_t W[16];

    memcpy(W, M, sizeof W);

    a = h_in[0];
    b = h_in[1];
    c = h_in[2];
    d = h_in[3];
    e = h_in[4];
    f = h_in[5];
    g = h_in[6];
    h = h_in[7];

    CYCLE(a,b,c,d,e,f,g,h, 0);
    CYCLE(h,a,b,c,d,e,f,g, 1);
    CYCLE(g,h,a,b,c,d,e,f, 2);
    CYCLE(f,g,h,a,b,c,d,e, 3);
    CYCLE(e,f,g,h,a,b,c,d, 4);
    CYCLE(d,e,f,g,h,a,b,c, 5);
    CYCLE(c,d,e,f,g,h,a,b, 6);
    CYCLE(b,c,d,e,f,g,h,a, 7);
    CYCLE(a,b,c,d,e,f,g,h, 8);
    CYCLE(h,a,b,c,d,e,f,g, 9);
    CYCLE(g,h,a,b,c,d,e,f, 10);
    CYCLE(f,g,h,a,b,c,d,e, 11);
    CYCLE(e,f,g,h,a,b,c,d, 12);
    CYCLE(d,e,f,g,h,a,b,c, 13);
    CYCLE(c,d,e,f,g,h,a,b, 14);
    CYCLE(b,c,d,e,f,g,h,a, 15);
    CYCLE(a,b,c,d,e,f,g,h, 16);
    CYCLE(h,a,b,c,d,e,f,g, 17);
    CYCLE(g,h,a,b,c,d,e,f, 18);
    CYCLE(f,g,h,a,b,c,d,e, 19);
    CYCLE(e,f,g,h,a,b,c,d, 20);
    CYCLE(d,e,f,g,h,a,b,c, 21);
    CYCLE(c,d,e,f,g,h,a,b, 22);
    CYCLE(b,c,d,e,f,g,h,a, 23);
    CYCLE(a,b,c,d,e,f,g,h, 24);
    CYCLE(h,a,b,c,d,e,f,g, 25);
    CYCLE(g,h,a,b,c,d,e,f, 26);
    CYCLE(f,g,h,a,b,c,d,e, 27);
    CYCLE(e,f,g,h,a,b,c,d, 28);
    CYCLE(d,e,f,g,h,a,b,c, 29);
    CYCLE(c,d,e,f,g,h,a,b, 30);
    CYCLE(b,c,d,e,f,g,h,a, 31);
    CYCLE(a,b,c,d,e,f,g,h, 32);
    CYCLE(h,a,b,c,d,e,f,g, 33);
    CYCLE(g,h,a,b,c,d,e,f, 34);
    CYCLE(f,g,h,a,b,c,d,e, 35);
    CYCLE(e,f,g,h,a,b,c,d, 36);
    CYCLE(d,e,f,g,h,a,b,c, 37);
    CYCLE(c,d,e,f,g,h,a,b, 38);
    CYCLE(b,c,d,e,f,g,h,a, 39);
    CYCLE(a,b,c,d,e,f,g,h, 40);
    CYCLE(h,a,b,c,d,e,f,g, 41);
    CYCLE(g,h,a,b,c,d,e,f, 42);
    CYCLE(f,g,h,a,b,c,d,e, 43);
    CYCLE(e,f,g,h,a,b,c,d, 44);
    CYCLE(d,e,f,g,h,a,b,c, 45);
    CYCLE(c,d,e,f,g,h,a,b, 46);
    CYCLE(b,c,d,e,f,g,h,a, 47);
    CYCLE(a,b,c,d,e,f,g,h, 48);
    CYCLE(h,a,b,c,d,e,f,g, 49);
    CYCLE(g,h,a,b,c,d,e,f, 50);
    CYCLE(f,g,h,a,b,c,d,e, 51);
    CYCLE(e,f,g,h,a,b,c,d, 52);
    CYCLE(d,e,f,g,h,a,b,c, 53);
    CYCLE(c,d,e,f,g,h,a,b, 54);
    CYCLE(b,c,d,e,f,g,h,a, 55);
    CYCLE(a,b,c,d,e,f,g,h, 56);
    CYCLE(h,a,b,c,d,e,f,g, 57);
    CYCLE(g,h,a,b,c,d,e,f, 58);
    CYCLE(f,g,h,a,b,c,d,e, 59);
    CYCLE(e,f,g,h,a,b,c,d, 60);
    CYCLE(d,e,f,g,h,a,b,c, 61);
    CYCLE(c,d,e,f,g,h,a,b, 62);
    CYCLE(b,c,d,e,f,g,h,a, 63);

#if SCHEDULE_SIZE==80
    CYCLE(a,b,c,d,e,f,g,h, 64);
    CYCLE(h,a,b,c,d,e,f,g, 65);
    CYCLE(g,h,a,b,c,d,e,f, 66);
    CYCLE(f,g,h,a,b,c,d,e, 67);
    CYCLE(e,f,g,h,a,b,c,d, 68);
    CYCLE(d,e,f,g,h,a,b,c, 69);
    CYCLE(c,d,e,f,g,h,a,b, 70);
    CYCLE(b,c,d,e,f,g,h,a, 71);
    CYCLE(a,b,c,d,e,f,g,h, 72);
    CYCLE(h,a,b,c,d,e,f,g, 73);
    CYCLE(g,h,a,b,c,d,e,f, 74);
    CYCLE(f,g,h,a,b,c,d,e, 75);
    CYCLE(e,f,g,h,a,b,c,d, 76);
    CYCLE(d,e,f,g,h,a,b,c, 77);
    CYCLE(c,d,e,f,g,h,a,b, 78);
    CYCLE(b,c,d,e,f,g,h,a, 79);
#endif

    /** compute new intermediate hash **/
    h_out[0] = h_in[0] + a;
    h_out[1] = h_in[1] + b;
    h_out[2] = h_in[2] + c;
    h_out[3] = h_in[3] + d;
    h_out[4] = h_in[4] + e;
    h_out[5] = h_in[5] + f;
    h_out[6] = h_in[6] + g;
    h_out[7] = h_in[7] + h;
}
