#include "common.h"
#include "endianess.h"

FAKE_INIT(x25519)

/*
 * Fast variable-base scalar multiplication for the Montgomery curve Curve25519
 *
 *      y² = x³ + 486662x² + x
 *
 * over the prime field 2²⁵⁵ - 19.
 */

#include "mod25519.c"

/*
 * Execute the step in the Montgomery ladder.
 *
 * x2/z2 is updated with the doubling of P₂
 * x3/z3 is updated with the sum P₂+P₃
 *
 * @param[in,out]   x2  The projective X-coordinate of P₂   (< 2²⁶)
 * @param[in,out]   z2  The projective Z-coordinate of P₂   (< 2²⁶)
 * @param[in,out]   x3  The projective X-coordinate of P₃   (< 2²⁶)
 * @param[in,out]   z3  The projective Z-coordinate of P₃   (< 2²⁶)
 * @param[in]       xp  The affine X-coordinate of P₃-P₂    (< 2²⁶)
 */
STATIC void ladder_step(uint32_t x2[10], uint32_t z2[10], uint32_t x3[10], uint32_t z3[10], const uint32_t xp[10])
{
    uint32_t t0[10], t1[10];
    static const uint32_t nr_121666[10] = { 121666 };

    /* https://www.hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#ladder-mladd-1987-m */

    sub_25519(t0, x3, z3);          /* t0 = D           < 2^26 */
    sub_25519(t1, x2, z2);          /* t1 = B           < 2^26 */
    add32(x2, x2, z2);              /* x2 = A           < 2^27 */
    add32(z2, x3, z3);              /* z2 = C           < 2^27 */
    mul_25519(z3, t0, x2);          /* z3 = DA          < 2^26 */
    mul_25519(z2, z2, t1);          /* z2 = CB          < 2^26 */
    add32(x3, z3, z2);              /* x3 = DA+CB       < 2^27 */
    sub_25519(z2, z3, z2);          /* z2 = DA-CB       < 2^26 */
    mul_25519(x3, x3, x3);          /* x3 = X5          < 2^26 */
    mul_25519(z2, z2, z2);          /* z2 = (DA-CB)²    < 2^26 */
    mul_25519(t0, t1, t1);          /* t0 = BB          < 2^26 */
    mul_25519(t1, x2, x2);          /* t1 = AA          < 2^26 */
    sub_25519(x2, t1, t0);          /* x2 = E           < 2^26 */
    mul_25519(z3, xp, z2);          /* z3 = Z5          < 2^26 */
    mul_25519(z2, x2, nr_121666);   /* z2 = a24*E       < 2^26 */
    add32(z2, t0, z2);              /* z2 = BB+a24*E    < 2^27 */
    mul_25519(z2, x2, z2);          /* z2 = Z4          < 2^26 */
    mul_25519(x2, t1, t0);          /* x2 = X4          < 2^26 */
}

/*
 * Variable-base scalar multiplication on Curve25519.
 *
 * @param[out]  ssecret The X-coordinate of the resulting point.
 * @param[in]   k       The scalar encoded in little-endian mode.
 *                      It must have been already clamped.
 * @param[in]   len     Length of the scalar in bytes.
 * @param[in]   pubkey  The X-coordinate of the point to multiply, encoded in
 *                      little-endian mode.
 */
void ladder(uint8_t ssecret[32], const uint8_t *k, size_t len, const uint8_t pubkey[32])
{
    uint32_t R0x[10] = { 1 };
    uint32_t R0z[10] = { 0 };
    uint32_t R1x[10];
    uint32_t R1z[10] = { 1 };
    uint32_t xp[10];
    uint32_t invz[10];
    uint32_t affx[10];
    uint64_t tmp_64[4];
    unsigned bit_idx, swap;
    unsigned i;

    for (i=0; i<4; i++) {
        tmp_64[i] = LOAD_U64_LITTLE(&pubkey[i*8]);
    }
    convert_le64_to_le25p5(xp, tmp_64);

    memcpy(R1x, xp, sizeof R1x);
    bit_idx = 7;
    swap = 0;

    /* https://eprint.iacr.org/2020/956.pdf */

    while (len>0) {
        unsigned bit;

        bit = (k[len-1] >> bit_idx) & 1;
        swap ^= bit;

        cswap(R0x, R0z, R1x, R1z, swap);
        ladder_step(R0x, R0z, R1x, R1z, xp);
        swap = bit;

        if (bit_idx-- == 0) {
            bit_idx = 7;
            len--;
        }
    }
    cswap(R0x, R0z, R1x, R1z, swap);

    invert_25519(invz, R0z);
    mul_25519(affx, R0x, invz);
    convert_le25p5_to_le64(tmp_64, affx);
    reduce_25519_le64(tmp_64);

    for (i=0; i<4; i++) {
        STORE_U64_LITTLE(&ssecret[i*8], tmp_64[i]);
    }
}

#ifdef PROFILE
int main(void)
{
    uint8_t pubkey[32];
    uint8_t secret[32];
    uint8_t out[32];
    unsigned i;

    secret[0] = pubkey[0] = 0xAA;
    for (i=1; i<32; i++) {
        secret[i] = pubkey[i] = (uint8_t)((secret[i-1] << 1) | (secret[i-1] >> 7));
    }

    for (i=0; i<10000; i++) {
        ladder(out, secret, sizeof secret, pubkey);
    }
}
#endif
