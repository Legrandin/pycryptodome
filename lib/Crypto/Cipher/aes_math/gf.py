AES_MOD = 0x1B  # x^8 + x^4 + x^3 + x + 1

def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)"""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = (a << 1) ^ (AES_MOD if a & 0x80 else 0)
        a &= 0xFF
        b >>= 1
    return r

def gf_pow(a, n):
    r = 1
    while n:
        if n & 1:
            r = gf_mul(r, a)
        a = gf_mul(a, a)
        n >>= 1
    return r

def gf_inv(a):
    """Multiplicative inverse in GF(2^8)"""
    if a == 0:
        return 0
    return gf_pow(a, 254)  # a^(2^8 − 2)

