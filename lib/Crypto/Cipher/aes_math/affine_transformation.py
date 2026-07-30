def affine_transform(byte):
    c = 0x63
    r = 0
    for i in range(8):
        bit = (
            (byte >> i) & 1 ^
            (byte >> ((i + 4) % 8)) & 1 ^
            (byte >> ((i + 5) % 8)) & 1 ^
            (byte >> ((i + 6) % 8)) & 1 ^
            (byte >> ((i + 7) % 8)) & 1 ^
            (c >> i) & 1
        )
        r |= bit << i
    return r