from .gf import gf_mul

def mix_single_column(col):
    a = col[:]
    return [
        gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3],
        a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3],
        a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3),
        gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2)
    ]

def mix_single_column_n(col, M):
    """
    col : list of n bytes
    M   : n x n MixColumns matrix
    """
    n = len(col)
    result = [0] * n

    for i in range(n):
        for j in range(n):
            result[i] ^= gf_mul(M[i][j], col[j])

    return result

def mix_columns(state):
    """
    state: 4x4 matrix (list of lists or ndarray)
           column-major AES state
    """
    for c in range(4):
        column = [state[r][c] for r in range(4)]
        mixed = mix_single_column(column)
        for r in range(4):
            state[r][c] = mixed[r]
    return state

def mix_columns_n(state, M):
    """
    state : n x n matrix (column-major)
    M     : n x n MixColumns matrix
    """
    n = len(state)

    for c in range(n):
        column = [state[r][c] for r in range(n)]
        mixed = mix_single_column_n(column, M)
        for r in range(n):
            state[r][c] = mixed[r]

    return state

