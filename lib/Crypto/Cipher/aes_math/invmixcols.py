from .gf import gf_mul
from .mixcols import mix_single_column_n, mix_columns_n

def inv_mix_single_column(col):
    a0, a1, a2, a3 = col

    return [
        gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9),
        gf_mul(a0, 9)  ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13),
        gf_mul(a0, 13) ^ gf_mul(a1, 9)  ^ gf_mul(a2, 14) ^ gf_mul(a3, 11),
        gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9)  ^ gf_mul(a3, 14),
    ]

def inv_mix_columns(state):
    """
    state: 4x4 matrix (list of lists or ndarray)
           column-major AES state
    """
    for c in range(4):
        column = [state[r][c] for r in range(4)]
        mixed = inv_mix_single_column(column)
        for r in range(4):
            state[r][c] = mixed[r]
    return state

def inv_matrix_gf256(M):
    """
    Invert an n×n matrix over GF(2^8)
    """
    n = len(M)
    A = [[M[i][j] for j in range(n)] for i in range(n)]
    I = [[1 if i == j else 0 for j in range(n)] for i in range(n)]

    for col in range(n):
        # Find pivot
        if A[col][col] == 0:
            for r in range(col + 1, n):
                if A[r][col] != 0:
                    A[col], A[r] = A[r], A[col]
                    I[col], I[r] = I[r], I[col]
                    break
            else:
                raise ValueError("Matrix not invertible over GF(2^8)")

        # Invert pivot
        pivot = A[col][col]
        inv_pivot = pow(pivot, 254, 0x11B)  # GF inverse

        for j in range(n):
            A[col][j] = gf_mul(A[col][j], inv_pivot)
            I[col][j] = gf_mul(I[col][j], inv_pivot)

        # Eliminate other rows
        for r in range(n):
            if r != col and A[r][col] != 0:
                factor = A[r][col]
                for j in range(n):
                    A[r][j] ^= gf_mul(factor, A[col][j])
                    I[r][j] ^= gf_mul(factor, I[col][j])

    return I

def inv_mix_columns_n(state, M):
    Minv = inv_matrix_gf256(M)

    return mix_columns_n(state, Minv)
