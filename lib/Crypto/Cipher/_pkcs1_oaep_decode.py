from Crypto.Util._raw_api import c_size_t, c_uint8_ptr, c_uint8_ptr_len, load_pycryptodome_raw_lib

_raw_pkcs1_decode = load_pycryptodome_raw_lib(
    "Crypto.Cipher._pkcs1_decode",
    """
                        int pkcs1_decode(const uint8_t *em, size_t len_em,
                                         const uint8_t *sentinel, size_t len_sentinel,
                                         size_t expected_pt_len,
                                         uint8_t *output);

                        int pkcs1_decode_implicit(const uint8_t *em, size_t len_em,
                                                  const uint8_t *am,
                                                  const uint8_t cl[256],
                                                  size_t expected_pt_len,
                                                  uint8_t *output);

                        int oaep_decode(const uint8_t *em,
                                        size_t em_len,
                                        const uint8_t *lHash,
                                        size_t hLen,
                                        const uint8_t *db,
                                        size_t db_len);
                        """,
)


def pkcs1_decode(em, sentinel, expected_pt_len, output):
    if len(em) != len(output):
        raise ValueError("Incorrect output length")

    em_ptr, em_len = c_uint8_ptr_len(em)
    sentinel_ptr, sentinel_len = c_uint8_ptr_len(sentinel)
    ret = _raw_pkcs1_decode.pkcs1_decode(
        em_ptr,
        c_size_t(em_len),
        sentinel_ptr,
        c_size_t(sentinel_len),
        c_size_t(expected_pt_len),
        c_uint8_ptr(output),
    )
    return ret


def pkcs1_decode_implicit(em, am, cl, expected_pt_len, output):
    if not (len(em) == len(am) == len(output)):
        raise ValueError("Incorrect output length")

    # The C function reads exactly 256 bytes of candidate lengths
    # (it is declared as uint8_t cl[128][2], which is passed the same way)
    em_ptr, em_len = c_uint8_ptr_len(em)
    cl_ptr, cl_len = c_uint8_ptr_len(cl)
    if cl_len != 256:
        raise ValueError("Incorrect length of the candidate lengths")
    ret = _raw_pkcs1_decode.pkcs1_decode_implicit(
        em_ptr,
        c_size_t(em_len),
        c_uint8_ptr(am),
        cl_ptr,
        c_size_t(expected_pt_len),
        c_uint8_ptr(output),
    )
    return ret


def oaep_decode(em, lHash, db):
    em_ptr, em_len = c_uint8_ptr_len(em)
    lHash_ptr, lHash_len = c_uint8_ptr_len(lHash)
    db_ptr, db_len = c_uint8_ptr_len(db)
    ret = _raw_pkcs1_decode.oaep_decode(
        em_ptr,
        c_size_t(em_len),
        lHash_ptr,
        c_size_t(lHash_len),
        db_ptr,
        c_size_t(db_len),
    )
    return ret
