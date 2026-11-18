Test vectors for SLH-DSA (FIPS 205)

SLH-DSA-keyGen-FIPS205.json
SLH-DSA-sigGen-FIPS205.json
SLH-DSA-sigVer-FIPS205.json

    A subset of the NIST ACVP vectors (internalProjection.json, with both the
    inputs and the expected results) from:

        https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
        (commit 112690e8484dba7077709a05b1f3af58ddefdd5d; the SLH-DSA files
         are unchanged up to commit 975de31, 12 August 2026)

    The tests were selected to keep the test time short (generating a key
    with the "s" parameter sets, and signing with them, is slow):

    keyGen:  the first 4 tests of each group (12 groups, 48 tests).
    sigGen:  the groups for the internal interface and for pure SLH-DSA
             (not HashSLH-DSA), and the test with the shortest message in each.
    sigVer:  the groups for the internal interface and for pure SLH-DSA
             (24 groups), with the first test of each of the 7 kinds in each
             group (168 tests): a valid signature, and a signature that is too
             short or too long, or with a modified message, R, SIG_FORS or SIG_HT.

SLH-DSA-sigGen-FIPS205-preHash.json
SLH-DSA-sigVer-FIPS205-preHash.json

    The HashSLH-DSA groups of the same ACVP files (same commit).

    sigGen:  the "f" parameter sets only (signing with the "s" sets is slow),
             with each hash function or XOF twice (once deterministic, once
             hedged, with different parameter sets).
    sigVer:  the first test of each of the 7 kinds in each group
             (12 groups, 84 tests), as above.

SLH-DSA-SP800-230-ipd.json

    One key and one signature for each of the six parameter sets of the
    initial public draft of NIST SP 800-230 (April 2026, Table 1),
    https://doi.org/10.6028/NIST.SP.800-230.ipd

    Origin: there are no official test vectors (ACVP or other) for these
    parameter sets yet, so these were generated with PyCryptodome itself,
    and then checked with an independent implementation (see below).
    They only test that PyCryptodome keeps producing the same results,
    and that they agree with that implementation: if the final SP 800-230
    changes the parameter sets, or NIST publishes official vectors,
    they must be replaced.

    Generation (on 2026-10-24, with the SLH-DSA code of PyCryptodome on the
    branch slhdsa, after commit bd79876c, with the C code for SHA-NI and
    AVX2/BMI2, and 16 threads):

    - The inputs are derived from fixed strings, for reproducibility.
      For the parameter set P (its name, as in Table 1) and a tag T,
      X(P, T, len) is the first len bytes of SHAKE256("SP 800-230 P T")
      (for instance "SP 800-230 SLH-DSA-SHA2-128-24 skSeed"):

        skSeed  = X(P, "skSeed", n)
        skPrf   = X(P, "skPrf", n)
        pkSeed  = X(P, "pkSeed", n)
        message = X(P, "message", 33 + i)

      where i is the position of P in Table 1 (0 to 5, SHA2-128-24 first).
      The SHA2 sets (i even) sign hedged, with a context; the SHAKE sets
      (i odd) sign deterministically, with an empty context:

        context              = X(P, "context", i + 3)    (SHA2 only)
        additionalRandomness = X(P, "addrnd", n)         (SHA2 only)

    - pk and sk are the output of slh_keygen_internal(skSeed, skPrf, pkSeed)
      (FIPS 205, Algorithm 18).

    - signature is the output of slh_sign_internal(M', sk, addrnd)
      (FIPS 205, Algorithm 19), for pure SLH-DSA (Algorithm 22):
      M' = 0x00 || len(context) || context || message, and addrnd is
      additionalRandomness, or PK.seed when deterministic is true.

    - Each key generation and each signature took from 16 to 137 seconds
      (about a billion hashes each).

    Checks:

    - PyCryptodome verified each signature.

    - Each signature was also verified with slh_verify() of the Python
      implementation of FIPS 205 in slhdsa-c (test/fips205.py, which takes
      the parameters n, h, d, h', a, k, lg_w and m of any parameter set):

        https://github.com/slh-dsa/slhdsa-c
        (commit 2b111e076a3bf0b6041651cf8746acf5ade56cc7, test/fips205.py
         with SHA-256 f4e798ba942e11815334db07511ef766ea4c58ea56db315936ca376df241812b)

      and it rejected each signature with one bit flipped.
      That implementation is too slow to generate the keys or the signatures
      itself (pure Python), but verifying recomputes PK.root from the
      signature, so it also checks pk.

    - Before that, the same comparison with slhdsa-c (keys and signatures,
      all computed by both) passed on 42 small parameter sets with lg_w = 2, 3
      and 4, both hash families, and d = 1 to 3 (some of them are in
      TOY_KATS in lib/Crypto/SelfTest/PublicKey/test_SLHDSA.py).

rfc9909_*.pem

    The examples in Appendix C of RFC 9909 (Algorithm Identifiers for the
    Stateless Hash-Based Digital Signature Algorithm (SLH-DSA) in Internet
    X.509 Public Key Infrastructure), for SLH-DSA-SHA2-128s:

        https://www.rfc-editor.org/rfc/rfc9909.txt

    slh_dsa_sha2_128s_public.pem   C.1, public key
    slh_dsa_sha2_128s_private.pem  C.2, the matching private key (without
                                   the public key field)
    slh_dsa_sha2_128s_cert.pem     C.3, self-signed certificate for that key
                                   (pure SLH-DSA, empty context)

    The certificate spans several pages of the RFC: the page footers and
    headers were removed from its base64 lines.

openssl_slh_dsa_*_key_cert.pem

    The S/MIME test files of OpenSSL (Apache License 2.0) for SLH-DSA-SHA2-128s,
    SLH-DSA-SHAKE-128s and SLH-DSA-SHAKE-256s: a private key (PKCS#8 as in
    RFC 9909, without the public key field) and a certificate for the same key,
    both made by OpenSSL. The certificates are issued by another key (a test CA),
    so they test the import of the public key only. Unmodified copies of:

        https://github.com/openssl/openssl/tree/master/test/smime-certs
        sm_slhdsa_sha2_128s.pem, sm_slhdsa_shake_128s.pem, sm_slhdsa_shake_256s.pem
        (commit f08c66439cfb6eef09eee64c875090b1d0796c10, 18 November 2026)
