"""Generate test_slhdsa_vectors.h, the test vectors of test_slhdsa.c.

Run it from the root of the repository, after building the extensions:

    PYTHONPATH=lib python src/test/make_slhdsa_vectors.py > src/test/test_slhdsa_vectors.h

Unlike the other make_tests_*.py, it is not run by CMake: it needs
pycryptodome and the test vectors in test_vectors/.

Each vector is a node computed by slhdsa_xmss_node() or slhdsa_fors_node().
The expected values are not computed here: they are taken from the vectors
of NIST and of SP 800-230 in test_vectors/.../PublicKey/SLHDSA/.

  - PK.root of the keyGen vectors of NIST (ACVP), the root of the top XMSS tree.
  - Nodes of the authentication paths in the deterministic sigGen vectors
    of NIST (with the internal interface), for XMSS and FORS.
  - The same for the SP 800-230 vector of each parameter set
    (SLH-DSA-SP800-230-ipd.json, see its README.txt), with the pure interface.

This script only finds where each node is (address, index and height),
with H_msg (in Python) for the indices of the FORS and XMSS trees.
"""

import json
import os
import sys

from Crypto.PublicKey import _fips205
from Crypto.PublicKey._fips205 import ADRS, Context, base_2b, split_digest

VECTORS = os.path.join("test_vectors", "pycryptodome_test_vectors", "PublicKey", "SLHDSA")

PARAMS = {p.name: p for p in _fips205.PARAMS}

vectors = []


def add(name, p, kind, sk_seed, pk_seed, adrs, i, z, node):
    # Check that the node is where we think it is
    ctx = Context(p, pk_seed, sk_seed)
    computed = (ctx.xmss_node if kind == "XMSS" else ctx.fors_node)(i, z, adrs)
    assert computed == node, name
    vectors.append((name, p, kind, sk_seed, pk_seed, bytes(adrs), i, z, node))


def add_signature(source, p, M, SIG, SK, xmss_heights, top_heights, fors_trees_heights):
    """The nodes of the authentication paths in the signature SIG of M.

    xmss_heights: the heights in the XMSS tree of layer 0
    top_heights: the heights in the XMSS tree of the top layer (d - 1)
    fors_trees_heights: (tree, height) of the FORS nodes
    """

    n = p.n
    sk_seed, _, pk_seed, pk_root = (SK[i * n : (i + 1) * n] for i in range(4))
    ctx = Context(p, pk_seed)

    fors_len = p.k * (1 + p.a) * n
    R = SIG[:n]
    sig_fors = SIG[n : n + fors_len]
    sig_ht = SIG[n + fors_len :]

    md, idx_tree, idx_leaf = split_digest(p, ctx.H_msg(R, pk_root, [M]))

    # FORS (Algorithm 17): AUTH[j] of tree t is the sibling of the node
    # of height j on the path of the leaf t * 2^a + indices[t]
    indices = base_2b(md, p.a, p.k)
    adrs = ADRS()
    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(ADRS.FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)
    for t, j in fors_trees_heights:
        tree = sig_fors[t * (p.a + 1) * n : (t + 1) * (p.a + 1) * n]
        auth_j = tree[(1 + j) * n : (2 + j) * n]
        i = (((t << p.a) + indices[t]) >> j) ^ 1
        add("%s, FORS tree %d, AUTH[%d]" % (source, t, j), p, "FORS", sk_seed, pk_seed, adrs, i, j, auth_j)

    # XMSS (Algorithms 11 and 13): AUTH[j] of layer l is the sibling of
    # the node of height j on the path of the leaf idx_leaf of that layer
    xmss_len = (p.len + p.hp) * n
    for layer in range(p.d):
        heights = xmss_heights if layer == 0 else top_heights if layer == p.d - 1 else ()
        if p.d == 1:
            heights = sorted(set(xmss_heights) | set(top_heights))
        if heights:
            adrs = ADRS()
            adrs.set_layer_address(layer)
            adrs.set_tree_address(idx_tree)
            sig_xmss = sig_ht[layer * xmss_len : (layer + 1) * xmss_len]
            for j in heights:
                auth_j = sig_xmss[(p.len + j) * n : (p.len + j + 1) * n]
                add(
                    "%s, XMSS layer %d, AUTH[%d]" % (source, layer, j),
                    p,
                    "XMSS",
                    sk_seed,
                    pk_seed,
                    adrs,
                    (idx_leaf >> j) ^ 1,
                    j,
                    auth_j,
                )
        idx_leaf = idx_tree % (1 << p.hp)
        idx_tree = idx_tree >> p.hp


def main():
    with open(os.path.join(VECTORS, "SLH-DSA-keyGen-FIPS205.json")) as f:
        keygen = json.load(f)
    for group in keygen["testGroups"]:
        p = PARAMS[group["parameterSet"]]
        tv = group["tests"][0]
        pk = bytes.fromhex(tv["pk"])
        adrs = ADRS()
        adrs.set_layer_address(p.d - 1)
        add(
            "%s, keyGen tcId %d, PK.root" % (p.name, tv["tcId"]),
            p,
            "XMSS",
            bytes.fromhex(tv["skSeed"]),
            bytes.fromhex(tv["pkSeed"]),
            adrs,
            0,
            p.hp,
            pk[p.n :],
        )

    with open(os.path.join(VECTORS, "SLH-DSA-sigGen-FIPS205.json")) as f:
        siggen = json.load(f)
    for group in siggen["testGroups"]:
        if group["signatureInterface"] != "internal" or not group["deterministic"]:
            continue
        p = PARAMS[group["parameterSet"]]
        tv = group["tests"][0]
        small = p.name.endswith("s")
        add_signature(
            "%s, sigGen tcId %d" % (p.name, tv["tcId"]),
            p,
            bytes.fromhex(tv["message"]),
            bytes.fromhex(tv["signature"]),
            bytes.fromhex(tv["sk"]),
            xmss_heights=(0, 1, 2) if small else range(p.hp),
            top_heights=() if small else (p.hp - 1,),
            fors_trees_heights=((0, 0), (0, 1), (0, 2), (0, p.a - 1), (p.k - 1, p.a - 1)),
        )

    with open(os.path.join(VECTORS, "SLH-DSA-SP800-230-ipd.json")) as f:
        sp800230 = json.load(f)
    for tv in sp800230:
        p = PARAMS[tv["parameterSet"]]
        context = bytes.fromhex(tv["context"] or "")
        # The pure interface (Algorithm 22, line 8)
        M = b"\x00" + bytes([len(context)]) + context + bytes.fromhex(tv["message"])
        add_signature(
            "%s, SP 800-230 vector" % p.name,
            p,
            M,
            bytes.fromhex(tv["signature"]),
            bytes.fromhex(tv["sk"]),
            xmss_heights=(0, 1, 2, 3),
            top_heights=(),
            fors_trees_heights=((0, 0), (0, 1), (0, 2), (0, 8), (p.k - 1, 1), (p.k - 1, 8)),
        )

    out = sys.stdout
    out.write(
        "/*\n * Generated by make_slhdsa_vectors.py: do not edit.\n"
        " * The nodes come from the vectors of NIST and of SP 800-230 (see that script).\n */\n\n"
    )
    out.write("static const NodeVector node_vectors[] = {\n")
    for name, p, kind, sk_seed, pk_seed, adrs, i, z, node in vectors:
        out.write("    {\n")
        out.write('        "%s",\n' % name)
        out.write(
            "        %s, %d, %d, NODE_%s,\n"
            % ("SLHDSA_SHA2" if p.sha2 else "SLHDSA_SHAKE", p.n, p.lg_w, kind)
        )
        out.write('        "%s",\n' % sk_seed.hex())
        out.write('        "%s",\n' % pk_seed.hex())
        out.write('        "%s",\n' % adrs.hex())
        out.write("        %d, %d,\n" % (i, z))
        out.write('        "%s"\n' % node.hex())
        out.write("    },\n")
    out.write("};\n")


if __name__ == "__main__":
    main()
