/*
 * Tests of what the curves with projective coordinates have in common
 * (ec_common.c): the formulas through the group, the scalar
 * multiplications and the tables of the generator. The same tests run
 * for the NIST curves (test_ec_nat.c) and for Ed448 (test_ed448.c),
 * which include this file after defining rnd().
 *
 * The bases are points of the curve; the first one is the generator G.
 */

/* Private functions (they are not static when STATIC is defined as empty) */
int ec_mul_var(EcWs *ws, const EcGroup *g, uint64_t *rx, uint64_t *ry, uint64_t *rz,
               const uint64_t *px, const uint64_t *py, const uint64_t *pz,
               const uint64_t *kb, size_t windows, const uint64_t *lambda);
int ec_mul_g(EcWs *ws, const EcGroup *g, uint64_t *rx, uint64_t *ry, uint64_t *rz,
             const uint64_t *kb, size_t windows, const uint64_t *lambda);

/* Big enough for P-521 */
#define GT_MAX_WORDS 9
#define GT_MAX_LEN 66

/** dst = src (same group) **/
static void gt_copy(EcPoint *dst, const EcPoint *src)
{
    assert(dst->g == src->g);
    memcpy(dst->x, src->x, 3*src->nw*8);
}

static EcPoint *gt_clone(const EcPoint *p)
{
    EcPoint *q;

    assert(ec_point_clone(&q, p) == 0);
    return q;
}

/** p = the affine point (x, y), with Z = 1 **/
static void gt_set_affine(EcPoint *p, const uint64_t *x, const uint64_t *y)
{
    const size_t nw = p->g->nw;

    memcpy(p->x, x, nw*8);
    memcpy(p->y, y, nw*8);
    memcpy(p->z, p->g->field->one, nw*8);
}

static void gt_random_bytes(uint8_t *k, size_t len)
{
    size_t i;

    for (i=0; i<len; i++)
        k[i] = (uint8_t)rnd();
}

/* NULL arguments and empty scalars */
static void test_group_errors(const EcPoint *gen)
{
    EcPoint *p = gt_clone(gen), *q = gt_clone(gen);
    uint8_t k[1] = { 1 }, xy[2*GT_MAX_LEN];

    assert(ec_point_scalar(NULL, k, 1, 0) == ERR_NULL);
    assert(ec_point_scalar(p, NULL, 1, 0) == ERR_NULL);
    assert(ec_point_scalar(p, k, 0, 0) == ERR_NOT_ENOUGH_DATA);
    assert(ec_point_scalar_public(NULL, k, 1) == ERR_NULL);
    assert(ec_point_scalar_public(p, NULL, 1) == ERR_NULL);
    assert(ec_point_scalar_public(p, k, 0) == ERR_NOT_ENOUGH_DATA);

    assert(ec_point_add(NULL, p) == ERR_NULL);
    assert(ec_point_add(p, NULL) == ERR_NULL);
    assert(ec_point_double(NULL) == ERR_NULL);
    assert(ec_point_neg(NULL) == ERR_NULL);
    assert(ec_point_cmp(NULL, p) == ERR_NULL);
    assert(ec_point_cmp(p, NULL) == ERR_NULL);
    assert(ec_point_clone(NULL, p) == ERR_NULL);
    assert(ec_point_get_xy(NULL, xy, gen->g->len, p) == ERR_NULL);
    assert(ec_point_get_xy(xy, xy + GT_MAX_LEN, gen->g->len - 1, p) == ERR_NOT_ENOUGH_DATA);

    /* The clone is independent */
    assert(ec_point_double(q) == 0);
    assert(ec_point_cmp(p, q) == ERR_VALUE);

    ec_point_free(p);
    ec_point_free(q);
    ec_point_free(NULL);
}

/* Operations on points of two different groups */
static void test_group_other(EcPoint *a, EcPoint *b)
{
    assert(a->g != b->g);
    assert(ec_point_add(a, b) == ERR_EC_CURVE);
    assert(ec_point_cmp(a, b) == ERR_EC_CURVE);
}

/* The tables: entry j of window i is (j+1)*32^i*G (checked with the variable base code) */
static void test_group_g_table(const EcPoint *gen)
{
    const EcGroup *g = gen->g;
    const size_t nw = g->nw;
    uint8_t k[100];
    unsigned n;

    for (n=0; n<40; n++) {
        EcPoint *p, *q, *m;
        size_t i, j, bit;

        i = n < 2 ? n*(g->windows - 1) : rnd() % g->windows;
        j = n < 2 ? 15 : rnd() % EC_DIGITS;

        /* (j+1) << (5*i) */
        memset(k, 0, sizeof k);
        bit = 5*i;
        assert(bit/8 + 2 <= sizeof k);
        k[sizeof k - 1 - bit/8] = (uint8_t)((j + 1) << (bit % 8));
        k[sizeof k - 2 - bit/8] = (uint8_t)((j + 1) >> (8 - bit % 8));

        /* A point equal to G, but not detected as G (Z != 1): 2G - G */
        p = gt_clone(gen);
        assert(ec_point_double(p) == 0);
        m = gt_clone(gen);
        assert(ec_point_neg(m) == 0);
        assert(ec_point_add(p, m) == 0);
        assert(ec_point_scalar(p, k, sizeof k, rnd()) == 0);
        ec_point_free(m);

        q = gt_clone(gen);
        gt_set_affine(q, g->g_table + (i*EC_DIGITS + j)*2*nw, g->g_table + (i*EC_DIGITS + j)*2*nw + nw);
        assert(ec_point_cmp(p, q) == 0);

        /* The same with G itself (fixed base) */
        ec_point_free(p);
        p = gt_clone(gen);
        assert(ec_point_scalar(p, k, sizeof k, rnd()) == 0);
        assert(ec_point_cmp(p, q) == 0);

        ec_point_free(p);
        ec_point_free(q);
    }
}

/*
 * The formulas directly: the addition of an affine point against the full
 * addition (also in place, from the neutral point, and for equal points),
 * the doubling against an addition to itself, the neutral point in the
 * full formulas, and the two scalar multiplications against each other
 * (same blinded scalar). base is a point other than G.
 */
static void test_group_formulas(const EcPoint *gen, const EcPoint *base)
{
    const EcGroup *g = gen->g;
    const size_t nw = g->nw;
    EcPoint *p, *q, *r1, *r2;
    uint8_t k[GT_MAX_LEN];
    uint64_t kb[16], lambda[GT_MAX_WORDS];
    EcWs ws;
    unsigned t;
    size_t i;

    assert(nw <= GT_MAX_WORDS && g->k_words <= 16 && g->len <= GT_MAX_LEN);
    assert(ec_ws_new(&ws, g->field) == 0);
    p = gt_clone(base);
    q = gt_clone(gen);
    r1 = gt_clone(gen);
    r2 = gt_clone(gen);

    for (t=0; t<20; t++) {
#if EC_USE_TABLES
        const uint64_t *tx = g->g_table + (rnd() % (g->windows*EC_DIGITS))*2*nw, *ty = tx + nw;
#else
        const uint64_t *tx = g->gx, *ty = g->gy;
#endif

        /* p: projective (Z != 1); q: affine, from the tables */
        assert(ec_point_double(p) == 0);
        gt_set_affine(q, tx, ty);

        g->add_affine(&ws, g, r1->x, r1->y, r1->z, p->x, p->y, p->z, tx, ty);
        g->add(&ws, g, r2->x, r2->y, r2->z, p->x, p->y, p->z, q->x, q->y, q->z);
        assert(ec_point_cmp(r1, r2) == 0);

        /* In place */
        gt_copy(r2, p);
        g->add_affine(&ws, g, r2->x, r2->y, r2->z, r2->x, r2->y, r2->z, tx, ty);
        assert(ec_point_cmp(r1, r2) == 0);

        /* From the neutral point (randomized) */
        ec_point_set_neutral(g, r1->x, r1->y, r1->z);
        for (i=0; i<3; i++)
            fe_mul(&ws, r1->x + i*nw, r1->x + i*nw, p->z);
        g->add_affine(&ws, g, r1->x, r1->y, r1->z, r1->x, r1->y, r1->z, tx, ty);
        assert(ec_point_cmp(r1, q) == 0);

        /* Equal points: a doubling */
        for (i=0; i<3; i++)
            fe_mul(&ws, r1->x + i*nw, q->x + i*nw, p->z);
        g->add_affine(&ws, g, r1->x, r1->y, r1->z, r1->x, r1->y, r1->z, tx, ty);
        g->dbl(&ws, g, r2->x, r2->y, r2->z, q->x, q->y, q->z);
        assert(ec_point_cmp(r1, r2) == 0);

        /* Doubling = addition to itself (in place) */
        g->dbl(&ws, g, r1->x, r1->y, r1->z, p->x, p->y, p->z);
        gt_copy(r2, p);
        g->add(&ws, g, r2->x, r2->y, r2->z, r2->x, r2->y, r2->z, r2->x, r2->y, r2->z);
        assert(ec_point_cmp(r1, r2) == 0);
        assert(g->on_curve(&ws, g, r1->x, r1->y, r1->z));

        /* The full formulas with the neutral point */
        ec_point_set_neutral(g, r1->x, r1->y, r1->z);
        g->add(&ws, g, r2->x, r2->y, r2->z, r1->x, r1->y, r1->z, p->x, p->y, p->z);
        assert(ec_point_cmp(r2, p) == 0);
        g->add(&ws, g, r2->x, r2->y, r2->z, p->x, p->y, p->z, r1->x, r1->y, r1->z);
        assert(ec_point_cmp(r2, p) == 0);
        g->dbl(&ws, g, r2->x, r2->y, r2->z, r1->x, r1->y, r1->z);
        assert(ec_point_cmp(r2, r1) == 0);
        assert(g->on_curve(&ws, g, r2->x, r2->y, r2->z));

        /* Variable and fixed base, with the same blinded scalar and lambda */
        gt_random_bytes(k, g->len);
        assert(ec_blind_scalar(kb, g->k_words, g->order, k, g->len, rnd()) == 0);
        for (i=0; i<nw; i++)
            lambda[i] = i == 0 ? rnd() | 1 : 0;
        gt_set_affine(r1, g->gx, g->gy);
        assert(ec_mul_var(&ws, g, r1->x, r1->y, r1->z, r1->x, r1->y, r1->z, kb, g->windows, lambda) == 0);
#if EC_USE_TABLES
        assert(ec_mul_g(&ws, g, r2->x, r2->y, r2->z, kb, g->windows, lambda) == 0);
        assert(ec_point_cmp(r1, r2) == 0);
#endif
        assert(g->on_curve(&ws, g, r1->x, r1->y, r1->z));
    }

    ec_point_free(p);
    ec_point_free(q);
    ec_point_free(r1);
    ec_point_free(r2);
    ec_ws_free(&ws);
}

/* k1*(k2*P) = k2*(k1*P), and (k1 + k2)*P = k1*P + k2*P, for random scalars and all the bases */
static void test_group_random(EcPoint *const *bases, size_t nbases)
{
    const EcGroup *g = bases[0]->g;
    uint8_t k1[GT_MAX_LEN], k2[GT_MAX_LEN], ks[GT_MAX_LEN + 1];
    unsigned t;
    size_t i;

    for (t=0; t<10; t++) {
        const EcPoint *base = bases[t % nbases];
        EcPoint *a, *b, *s;
        int carry = 0;

        gt_random_bytes(k1, g->len);
        gt_random_bytes(k2, g->len);
        a = gt_clone(base);
        b = gt_clone(base);
        assert(ec_point_scalar(a, k2, g->len, rnd()) == 0);
        assert(ec_point_scalar(a, k1, g->len, rnd()) == 0);
        assert(ec_point_scalar(b, k1, g->len, rnd()) == 0);
        assert(ec_point_scalar(b, k2, g->len, rnd()) == 0);
        assert(ec_point_cmp(a, b) == 0);
        ec_point_free(a);
        ec_point_free(b);

        for (i=g->len; i-- > 0;) {
            int v = k1[i] + k2[i] + carry;

            ks[i + 1] = (uint8_t)v;
            carry = v >> 8;
        }
        ks[0] = (uint8_t)carry;
        a = gt_clone(base);
        b = gt_clone(base);
        s = gt_clone(base);
        assert(ec_point_scalar(a, k1, g->len, rnd()) == 0);
        assert(ec_point_scalar(b, k2, g->len, rnd()) == 0);
        assert(ec_point_add(a, b) == 0);
        assert(ec_point_scalar(s, ks, g->len + 1, rnd()) == 0);
        assert(ec_point_cmp(a, s) == 0);
        ec_point_free(a);
        ec_point_free(b);
        ec_point_free(s);
    }
}

/*
 * The multiplication for public scalars gives the same result as the
 * blinded one, for all the bases (G uses the tables): for random scalars
 * of several lengths (also longer than the order), 0, the order of the
 * group and the order plus one.
 */
static void test_group_scalar_public(EcPoint *const *bases, size_t nbases)
{
    const EcGroup *g = bases[0]->g;
    const size_t lens[] = { 1, 2, 8, g->len, g->len + 8, 2*g->len };
    uint8_t k[2*GT_MAX_LEN + 8];
    unsigned t;
    size_t b, i, l;

    for (b=0; b<nbases; b++) {
        for (l=0; l<sizeof lens / sizeof lens[0]; l++) {
            for (t=0; t<5; t++) {
                EcPoint *p1 = gt_clone(bases[b]), *p2 = gt_clone(bases[b]);

                gt_random_bytes(k, lens[l]);
                assert(ec_point_scalar(p1, k, lens[l], rnd()) == 0);
                assert(ec_point_scalar_public(p2, k, lens[l]) == 0);
                assert(ec_point_cmp(p1, p2) == 0);
                ec_point_free(p1);
                ec_point_free(p2);
            }
        }

        /* 0, the order, the order + 1 (one more byte, for the carry) */
        for (t=0; t<3; t++) {
            const size_t len = g->len + 1;
            EcPoint *p1 = gt_clone(bases[b]), *p2 = gt_clone(bases[b]);

            memset(k, 0, len);
            if (t > 0)
                assert(nat_to_bytes(k, len, g->order, 0) == 0);
            for (i=len; t == 2 && i-- > 0;) {
                if (++k[i] != 0)
                    break;
            }
            assert(ec_point_scalar(p1, k, len, rnd()) == 0);
            assert(ec_point_scalar_public(p2, k, len) == 0);
            assert(ec_point_cmp(p1, p2) == 0);
            ec_point_free(p1);
            ec_point_free(p2);
        }
    }
}

/** All the tests of this file, for the bases of a curve (the first is G) **/
static void test_group(EcPoint *const *bases, size_t nbases)
{
    assert(nbases >= 2);
    test_group_errors(bases[0]);
#if EC_USE_TABLES
    test_group_g_table(bases[0]);
#else
    (void)test_group_g_table;
#endif
    test_group_formulas(bases[0], bases[nbases - 1]);
    test_group_random(bases, nbases);
    test_group_scalar_public(bases, nbases);
}
