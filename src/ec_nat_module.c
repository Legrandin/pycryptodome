/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The elliptic curves on the natural number library (nat*.c): the NIST
 * curves (ec_nat.c), Ed448 (ed448.c) and X448 (curve448.c),
 * as the module Crypto.PublicKey._ec_nat.
 */

#define NAT_MODULE ec_nat

#include "nat.c"
#include "nat_div.c"
#include "nat_mod.c"
#include "nat_gcd.c"
#include "nat_prime.c"
#include "ec_common.c"
#include "ec_nat.c"
#include "ed448.c"
#include "curve448.c"
