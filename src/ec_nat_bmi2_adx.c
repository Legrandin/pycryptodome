/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The NIST curves (ec_nat.c), with the natural number library (nat*.c),
 * compiled for x86-64 CPUs with BMI2 and ADX, as the module
 * Crypto.PublicKey._ec_nat_bmi2_adx. It can only be loaded on a CPU that
 * supports both; Crypto.PublicKey._nist_ecc checks that, and uses
 * Crypto.PublicKey._ec_nat otherwise. See nat_bmi2_adx.c.
 */

#define NAT_MODULE ec_nat_bmi2_adx
#define NAT_BMI2_ADX

#include "nat.c"
#include "nat_div.c"
#include "nat_mod.c"
#include "nat_gcd.c"
#include "nat_prime.c"
#include "ec_nat.c"
