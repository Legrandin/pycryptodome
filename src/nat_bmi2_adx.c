/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The natural number library (nat*.c), compiled for x86-64 CPUs with
 * BMI2 and ADX (MULX, ADCX and ADOX), as the module
 * Crypto.Math._nat_bmi2_adx. It can only be loaded on a CPU that supports
 * both; Crypto.Math._IntegerNat checks that, and uses Crypto.Math._nat
 * otherwise.
 *
 * Only addmul_row() in nat_mod.c differs (NAT_BMI2_ADX): the core of the
 * Montgomery multiplication and squaring.
 */

#define NAT_MODULE nat_bmi2_adx
#define NAT_BMI2_ADX

#include "nat.c"
#include "nat_div.c"
#include "nat_mod.c"
#include "nat_gcd.c"
#include "nat_prime.c"
