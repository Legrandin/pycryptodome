/*
 * SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Salsa20 stream cipher (Salsa20.c), compiled with AVX2, BMI1 and BMI2
 * enabled. It can only be loaded on a CPU that supports all three.
 *
 * It computes 8 blocks of key stream at a time with AVX2.
 * BMI1 and BMI2 are not used, but they come with the same compiler flags
 * and CPU check as the other *_avx2_bmi2 modules.
 */

#define SALSA20_MODULE Salsa20_avx2_bmi2
#define SALSA20_AVX2
#include "Salsa20.c"
