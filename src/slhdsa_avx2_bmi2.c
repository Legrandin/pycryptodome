/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SLH-DSA (slhdsa.c), compiled with AVX2, BMI1 and BMI2 enabled.
 * It can only be loaded on a CPU that supports all three.
 *
 * - For SHAKE, wots_pkGen computes 4 chains at once with AVX2
 *   (see keccak_x4_avx2.c).
 * - The scalar Keccak gets faster with BMI1 and BMI2, as in keccak_avx2_bmi2.c.
 *
 * The exported functions have the same names as in slhdsa.c.
 */

#define SLHDSA_MODULE slhdsa_avx2_bmi2
#define SLHDSA_AVX2
#include "slhdsa.c"
