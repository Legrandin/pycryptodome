/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * ML-DSA (mldsa.c), compiled with AVX2, BMI1 and BMI2 enabled.
 * It can only be loaded on a CPU that supports all three.
 *
 * The C code of mldsa-native does not change (the compiler can use the
 * new instructions for it), but SHA-3 and SHAKE compute 4 Keccak states
 * at once with AVX2 (keccak_x4_avx2.c, see mldsa_fips202.h).
 */

#define MLDSA_AVX2
#define MLDSA_MODULE mldsa_avx2_bmi2
#include "mldsa.c"
