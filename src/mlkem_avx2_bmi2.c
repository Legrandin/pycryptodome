/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * ML-KEM (mlkem.c), compiled with AVX2, BMI1 and BMI2 enabled.
 * It can only be loaded on a CPU that supports all three.
 *
 * The C code of mlkem-native does not change (the compiler can use the
 * new instructions for it), but SHA-3 and SHAKE compute 4 Keccak states
 * at once with AVX2 (keccak_x4_avx2.c, see mlkem_fips202.h).
 */

#define MLKEM_AVX2
#define MLKEM_MODULE mlkem_avx2_bmi2
#include "mlkem.c"
