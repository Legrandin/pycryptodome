/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Definitions shared by aegis.c and the backends that define their own state */

#ifndef AEGIS_H
#define AEGIS_H

#include <stddef.h>
#include <stdint.h>

/* The variants, as in Crypto.Cipher.AEGIS */
enum AegisVariant { AEGIS_128L = 1, AEGIS_256 = 2 };

static void wipe(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t*)p;

    while (len--)
        *v++ = 0;
}

#endif
