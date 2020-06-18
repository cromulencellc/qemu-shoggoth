/*
 * Rapid Analysis QEMU System Emulator
 *
 * Copyright (c) 2020 Cromulence LLC
 *
 * Distribution Statement A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * Authors:
 *  Adam Critchley <shoggoth@cromulence.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 * 
 * The creation of this code was funded by the US Government.
 */

#ifndef __INLINES_H__
#define __INLINES_H__

#include "qemu/error-report.h"

#define fread_checked(dest, s, infile) \
{ \
    size_t b = fread(dest, 1, s, infile); \
    if( b != s ){ \
        error_printf("Only able to read %lu out of requested %lu bytest: %s, %d", \
            b, s, __FILE__, __LINE__); \
    } \
}

#endif

