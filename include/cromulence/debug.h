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

#define CROM_DEBUG_LVL_BASE (20)
#define CROM_DEBUG_LVL_INFO  (CROM_DEBUG_LVL_BASE + 1)
#define CROM_DEBUG_LVL_WARN  (CROM_DEBUG_LVL_BASE + 2)
#define CROM_DEBUG_LVL_ERROR (CROM_DEBUG_LVL_BASE + 3)
#define CROM_DEBUG_LVL_DEBUG (CROM_DEBUG_LVL_BASE + 4)
#define CROM_DEBUG_LVL_PANIC (CROM_DEBUG_LVL_BASE + 5)

#define CROM_DEBUG_CAT_BASE (120)
#define CROM_DEBUG_CAT_DONTCARE  (CROM_DEBUG_CAT_BASE + 1)
#define CROM_DEBUG_CAT_CALLSTACK (CROM_DEBUG_CAT_BASE + 2)
#define CROM_DEBUG_CAT_EXCEPTION (CROM_DEBUG_CAT_BASE + 3)

#define CROM_DEBUG3(level, category, msg) \
{  \
   printf("{CROM} %s\n", msg); \
}

#define CROM_DEBUG2(level, msg) CROM_DEBUG3(level, CROM_DEBUG_CAT_DONTCARE, msg)

#define CROM_DEBUG(msg) CROM_DEBUG3(CROM_DEBUG_LVL_INFO, CROM_DEBUG_CAT_DONTCARE, msg)

#define CROM_CALLSTACK_DEBUG() CROM_DEBUG3(CROM_DEBUG_LVL_INFO, CROM_DEBUG_CAT_CALLSTACK, __func__)

#define CROM_INSERT_BKPT() {asm("int $3");}