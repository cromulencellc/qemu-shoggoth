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

#ifndef __RA_CB_H__
#define __RA_CB_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "ra.h"

bool is_ra_stop_instrumentation_enabled(void);

void notify_ra_start(CommsWorkItem *work);
void notify_ra_stop(CPUState *cpu, SHA1_HASH_TYPE job_hash);
void notify_ra_idle(void);

#endif