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
 *  Joseph Walker
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 * 
 * The creation of this code was funded by the US Government.
 */

#ifndef __QEMU_PROCESSES_H__
#define __QEMU_PROCESSES_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/cpu.h"
#include "oshandler/ostypes.h"

#ifdef __cplusplus
extern "C"{
#endif

int qemu_set_anonymous_breakpoint(uint64_t addr);
int qemu_set_anonymous_breakpoint_on_cpu(CPUState* cpu , uint64_t addr, uint64_t length, OSBreakpointType bp_type);

#ifdef __cplusplus
}
#endif

#endif