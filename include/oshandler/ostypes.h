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

#ifndef __OSTYPES_H__
#define __OSTYPES_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/qapi-types-oshandler.h"

#define NULL_PID  ((OSPid)NULL)

// Undefined type protection.
typedef struct OSPid_d *OSPid;

typedef enum OSBreakpointType{
    OS_BREAKPOINT_SW,
    OS_BREAKPOINT_HW,
    OS_WATCHPOINT_WRITE,
    OS_WATCHPOINT_READ,
    OS_WATCHPOINT_ACCESS
} OSBreakpointType;

typedef struct OSBreakpoint {
    uint64_t id;
    uint64_t addr;
    uint64_t length;
    uint16_t flags;
    bool disabled;
    bool suppressed;
    OSBreakpointType type;
    OSPid pid;
} OSBreakpoint;

#endif
