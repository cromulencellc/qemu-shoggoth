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

#ifndef __OSARCH__
#define __OSARCH__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/object.h"
#include "qapi/qmp/qstring.h"
#include "oshandler/ostypes.h"
#include "qapi/qapi-types-oshandler.h"

#define TYPE_OSARCH "osarch"
#define OSARCH(obj)                                    \
    OBJECT_CHECK(OSArch, (obj), TYPE_OSARCH)
#define OSARCH_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(OSArchClass, klass, TYPE_OSARCH)
#define OSARCH_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(OSArchClass, obj, TYPE_OSARCH)

typedef struct {
    Object obj;
    QString *process_header;
    CPUState *cpu;
} OSArch;

typedef struct {
    ObjectClass parent;

    OSArch* (*detect)(CPUState* cpu);

    int  (*set_breakpoint)(OSArch* ctxt, uint64_t addr, uint64_t length, int flags, ProcessInfo *pi);
    int  (*remove_breakpoint)(OSArch* ctxt, uint64_t addr, uint64_t length, int flags, ProcessInfo *pi);
    bool (*breakpoint_check)(OSArch *ctxt, CPUState* cpu, OSBreakpoint *bp);
    void (*remove_all_breakpoints)(OSArch* ctxt);
    bool (*is_same_process)(OSArch* ctxt, ProcessInfo *lhs, ProcessInfo *rhs);
    void (*get_process_string)(OSArch* ctxt, ProcessInfo *pi, QString **pqstr);
    uint64_t (*get_active_pagetable)(OSArch* arch, CPUState* cpu);
    void* (*process_enter)(OSArch* ctxt, ProcessInfo *pi);
    void  (*process_exit)(OSArch* ctxt, void *state);
} OSArchClass;

OSArch *osarch_init(CPUState *cpu);

#endif