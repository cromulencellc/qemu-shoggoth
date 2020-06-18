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

#ifndef __OSHANDLER_H__
#define __OSHANDLER_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qstring.h"
#include "oshandler/osarch.h"
#include "oshandler/ostypes.h"
#include "qapi/qapi-types-oshandler.h"

#define TYPE_OSHANDLER "oshandler"
#define OSHANDLER(obj)                                    \
    OBJECT_CHECK(OSHandler, (obj), TYPE_OSHANDLER)
#define OSHANDLER_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(OSHandlerClass, klass, TYPE_OSHANDLER)
#define OSHANDLER_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(OSHandlerClass, obj, TYPE_OSHANDLER)

#define COROUTINE_FAILED ((void*)0)
#define COROUTINE_SUCCESS ((void*)~0)

typedef struct OSPidPool OSPidPool;
typedef void *(*OSHANDLER_PROC_COROUTINE)(ProcessInfo *pi, void *args);

typedef struct {
    Object obj;

    OSPidPool *pid_pool;
    size_t pool_size;

    OSArch *arch;
    uint32_t num_bp;
    QList *breakpoints;
    QString *process_header;
    int singlestep_enabled;
} OSHandler;

typedef struct {
    ObjectClass parent;

    OSHandler* (*scan)(OSHandler* ctxt, OSArch *arch);

    void (*print_process_list)(OSHandler* ctxt, ProcessInfo *cur_pi);

    QList* (*get_breakpoints)(OSHandler* ctxt);
    OSBreakpoint* (*set_breakpoint)(OSHandler* ctxt, uint64_t addr, uint64_t length, OSBreakpointType bp_type, OSPid pid);
    OSBreakpoint* (*get_breakpoint)(OSHandler* ctxt, uint64_t bp_id);
    bool (*breakpoint_check)(OSHandler* ctxt, CPUState* cpu, OSBreakpoint *bp);
    void (*enable_breakpoint)(OSHandler* ctxt, OSBreakpoint *bp);
    void (*disable_breakpoint)(OSHandler* ctxt, OSBreakpoint *bp);
    void (*suppress_breakpoint)(OSHandler* ctxt, OSBreakpoint *bp);
    void (*reset_breakpoint)(OSHandler* ctxt, OSBreakpoint *bp);
    int  (*remove_breakpoint)(OSHandler* ctxt, OSBreakpoint *bp);
    void (*remove_breakpoints)(OSHandler* ctxt, OSBreakpointType bp_type);
    void (*remove_all_breakpoints)(OSHandler* ctxt);

    bool (*is_active_process)(OSHandler* ctxt, CPUState* cpu, ProcessInfo *pi);
    Process* (*get_process_detail)(OSHandler* ctxt, ProcessInfo *pi);
    void (*get_process_string)(OSHandler* ctxt, ProcessInfo *pi, QString **pqstr);
    ProcessList* (*get_process_list)(OSHandler* ctxt);
    void (*load_new_process)(OSHandler *ctxt, int pid ,const char *);

    OSPid (*get_ospid_by_pid)(OSHandler* ctxt, uint64_t pid);
    OSPid (*get_ospid_by_active)(OSHandler* ctxt, CPUState* cpu);
    OSPid (*get_ospid_by_name)(OSHandler* ctxt, const char *name);
    void (*release_ospid)(OSHandler* ctxt, OSPid pid);

    ProcessInfo* (*get_processinfo_by_pid)(OSHandler* ctxt, uint64_t pid);
    ProcessInfo* (*get_processinfo_by_active)(OSHandler* ctxt, CPUState *cpu);
    ProcessInfo* (*get_processinfo_by_name)(OSHandler* ctxt, const char *name);
    ProcessInfo* (*get_processinfo_by_ospid)(OSHandler* ctxt, OSPid pid);
    bool         (*is_active_by_processinfo)(OSHandler* ctxt, CPUState* cpu, ProcessInfo *pi);
    void*        (*do_process_coroutine)(OSHandler *ctxt, ProcessInfo *pi, OSHANDLER_PROC_COROUTINE func, void *args);

} OSHandlerClass;

OSHandler *oshandler_init(CPUState *cpu, const char *hint);
bool is_oshandler_active(void);
OSHandler *oshandler_get_instance(void);

void object_property_add_uint64_ptr2(Object *obj, const char *name,
                                    uint64_t *v, Error **errp);

Process *process_new(ProcessTypes pt);
ProcessList *processlist_new(void);

#endif
