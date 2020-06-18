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

#ifndef __QEMU_PROCESSES_H__
#define __QEMU_PROCESSES_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/cpu.h"
#include "oshandler/ostypes.h"

#ifdef __cplusplus
extern "C"{
#endif

const char *qemu_init_oshandler(int cpu_idx, const char *hint);
OSPid qemu_get_ospid(uint64_t pid);
OSPid qemu_get_ospid_by_name(const char *name);
OSPid qemu_get_ospid_by_active(int cpu_idx);
uint64_t qemu_get_pid_by_os_process(OSPid pid);
void qemu_free_ospid(OSPid pid);

OSBreakpoint* qemu_set_os_breakpoint(OSPid pid, uint64_t addr);
OSBreakpoint* qemu_set_os_breakpoint_full(OSPid pid, uint64_t addr, uint64_t length, OSBreakpointType bp_type);
OSBreakpoint* qemu_find_os_breakpoint(uint64_t bp_id);
void qemu_remove_os_breakpoint(OSBreakpoint *bp);

Process* qemu_get_process(OSPid pid);
void qemu_free_process(Process *ps);

ProcessList* qemu_get_process_list(void);
void qemu_free_process_list(ProcessList *pl);

void *qemu_get_process_vma_first(Process *ps);
void qemu_get_process_vma_next(Process *ps, void **next, uint64_t *start, uint64_t *end, uint64_t *flags, uint64_t *pgprot, void **all);

void qemu_get_process_detail(Process *p, uint64_t *pid, uint64_t *procbase, uint64_t *procdir, const char **name);

int qemu_set_anonymous_breakpoint(uint64_t addr);
int qemu_set_anonymous_breakpoint_on_cpu(int cpu_idx, uint64_t addr, uint64_t length, OSBreakpointType bp_type);
int qemu_remove_anonymous_breakpoint(uint64_t addr);
int qemu_remove_anonymous_breakpoint_on_cpu(int cpu_idx, uint64_t addr, uint64_t length, OSBreakpointType bp_type);

bool qemu_process_get_memory(int cpu_idx, OSPid pid, uint64_t address, uint8_t size, uint8_t **data);
bool qemu_process_set_memory(int cpu_idx, OSPid pid, uint64_t address, uint8_t size, uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif
