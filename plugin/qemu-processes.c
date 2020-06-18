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

#include "qemu-processes.h"
#include "exec/gdbstub.h"
#include "target-types.h"
#include "oshandler/oshandler.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qpointer.h"
#include "qapi/qapi-types-oshandler.h"
#include "plugin/qemu-memory.h"

static int os_to_flags_breakpoint_type(int bp_type)
{
    switch(bp_type)
    {
        case OS_BREAKPOINT_SW:
        case OS_BREAKPOINT_HW:
            return GDB_BREAKPOINT_SW;
        case OS_WATCHPOINT_WRITE:
            return GDB_WATCHPOINT_WRITE;
        case OS_WATCHPOINT_READ:
            return GDB_WATCHPOINT_READ;
        case OS_WATCHPOINT_ACCESS:
            return GDB_WATCHPOINT_ACCESS;
    }

    return GDB_BREAKPOINT_SW;
}

const char *qemu_init_oshandler(int cpu_idx, const char *hint)
{
    OSHandler *os_handler = NULL;

    if(is_oshandler_active())
    {
        os_handler = oshandler_get_instance();
    }else{
        CPUState *cpu = qemu_get_cpu(cpu_idx);
        if(cpu)
        {
            os_handler = oshandler_init(cpu, hint);
        }
    }

    if(os_handler){
        return object_get_typename(OBJECT(os_handler));
    }

    return NULL;
}

OSPid qemu_get_ospid(uint64_t pid)
{
    if(!is_oshandler_active())
    {
        return NULL_PID;
    }

    OSHandler *os_handler = oshandler_get_instance();

    return OSHANDLER_GET_CLASS(os_handler)->get_ospid_by_pid(os_handler, pid);
}

OSPid qemu_get_ospid_by_name(const char *name)
{
    if(is_oshandler_active() && name != NULL)
    {
        OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

        return os_cc->get_ospid_by_name(os_handler, name);
    }

    return NULL_PID;
}

OSPid qemu_get_ospid_by_active(int cpu_idx)
{
    if(is_oshandler_active())
    {
        OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

        return os_cc->get_ospid_by_active(os_handler, qemu_get_cpu(cpu_idx));
    }

    return NULL_PID;
}

void qemu_free_ospid(OSPid pid)
{
    if(is_oshandler_active())
    {
        OSHandler *os_handler = oshandler_get_instance();

        OSHANDLER_GET_CLASS(os_handler)->release_ospid(os_handler, pid);
    }
}

OSBreakpoint* qemu_set_os_breakpoint(OSPid pid, uint64_t addr)
{
    if(!is_oshandler_active())
    {
        return NULL;
    }

    OSHandler *os_handler = oshandler_get_instance();

    return OSHANDLER_GET_CLASS(os_handler)->set_breakpoint(os_handler, addr, 1, OS_BREAKPOINT_SW, pid);
}

OSBreakpoint* qemu_find_os_breakpoint(uint64_t bp_id)
{
    if(!is_oshandler_active())
    {
        return NULL;
    }

    OSHandler *os_handler = oshandler_get_instance();
    OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

    QList *bps = os_cc->get_breakpoints(os_handler);
    const QListEntry *entry;
    OSBreakpoint *fbp = NULL;

    QLIST_FOREACH_ENTRY(bps, entry) {
        OSBreakpoint *bp = qpointer_get_pointer(qobject_to(QPointer, entry->value));
        if (bp->id == bp_id) {
            fbp = bp;
        }
    }

    return fbp;
}

OSBreakpoint* qemu_set_os_breakpoint_full(OSPid pid, uint64_t addr, uint64_t length, OSBreakpointType bp_type)
{
    int bp_flags = 0;

    if(!is_oshandler_active())
    {
        return NULL;
    }

    OSHandler *os_handler = oshandler_get_instance();

    bp_flags = os_to_flags_breakpoint_type(bp_type);

    return OSHANDLER_GET_CLASS(os_handler)->set_breakpoint(os_handler, addr, length, bp_flags, pid);
}

void qemu_remove_os_breakpoint(OSBreakpoint *bp)
{
    if(is_oshandler_active() && bp)
    {
        OSHandler *os_handler = oshandler_get_instance();

        OSHANDLER_GET_CLASS(os_handler)->remove_breakpoint(os_handler, bp);
    }
}

Process* qemu_get_process(OSPid pid)
{
    if(is_oshandler_active() && pid != NULL_PID)
    {
        OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

        ProcessInfo *pi = os_cc->get_processinfo_by_ospid(os_handler, pid);
        if(pi){
            return os_cc->get_process_detail(os_handler, pi);
        }
    }

    return NULL;
}

void qemu_free_process(Process *ps)
{
    qapi_free_Process(ps);
}

ProcessList* qemu_get_process_list(void)
{
    if(is_oshandler_active())
    {
        OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

        return os_cc->get_process_list(os_handler);
    }

    return NULL;
}

void qemu_free_process_list(ProcessList *pl)
{
    qapi_free_ProcessList(pl);
}

uint64_t qemu_get_pid_by_os_process(OSPid pid)
{
    if(is_oshandler_active() && pid != NULL_PID)
    {
        OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

        ProcessInfo *pi = os_cc->get_processinfo_by_ospid(os_handler, pid);
        if(pi){
            return pi->pid;
        }
    }

    return 0;
}

void *qemu_get_process_vma_first(Process *ps)
{
    void *first = NULL;

    switch(ps->type)
    {
        case PROCESS_TYPES_LNX:
            if(ps->u.lnx.task_mem){
                first = ps->u.lnx.task_mem->vm_areas;
            }
            break;
        case PROCESS_TYPES_WIN:
            first = ps->u.win.vad;
            break;
        case PROCESS_TYPES_WIN64:
            first = ps->u.win64.vad;
            break;
        case PROCESS_TYPES_NONE:
        case PROCESS_TYPES__MAX:
            break;
    }

    return first;
}

void qemu_get_process_vma_next(Process *ps, void **next, uint64_t *start, uint64_t *end, uint64_t *flags, uint64_t *pgprot, void **all)
{
    if(*next){
        switch(ps->type)
        {
            case PROCESS_TYPES_LNX:
            {
                VmAreaInfoList *cur = (VmAreaInfoList *)*next;
                *start = cur->value->vm_start;
                *end = cur->value->vm_end;
                *flags = cur->value->flags;
                *pgprot = cur->value->page_prot;
                if(all){
                    *all = cur->value;
                }
                *next = cur->next;
            }
                break;
            case PROCESS_TYPES_WIN:
            {
                WinVADList *cur = (WinVADList *)*next;
                *start = cur->value->base;
                *end = cur->value->base + cur->value->size;
                *flags = cur->value->flags;
                *pgprot = cur->value->control;
                if(all){
                    *all = cur->value;
                }
                *next = cur->next;
            }
                break;
            case PROCESS_TYPES_WIN64:
            {
                Win64VADList *cur = (Win64VADList *)*next;
                *start = cur->value->base;
                *end = cur->value->base + cur->value->size;
                *flags = cur->value->flags;
                *pgprot = cur->value->control;
                if(all){
                    *all = cur->value;
                }
                *next = cur->next;
            }
                break;
            case PROCESS_TYPES_NONE:
            case PROCESS_TYPES__MAX:
                break;
        }
    }else{
        *start = -1;
        *end = -1;
        *flags = 0;
        *pgprot = 0;
        if(all){
            *all = NULL;
        }
    }
}

void qemu_get_process_detail(Process *p, uint64_t *pid, uint64_t *procbase, uint64_t *procdir, const char **name)
{
    if(p){
        *name = p->name;
        *pid = p->info->pid;
        *procbase = p->info->procaddr;
        *procdir = p->info->cr3;
    }else{
        *pid = -1;
        *procbase = -1;
        *procdir = -1;
        *name = NULL;
    }
}

int qemu_set_anonymous_breakpoint(uint64_t addr)
{
    int ret_val = -1;
    CPUState* cpu = NULL;

    CPU_FOREACH(cpu)
    {
        ret_val = qemu_set_anonymous_breakpoint_on_cpu(cpu->cpu_index, addr, 1, OS_BREAKPOINT_SW);
        if (ret_val < 0)
        {
            return ret_val;
        }
    }

    return ret_val;
}

int qemu_set_anonymous_breakpoint_on_cpu(int cpu_idx, uint64_t addr, uint64_t length, OSBreakpointType bp_type)
{
    CPUState *cpu = qemu_get_cpu(cpu_idx);
    if(!cpu){
        return -1;
    }

    int bp_flags = os_to_flags_breakpoint_type(bp_type);

    return set_target_breakpoint(cpu, addr, length, bp_flags);
}

int qemu_remove_anonymous_breakpoint(uint64_t addr)
{
    int ret_val = -1;
    CPUState* cpu = NULL;

    CPU_FOREACH(cpu)
    {
        ret_val = qemu_remove_anonymous_breakpoint_on_cpu(cpu->cpu_index, addr, 1, OS_BREAKPOINT_SW);
        if (ret_val < 0)
        {
            return ret_val;
        }
    }

    return ret_val;
}

int qemu_remove_anonymous_breakpoint_on_cpu(int cpu_idx, uint64_t addr, uint64_t length, OSBreakpointType bp_type)
{
    CPUState *cpu = qemu_get_cpu(cpu_idx);
    if(!cpu){
        return -1;
    }

    int bp_flags = os_to_flags_breakpoint_type(bp_type);

    return remove_target_breakpoint(cpu, addr, length, bp_flags);
}

bool qemu_process_get_memory(int cpu_idx, OSPid pid, uint64_t address, uint8_t size, uint8_t **data)
{
    struct GetProcessMemoryArgs{
        int cpu_id;
        uint64_t address;
        uint8_t size;
        uint8_t **data;
    };

    struct GetProcessMemoryArgs gpm_args = {
        cpu_idx,
        address,
        size,
        data
    };

    void *get_process_memory(ProcessInfo *pi, void *args)
    {
        struct GetProcessMemoryArgs *gpm = (struct GetProcessMemoryArgs*)args;

        if(!qemu_get_virtual_memory(gpm->cpu_id, gpm->address, gpm->size, gpm->data)){
            return COROUTINE_FAILED;
        }

        return COROUTINE_SUCCESS;
    }

    if(!is_oshandler_active()) {
        return false;
    }

    OSHandler *os_handler = oshandler_get_instance();
    OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

    ProcessInfo *pi = os_cc->get_processinfo_by_ospid(os_handler, pid);
    if(!pi){
        return false;
    }

    if(os_cc->do_process_coroutine(os_handler, pi, get_process_memory, &gpm_args) == COROUTINE_FAILED){
        return false;
    }

    return true;
}

bool qemu_process_set_memory(int cpu_idx, OSPid pid, uint64_t address, uint8_t size, uint8_t *data)
{
    struct SetProcessMemoryArgs{
        int cpu_id;
        uint64_t address;
        uint8_t size;
        uint8_t *data;
    };

    struct SetProcessMemoryArgs spm_args = {
        cpu_idx,
        address,
        size,
        data
    };

    void *set_process_memory(ProcessInfo *pi, void *args)
    {
        struct SetProcessMemoryArgs *spm = (struct SetProcessMemoryArgs*)args;

        if(!qemu_set_virtual_memory(spm->cpu_id, spm->address, spm->size, spm->data)){
            return COROUTINE_FAILED;
        }

        return COROUTINE_SUCCESS;
    }

    if(!is_oshandler_active()) {
        return false;
    }

    OSHandler *os_handler = oshandler_get_instance();
    OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

    ProcessInfo *pi = os_cc->get_processinfo_by_ospid(os_handler, pid);
    if(!pi){
        return false;
    }

    if(os_cc->do_process_coroutine(os_handler, pi, set_process_memory, &spm_args) == COROUTINE_FAILED){
        return false;
    }

    return true;
}
