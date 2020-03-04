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

#include "qemu-processes.h"
#include "target-types.h"
#include "exec/gdbstub.h"

int qemu_set_anonymous_breakpoint(uint64_t addr)
{
    int ret_val = -1;
    CPUState* cpu = NULL;

    CPU_FOREACH(cpu)
    {
        ret_val = qemu_set_anonymous_breakpoint_on_cpu(cpu, addr, 1, OS_BREAKPOINT_SW);
        if (ret_val < 0)
        {
            return ret_val;
        }
    }
    return ret_val;
}

int qemu_set_anonymous_breakpoint_on_cpu(CPUState* cpu, uint64_t addr, uint64_t length, OSBreakpointType bp_type)
{
    int bp_flags = 0;

    switch(bp_type)
    {
        case OS_BREAKPOINT_SW:
        case OS_BREAKPOINT_HW:
            bp_flags = GDB_BREAKPOINT_SW;
            break;
        case OS_WATCHPOINT_WRITE:
            bp_flags = GDB_WATCHPOINT_WRITE;
            break;
        case OS_WATCHPOINT_READ:
            bp_flags = GDB_WATCHPOINT_READ;
            break;
        case OS_WATCHPOINT_ACCESS:
            bp_flags = GDB_WATCHPOINT_ACCESS;
            break;
    }

    return set_target_breakpoint(cpu, addr, length, bp_flags);
}