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

#include "qemu/osdep.h"
#include "qom/cpu.h"
#include "target-types.h"
#include "register-types.h"
#include "cpu.h"
#include "exec/gdbstub.h"
#include "sysemu/hw_accel.h"
#include "oshandler/oshandler.h"
    
int get_target_first_register_id(void)
{
    return -1;
}

int get_target_next_register_id(int reg_id)
{
    return -1;
}

const char *get_target_register_name(int reg_id)
{
    return NULL;
}

int get_target_register_id(const char *reg_name)
{
    return -1;
}

int remove_target_breakpoint(CPUState *cpu, uint64_t bp_addr, uint64_t length, int bp_flags)
{
    return 0;
}

int set_target_breakpoint(CPUState *cpu, uint64_t bp_addr, uint64_t length, int bp_flags)
{
    return -ENOSYS;  
}

uint8_t get_target_cpu_register(CPUState *cpu, int reg_id, uint8_t **data)
{
    return 0;
}

void set_target_cpu_register(CPUState *cpu, int reg_id, uint8_t size, const uint8_t *data)
{
}
