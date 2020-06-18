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
#include "qemu-registers.h"

void qemu_get_cpu_register_descriptor(int cpu_id, int reg_id, RegisterDescriptor **reg)
{
    CPUState *cpu = NULL;
    CPU_FOREACH(cpu)
    {
        CPUClass *cpu_class = CPU_GET_CLASS(cpu);

        if (cpu_class->get_register_list && cpu->cpu_index == cpu_id)
        {
            // Get a list of registers
            RegisterList reg_list;
            RegisterDescriptor *reg_desc = NULL;
            RegisterDescriptor *r_next = NULL;

            QLIST_INIT(&reg_list);
            cpu_class->get_register_list(cpu, &reg_list);

            // Cycle through the list and find the register reference
            QLIST_FOREACH_SAFE(reg_desc, &reg_list, next, r_next)
            {
                if( reg_desc->reg_id == reg_id )
                {
                    *reg = reg_desc;
                    break;
                }

                QLIST_REMOVE(reg_desc, next);
            }
        }
    }
}

uint8_t qemu_get_cpu_register(int cpu_id, int reg_id, uint8_t **data)
{
    CPUState *cpu = NULL;
    CPU_FOREACH(cpu)
    {
        if (cpu->cpu_index == cpu_id)
        {
            return get_target_cpu_register(cpu, reg_id, data);
        }
    }

    return 0;
}

void qemu_set_cpu_register(int cpu_id, int reg_id, uint8_t size, const uint8_t *data)
{
    CPUState *cpu = NULL;
    CPU_FOREACH(cpu)
    {
        if (cpu->cpu_index == cpu_id)
        {
            set_target_cpu_register(cpu, reg_id, size, data);
        }
    }
}

int qemu_get_cpu_register_id(const char *reg_name)
{
    return get_target_register_id(reg_name);
}

const char *qemu_get_cpu_register_name(int reg_id)
{
    return get_target_register_name(reg_id);
}

int qemu_get_cpu_first_register_id(void)
{
    return get_target_first_register_id();
}

int qemu_get_cpu_next_register_id(int reg_id)
{
    return get_target_next_register_id(reg_id);
}