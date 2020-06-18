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
#include "sysemu/hw_accel.h"
#include "target-types.h"
#include "qemu-memory.h"
#include "cpu.h"

bool qemu_get_virtual_memory(int cpu_id, uint64_t address, uint64_t size, uint8_t **data)
{
    CPUState *cpu = qemu_get_cpu(cpu_id);
    if (cpu)
    {
        if(!(*data))
        {
            *data = g_malloc(size);
        }

        CPUClass *cc = CPU_GET_CLASS(cpu);
        if (cc->memory_rw_debug) {
            if(cc->memory_rw_debug(cpu, address, *data, size, 0) < 0){
                return false;
            }
        }else{
            if(cpu_memory_rw_debug(cpu, address, *data, size, 0) < 0){
                return false;
            }
        }
    }

    return true;
}

bool qemu_set_virtual_memory(int cpu_id, uint64_t address, uint64_t size, uint8_t *data)
{
    CPUState *cpu = qemu_get_cpu(cpu_id);
    if (cpu)
    {
        CPUClass *cc = CPU_GET_CLASS(cpu);

        if (cc->memory_rw_debug) {
            if(cc->memory_rw_debug(cpu, address, data, size, 1) != 0){
                return false;
            }
        }else{
            if(cpu_memory_rw_debug(cpu, address, data, size, 1) != 0){
                return false;
            }
        }
    }

    return true;
}

void qemu_get_physical_memory(uint64_t address, uint64_t size, uint8_t **data)
{
    if(*data)
    {
        // Read into existing memory...
        cpu_physical_memory_read(address, *data, size);
    }else{
        // Get the pointer to physical memory in host memory.
        *data = qemu_map_ram_ptr_nofault(NULL, address, NULL);
        if (!*data) {
            return;
        }
    }
}

void qemu_set_physical_memory(uint64_t address, uint64_t size, uint8_t *data)
{
    cpu_physical_memory_write(address, data, size);
}

bool qemu_load_u64(int cpu_id, uint64_t address, uint64_t *data)
{
    return qemu_get_virtual_memory(cpu_id, address, sizeof(data[0]), ((uint8_t **)&data));
}

bool qemu_load_u32(int cpu_id, uint64_t address, uint32_t *data)
{
    return qemu_get_virtual_memory(cpu_id, address, sizeof(data[0]), ((uint8_t **)&data));
}

bool qemu_load_u16(int cpu_id, uint64_t address, uint16_t *data)
{
    return qemu_get_virtual_memory(cpu_id, address, sizeof(data[0]), ((uint8_t **)&data));
}

bool qemu_load_u8(int cpu_id, uint64_t address, uint8_t *data)
{
    return qemu_get_virtual_memory(cpu_id, address, sizeof(data[0]), ((uint8_t **)&data));
}

bool qemu_store_u64(int cpu_id, uint64_t address, uint64_t data)
{
    return qemu_set_virtual_memory(cpu_id, address, sizeof(data), (uint8_t *)&data);
}

bool qemu_store_u32(int cpu_id, uint64_t address, uint32_t data)
{
    return qemu_set_virtual_memory(cpu_id, address, sizeof(data), (uint8_t *)&data);
}

bool qemu_store_u16(int cpu_id, uint64_t address, uint16_t data)
{
    return qemu_set_virtual_memory(cpu_id, address, sizeof(data), (uint8_t *)&data);
}

bool qemu_store_u8(int cpu_id, uint64_t address, uint8_t data)
{
    return qemu_set_virtual_memory(cpu_id, address, sizeof(data), (uint8_t *)&data);
}
