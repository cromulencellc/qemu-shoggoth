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

#ifndef __QEMU_MEMORY_H__
#define __QEMU_MEMORY_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

bool qemu_get_virtual_memory(int cpu_id, uint64_t address, uint64_t size, uint8_t **data);
bool qemu_set_virtual_memory(int cpu_id, uint64_t address, uint64_t size, uint8_t *data);
void qemu_get_physical_memory(uint64_t address, uint64_t size, uint8_t **data);
void qemu_set_physical_memory(uint64_t address, uint64_t size, uint8_t *data);

bool qemu_load_u64(int cpu_id, uint64_t address, uint64_t *data);
bool qemu_load_u32(int cpu_id, uint64_t address, uint32_t *data);
bool qemu_load_u16(int cpu_id, uint64_t address, uint16_t *data);
bool qemu_load_u8(int cpu_id, uint64_t address, uint8_t *data);

bool qemu_store_u64(int cpu_id, uint64_t address, uint64_t data);
bool qemu_store_u32(int cpu_id, uint64_t address, uint32_t data);
bool qemu_store_u16(int cpu_id, uint64_t address, uint16_t data);
bool qemu_store_u8(int cpu_id, uint64_t address, uint8_t data);

#ifdef __cplusplus
}
#endif

#endif
