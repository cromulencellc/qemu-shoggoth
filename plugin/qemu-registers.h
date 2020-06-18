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

#ifndef __QEMU_REGISTERS_H__
#define __QEMU_REGISTERS_H__

#include "ra-types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

void qemu_get_cpu_register_descriptor(int cpu_id, int reg_id, RegisterDescriptor **reg);
uint8_t qemu_get_cpu_register(int cpu_id, int reg_id, uint8_t **data);
void qemu_set_cpu_register(int cpu_id, int reg_id, uint8_t size, const uint8_t *data);
int qemu_get_cpu_register_id(const char *reg_name);
const char *qemu_get_cpu_register_name(int reg_id);
int qemu_get_cpu_first_register_id(void);
int qemu_get_cpu_next_register_id(int reg_id);

#ifdef __cplusplus
}
#endif

#endif