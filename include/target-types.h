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

#ifndef __TARGET_TYPES_H__
#define __TARGET_TYPES_H__

#include <stdint.h>
#include "qom/cpu.h"

int get_target_register_id(const char *reg_name);
const char *get_target_register_name(int reg_id);
int get_target_first_register_id(void);
int get_target_next_register_id(int reg_id);
int remove_target_breakpoint(CPUState *cpu, uint64_t bp_addr, uint64_t length, int bp_flags);
int set_target_breakpoint(CPUState *cpu, uint64_t bp_addr, uint64_t length, int bp_flags);
uint8_t get_target_cpu_register(CPUState *cpu, int reg_id, uint8_t **data);
void set_target_cpu_register(CPUState *cpu, int reg_id, uint8_t size, const uint8_t *data);

#endif
