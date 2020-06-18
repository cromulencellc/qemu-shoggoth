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

#ifndef __RA_TYPES_H__
#define __RA_TYPES_H__

#include "qemu/queue.h"

#define C_RES 0xff
#define C_RES_NAME "RESERVED"

typedef struct RegisterDescriptor {
    uint8_t reg_id;
    char reg_name[25];
    uint8_t reg_size;
    uint8_t *reg_value;
    bool reserved;
    
    QLIST_ENTRY(RegisterDescriptor) next;
} RegisterDescriptor;

typedef QLIST_HEAD(RegisterList, RegisterDescriptor) RegisterList;


typedef struct MemoryDescriptor {
    uint64_t offset; 
    uint32_t size; 
    uint8_t *value;
    QLIST_ENTRY(MemoryDescriptor) next;
} MemoryDescriptor;

typedef QLIST_HEAD(MemoryList, MemoryDescriptor) MemoryList;

#endif