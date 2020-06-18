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

#ifndef __OSARCH_X86__
#define __OSARCH_X86__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "oshandler/osarch.h"

#define TYPE_OSARCHX86 "osarchx86"
#define OSARCHX86(obj)                                    \
    OBJECT_CHECK(OSArchX86, (obj), TYPE_OSARCHX86)
#define OSARCHX86_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(OSArchX86Class, klass, TYPE_OSARCHX86)
#define OSARCHX86_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(OSArchX86Class, obj, TYPE_OSARCHX86)

typedef struct {
    OSArch obj;
    X86CPU *x86cpu;
} OSArchX86;

typedef struct {
    OSArchClass parent;
} OSArchX86Class;

uint64_t parse_idt_entry_base(CPUState* cpu, uint64_t idt_addr, uint16_t entry);

#endif