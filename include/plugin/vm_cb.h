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

#ifndef __VM_CB_H__
#define __VM_CB_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/cpu.h"

void notify_vm_startup(void);
void notify_vm_shutdown(void);

bool is_vm_startup_instrumentation_enabled(void);
bool is_vm_shutdown_instrumentation_enabled(void);

#endif