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

#ifndef __QEMU_VM_H__
#define __QEMU_VM_H__

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qom/cpu.h"

#ifdef __cplusplus
extern "C"{
#endif

void continue_vm(Error **errp);
void stop_vm(Error **errp);
void shutdown_vm(Error **errp);
void reset_vm(Error **errp);
void quit_vm(Error **errp);

#ifdef __cplusplus
}
#endif

#endif
