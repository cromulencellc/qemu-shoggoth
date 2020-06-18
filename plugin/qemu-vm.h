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

#ifndef __QEMU_VM_H__
#define __QEMU_VM_H__

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qom/cpu.h"
#include "qapi/qapi-types-ui.h"
#include "qapi/qapi-types-block-core.h"

#ifdef __cplusplus
extern "C"{
#endif

void qemu_vm_continue(void);
void qemu_vm_stop(int reason);
void qemu_vm_shutdown(void);
void qemu_vm_reset(void);
void qemu_vm_quit(void);
int  qemu_vm_get_state(void);
void qemu_vm_send_key(const char *keys);
void qemu_vm_send_keylist(KeyValueList *keys, bool has_hold_time, int64_t hold_time);
void qemu_vm_send_keystring(const char *string);
bool qemu_vm_save_screenshot(const char *file_name, bool has_device, const char *device,
                    bool has_head, int64_t head);
void qemu_vm_get_snapshots(ImageInfoList **snapshots);
const char *qemu_vm_get_arch(int cpu_idx);

#ifdef __cplusplus
}
#endif

#endif
