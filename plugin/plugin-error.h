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

#ifndef __PLUGIN_ERROR_H__
#define __PLUGIN_ERROR_H__

#include "qemu/osdep.h"

#ifdef __cplusplus
extern "C"{
#endif

extern Error *qemu_plugin_last_error;

void qemu_get_last_error(Error **last_error);

#ifdef __cplusplus
}
#endif

#endif