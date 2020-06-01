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

#ifndef __QEMU_PLUGIN_H__
#define __QEMU_PLUGIN_H__

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/option.h"
#include "qemu/option_int.h"
#include "qom/object.h"
#include "racomms/interface.h"
#include "racomms/racomms-types.h"
#include "plugin/plugin-object.h"

void qemu_plugin_register_type(void *opaque, TypeInfo *plugin_type);
void qemu_plugin_register_options(void *opaque, QemuOptsList *opts);
void qemu_plugin_register_commands(void *opaque, QemuOptsList *commands);
void qemu_plugin_register_loader(void *opaque, const char *pattern, TypeInfo *plugin_subtype);

PluginObject *qemu_plugin_find_plugin(const char *name);

bool plugin_setup(void *plugin, const char *path);

#endif
