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

#ifndef __INTERNAL_PLUGIN_H__
#define __INTERNAL_PLUGIN_H__

#include "qemu-common.h"
#include "qemu/option.h"
#include "qemu-options.h"
#include "qemu/option_int.h"
#include "qapi/qapi-types-misc.h"
#include "plugin/plugin.h"

typedef struct PluginList {
    Plugin *plugin;
    QLIST_ENTRY(PluginList) next;
} PluginList;

// Option Contents
extern QemuOptsList qemu_plugin_opts;
extern QemuOptsList qemu_plugins_opts;

// Options lists
typedef struct PluginOptions {
     QTAILQ_HEAD(, QemuOpts) head;
} PluginOptions;

#endif