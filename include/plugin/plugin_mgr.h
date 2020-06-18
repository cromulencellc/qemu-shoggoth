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

#ifndef __PLUGIN_MGR_H__
#define __PLUGIN_MGR_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/option_int.h"
#include "qapi/qapi-types-misc.h"
#include "plugin/plugin.h"

typedef struct PluginList {
    Plugin *plugin;
    QLIST_ENTRY(PluginList) next;
} PluginList;

typedef QLIST_HEAD(Plugins, PluginList) Plugins;
extern Plugins plugin_list;

typedef struct PluginInstanceList {
    PluginObject *instance;
    QLIST_ENTRY(PluginInstanceList) next;
} PluginInstanceList;

typedef QLIST_HEAD(PluginInstances, PluginInstanceList) PluginInstances;
extern PluginInstances plugin_instance_list;

#define PLUGIN_FOREACH(plugin) QLIST_FOREACH(plugin, &plugin_instance_list, next)
#define PLUGIN_FOREACH_SAFE(plugin, next_plugin) \
    QLIST_FOREACH_SAFE(plugin, &plugin_instance_list, next, next_plugin)

// Option Contents
extern QemuOptsList qemu_plugin_opts;
extern QemuOptsList qemu_plugins_opts;

// Options lists
typedef struct PluginOptions {
     QTAILQ_HEAD(, QemuOpts) head;
} PluginOptions;

// Working with the plugin subsystem
void plugin_init_globals(void);
void plugin_init_plugins(void);
bool plugin_create_plugin(const char *optstr);

#endif