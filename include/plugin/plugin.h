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

#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/object.h"
#include "plugin/plugin-object.h"

// ****************************************************** //
// **********       Plugin Class Setup        ********** //
// **************************************************** //

#define TYPE_PLUGIN "Plugin"
#define PLUGIN(obj)                                    \
    OBJECT_CHECK(Plugin, (obj), TYPE_PLUGIN)
#define PLUGIN_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(PluginClass, klass, TYPE_PLUGIN)
#define PLUGIN_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(PluginClass, obj, TYPE_PLUGIN)

typedef struct Plugin Plugin;
typedef struct PluginClass PluginClass;

#define MAX_PLUGIN_NAME (251)

struct Plugin {
    Object obj;
    void *dl_handle;
    char plugin_name[MAX_PLUGIN_NAME];
    char plugin_path[PATH_MAX];
    TypeInfo type_info;
    QemuOptsList *options;
    QemuOptsList *commands;
    const char *loader_pattern;
    TypeInfo *loader_type;
};

struct PluginClass {
    ObjectClass parent;
    size_t (*path_equals)(Plugin *this, const char *to_compare);
    size_t (*name_equals)(Plugin *this, const char *to_compare);
    bool (*load_plugin)(Plugin *this);
    PluginObject *(*create_instance)(Plugin *this, const char *args);
};

// ******************************************************** //
// **********       Plugin Class Helpers         ********* //
// ****************************************************** //

void qemu_plugin_register_type(void *opaque, TypeInfo *plugin_type);
void qemu_plugin_register_options(void *opaque, QemuOptsList *opts);
void qemu_plugin_register_commands(void *opaque, QemuOptsList *commands);
void qemu_plugin_register_loader(void *opaque, const char *pattern, TypeInfo *plugin_subtype);

PluginObject *qemu_plugin_find_plugin(const char *name);

Plugin *plugin_create(const char *name, const char *file_path);
Plugin *plugin_create_extended(Plugin *base, const char *name, const char *file_path);

#endif