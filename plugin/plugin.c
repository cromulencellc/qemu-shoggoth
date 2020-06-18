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

#include "plugin/plugin.h"
#include "qemu/option.h"
#include "qemu-options.h"
#include "plugin/plugin_mgr.h"
#include "qemu/error-report.h"

#include <stdlib.h>
#include <dlfcn.h>

// ********************************************************* //
// **********       Plugin Class functions       ********** //
// ******************************************************* //

static size_t plugin_path_equals(Plugin *this, const char *to_compare)
{
    return strncmp(to_compare, this->plugin_path, strlen(this->plugin_path)) ?
       0 : strlen(this->plugin_path);
}

static size_t plugin_name_equals(Plugin *this, const char *to_compare)
{
    return strncmp(to_compare, this->plugin_name, strlen(this->plugin_name)) ?
       0 : strlen(this->plugin_name);
}

static bool plugin_load_plugin(Plugin *this)
{
    char *error = NULL;

    // Open the plugin
    this->dl_handle = dlopen(this->plugin_path, RTLD_LAZY);
    error = dlerror(); 
    if(error != NULL)
    {
        error_report("%s\n", error);
        return false;
    }

    bool (*this_plugin_setup)(void *plugin, char *path) = dlsym(this->dl_handle, "plugin_setup");
    error = dlerror(); 
    if(error != NULL)
    {
        error_report("%s\n", error);
        return false;
    }

    if(!this_plugin_setup((void*)this, this->plugin_path))
    {
        error_report("Setup failed for plugin %s\n", this->plugin_path);
        return false;
    }

    return true;
}

static PluginObject *plugin_create_instance(Plugin *this, const char *args)
{
    // Make a new instance of the plugin object
    const char *args_in = NULL;

    if (args && *args != '\0')
    {
        args_in = args + 1;
    }
    
    PluginObject *po = plugin_object_create(this->type_info.name, args_in);
    PluginObjectClass *po_class = PLUGIN_OBJECT_GET_CLASS(po);
    QemuOpts *plugin_options = NULL;

    // Check to see if the plugin takes opts
    if (this->options && args_in)
    {
        // We will parse the opts accroding to the plugin and create an instance
        plugin_options = qemu_opts_parse(this->options, args_in, false, NULL);
    }

    if( po_class->init_plugin &&
        !po_class->init_plugin(po, this->plugin_path, plugin_options) )
    {
        object_unref(OBJECT(po));
        // error_report("Setup failed for plugin %s\n", this->plugin_path);
        return NULL;
    }

    if( po_class->set_callbacks ) {
        po_class->set_callbacks(po, &(po->cb));
    }

    qemu_opts_del(plugin_options);

    return po;
}

// ****************************************************** //
// **********       Plugin Class Setup        ********** //
// **************************************************** //

static void plugin_initfn(Object *obj)
{
    Plugin *p = PLUGIN(obj);
    p->dl_handle = NULL;
    p->options = NULL;
    p->commands = NULL;
    p->loader_pattern = NULL;
    p->loader_type = NULL;
}

static void plugin_finalize(Object *obj)
{
    Plugin *p = PLUGIN(obj);
    
    // Close the plugin
    if (p->dl_handle)
    {
        dlclose(p->dl_handle);
        p->dl_handle = NULL;
    }

    p->options = NULL;
    p->commands = NULL;
    p->loader_pattern = NULL;
    p->loader_type = NULL;
}

static void plugin_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    // We'll set the functions that won't change here.
    // Some functions will be loaded when the plugin is open.
    PluginClass *p_klass = PLUGIN_CLASS(klass);
    p_klass->path_equals = plugin_path_equals;
    p_klass->name_equals = plugin_name_equals;
    p_klass->load_plugin = plugin_load_plugin;
    p_klass->create_instance = plugin_create_instance;
}

static const TypeInfo plugin_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_PLUGIN,
    .instance_size = sizeof(Plugin),
    .instance_init = plugin_initfn,
    .instance_finalize = plugin_finalize,
    .class_init = plugin_class_init,
    .class_size = sizeof(PluginClass)
};

static void plugin_register_types(void)
{
    type_register_static(&plugin_info);
}

type_init(plugin_register_types);

// ******************************************************** //
// **********       Plugin Class Helpers         ********* //
// ****************************************************** //

Plugin *plugin_create(const char *name, const char *file_path)
{
    Plugin *p = PLUGIN(object_new(TYPE_PLUGIN));
    PluginClass *p_class = PLUGIN_GET_CLASS(p);

    // Set the path and name
    snprintf(p->plugin_name, MAX_PLUGIN_NAME, "%s", name);
    snprintf(p->plugin_path, PATH_MAX, "%s", file_path);

    // Perform the dynamic loading here
    if (!p_class->load_plugin(p))
    {
        // Failed setup, so deallocate it.
        object_unref(OBJECT(p));
        return NULL;
    }

    return p;
}

Plugin *plugin_create_extended(Plugin *base, const char *name, const char *file_path)
{
    Plugin *p = PLUGIN(object_new(TYPE_PLUGIN));

    // Set the path and name
    snprintf(p->plugin_name, MAX_PLUGIN_NAME, "%s", name);
    snprintf(p->plugin_path, PATH_MAX, "%s", file_path);

    // Copy over the dynamic and type information
    p->type_info = *base->loader_type;
    p->dl_handle = base->dl_handle;
    p->options = base->options;
    p->commands = base->commands;

    // Change the plugin type and register the extended type
    p->type_info.name = p->plugin_name;
    type_register_static(&p->type_info);

    return p;
}

void qemu_plugin_register_type(void *opaque, TypeInfo *plugin_type)
{
    Plugin *p = PLUGIN(OBJECT(opaque));
    p->type_info = *plugin_type;
    type_register_static(&p->type_info);
}

void qemu_plugin_register_options(void *opaque, QemuOptsList *opts)
{
    Plugin *p = PLUGIN(OBJECT(opaque));
    p->options = opts;
}

void qemu_plugin_register_commands(void *opaque, QemuOptsList *commands)
{
    Plugin *p = PLUGIN(OBJECT(opaque));
    p->commands = commands;
}

void qemu_plugin_register_loader(void *opaque, const char *pattern, TypeInfo *plugin_subtype)
{
    Plugin *p = PLUGIN(OBJECT(opaque));
    p->loader_pattern = pattern;
    p->loader_type = plugin_subtype;
}

PluginObject *qemu_plugin_find_plugin(const char *name)
{
    PluginInstanceList *pil;
    PLUGIN_FOREACH(pil) {
        PluginObject *plugin = pil->instance;
        if(!strcmp(object_get_typename(OBJECT(plugin)), name)){
            return plugin;
        }
    }

    return NULL;
}
