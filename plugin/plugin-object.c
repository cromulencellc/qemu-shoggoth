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

#include "plugin/plugin-object.h"

#include <stdlib.h>

// ****************************************************** //
// **********       Plugin Class Setup        ********** //
// **************************************************** //

static const char *plugin_object_get_args(void *opaque)
{
    PluginObject *p = PLUGIN_OBJECT(opaque);
    return p->args;
}

static void plugin_object_initfn(Object *obj)
{
    PluginObject *p = PLUGIN_OBJECT(obj);
    p->args = NULL;
    p->cb.change_state_handler = NULL;
    p->cb.get_ra_report_type = NULL;
    p->cb.on_memory_read = NULL;
    p->cb.on_memory_write = NULL;
    p->cb.on_ra_start = NULL;
    p->cb.on_ra_stop = NULL;
    p->cb.on_ra_idle = NULL;
    p->cb.on_interrupt = NULL;
    p->cb.on_exception = NULL;
    p->cb.on_syscall = NULL;
    p->cb.on_syscall_exit = NULL;
    p->cb.on_command = NULL;
    p->cb.on_breakpoint = NULL;
    p->cb.on_execute_instruction = NULL;
    p->cb.on_packet_recv = NULL;
    p->cb.on_packet_send = NULL;
    p->cb.on_vm_startup = NULL;
    p->cb.on_vm_shutdown = NULL;
}

static void plugin_object_finalize(Object *obj)
{
}

static void plugin_object_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->get_args = plugin_object_get_args;
    p_klass->init_plugin = NULL;
    p_klass->set_callbacks = NULL;
}

static const TypeInfo plugin_object_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_PLUGIN_OBJECT,
    .instance_size = sizeof(PluginObject),
    .instance_init = plugin_object_initfn,
    .instance_finalize = plugin_object_finalize,
    .class_init = plugin_object_class_init,
    .class_size = sizeof(PluginObjectClass)
};

static void plugin_object_register_types(void)
{
    type_register_static(&plugin_object_info);
}

type_init(plugin_object_register_types);


// ******************************************************** //
// **********       Plugin Class Helpers         ********* //
// ****************************************************** //

PluginObject *plugin_object_create(const char *obj_name, const char *args)
{
    PluginObject *po = PLUGIN_OBJECT(object_new(obj_name));
    po->args = args;
    return po;
}
