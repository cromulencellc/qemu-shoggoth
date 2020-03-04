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

#include <stdio.h>

// This is the interface to QEMU
#include "qemu/qemu-plugin.h"
#include "plugin/plugin-object.h"
#include "qapi/error.h"
#include "monitor/monitor.h"
#include "example-qapi-commands.h"

// These macros define object operations
#define TYPE_QMPEXAMPLE "qmp-example"
#define QMPEXAMPLE(obj)                                    \
    OBJECT_CHECK(QMPExample, (obj), TYPE_QMPEXAMPLE)
#define QMPEXAMPLE_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(QMPExampleClass, klass, TYPE_QMPEXAMPLE)
#define QMPEXAMPLE_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(QMPExampleClass, obj, TYPE_QMPEXAMPLE)

// This is for opts
#define QMPEXAMPLE_OPTS  ("qmp-example-opts")

// Object type data
typedef struct QMPExample QMPExample;
typedef struct QMPExampleClass QMPExampleClass;

struct QMPExample 
{
    PluginObject obj;
};

struct QMPExampleClass
{
    PluginObjectClass parent;
};

void qmp_qmp_example(Error **errp)
{
	Error* local_err = NULL;

    error_setg(&local_err, "Error unimplemented sample command");

	error_propagate(errp, local_err);

	return;

}

// Object setup: constructor
static void hello_initfn(Object *obj)
{
}

// Object setup: destructor
static void hello_finalize(Object *obj)
{
}

static bool qmpexample_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    return true;
}

static void qmpexample_set_callbacks(void *opaque, PluginCallbacks *callbacks)
{
}

// Object setup: class constructor 
static void hello_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->init_plugin = qmpexample_init_plugin;
    p_klass->set_callbacks = qmpexample_set_callbacks;
}

// Object setup: Object info
static TypeInfo qmp_example_info = {
    .parent = TYPE_PLUGIN_OBJECT,
    .name = TYPE_QMPEXAMPLE,
    .instance_size = sizeof(QMPExample),
    .instance_init = hello_initfn,
    .instance_finalize = hello_finalize,
    .class_init = hello_class_init,
    .class_size = sizeof(QMPExampleClass)
};

// Setup options to configure the plugin
static QemuOptsList qmp_example_opts = {
    .name = QMPEXAMPLE_OPTS,
    .implied_opt_name = "message",
    .head = QTAILQ_HEAD_INITIALIZER(qmp_example_opts.head),
    .desc = { 
        {
            .name = "message",
            .type = QEMU_OPT_STRING,
            .help = "Provides information needed to load a plugin",
        },
        { /* end of list */ }
    },
};

/**
 * These are the call back functions that QEMU will use to 
 * talk to the plugins. It is not required to implement all
 * of them; QEMU should be smart in calling only the set 
 * callbacks. For more information on these functions and
 * how the behave, see qemu/qemu-plugin.h. There is 
 * documentation on each function that is currently implemented.
 */

//static void hello_on_memory_read(void *opaque) {}
//static void hello_on_memory_write(void *opaque) {}
//static void hello_on_vm_state_change(void *opaque) {}
//static void hello_on_interrupt(void *opaque) {}
//static void hello_on_exception(void *opaque) {}
//static void hello_on_syscall(void *opaque) {}
//static void hello_on_command(void *opaque) {}

// These functions are required to setup the plugins
bool plugin_setup(void *plugin, const char *path)
{
    qemu_plugin_register_type(plugin, &qmp_example_info);
    qemu_plugin_register_options(plugin, &qmp_example_opts);
    qmp_init_plugin_cmd(example_qmp_init_marshal);

    return true;
}
