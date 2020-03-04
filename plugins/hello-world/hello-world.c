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
#include "plugin/plugin-object.h"
#include "qemu/qemu-plugin.h"

// These macros define object operations
#define TYPE_HELLO "Hello"
#define HELLO(obj)                                    \
    OBJECT_CHECK(Hello, (obj), TYPE_HELLO)
#define HELLO_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(HelloClass, klass, TYPE_HELLO)
#define HELLO_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(HelloClass, obj, TYPE_HELLO)

// This is for opts
#define HELLO_OPTS  ("hello")

// Object type data
typedef struct Hello Hello;
typedef struct HelloClass HelloClass;

struct Hello
{
    PluginObject obj;
    char message[256];
};

struct HelloClass
{
    PluginObjectClass parent;
    void (*print_message)(Hello *this, const char *dest);
};

// class functions
static void hello_print_message(Hello *this, const char *dest)
{
    char msg[1000];
    snprintf(msg, sizeof(msg), "%s from %s\n", this->message, dest);
    printf("C: %s\n", msg);
}

// Object setup: constructor
static void hello_initfn(Object *obj)
{
    Hello *h = HELLO(obj);
    memset(h->message, 0x00, sizeof(h->message));
}

// Object setup: destructor
static void hello_finalize(Object *obj)
{
    Hello *h = HELLO(obj);
    memset(h->message, 0x00, sizeof(h->message));
}

/**
 * These are the call back functions that QEMU will use to 
 * talk to the plugins. It is not required to implement all
 * of them; QEMU should be smart in calling only the set 
 * callbacks. For more information on these functions and
 * how the behave, see qemu/qemu-plugin.h. There is 
 * documentation on each function that is currently implemented.
 */

static JOB_REPORT_TYPE hello_get_ra_report_type(void *opaque)
{
    Hello *h = HELLO(opaque);
    HelloClass *h_klass = HELLO_GET_CLASS(h);
    h_klass->print_message(h, "hello_get_ra_report_type");

    JOB_REPORT_TYPE ret_val = JOB_REPORT_PROCESSOR;
    return ret_val;
}

static void hello_on_ra_start(void *opaque, CommsWorkItem* work) 
{
    Hello *h = HELLO(opaque);
    HelloClass *h_klass = HELLO_GET_CLASS(h);
    h_klass->print_message(h, "hello_on_ra_start");
}

static void hello_on_ra_stop(void *opaque, CommsResultsItem *work_results) 
{
    Hello *h = HELLO(opaque);
    HelloClass *h_klass = HELLO_GET_CLASS(h);
    h_klass->print_message(h, "hello_on_ra_stop");
}

static void hello_on_ra_idle(void *opaque) 
{
    Hello *h = HELLO(opaque);
    HelloClass *h_klass = HELLO_GET_CLASS(h);
    h_klass->print_message(h, "hello_on_ra_idle");
}

static bool hello_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    Hello *h = HELLO(opaque);
    snprintf(h->message, sizeof(h->message), "%s", qemu_opt_get(opts, "message"));
    return true;
}

static void hello_set_callbacks(void *opaque, PluginCallbacks *cb)
{
    cb->get_ra_report_type = hello_get_ra_report_type;
    //cb->on_memory_read = hello_on_memory_read;
    //cb->on_memory_write = hello_on_memory_write;
    //cb->on_vm_state_change = hello_on_vm_state_change;
    cb->on_ra_start = hello_on_ra_start;
    cb->on_ra_stop = hello_on_ra_stop;
    cb->on_ra_idle = hello_on_ra_idle;
    //cb->on_interrupt = hello_on_interrupt;
    //cb->on_exception = hello_on_exception;
    //cb->on_syscall = hello_on_syscall;
    //cb->on_command = hello_on_command;
}

// Object setup: class constructor 
static void hello_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->init_plugin = hello_init_plugin;
    p_klass->set_callbacks = hello_set_callbacks;

    HelloClass *h_klass = HELLO_CLASS(klass);
    h_klass->print_message = hello_print_message;
}

// Object setup: Object info
static TypeInfo hello_info = {
    .parent = TYPE_PLUGIN_OBJECT,
    .name = TYPE_HELLO,
    .instance_size = sizeof(Hello),
    .instance_init = hello_initfn,
    .instance_finalize = hello_finalize,
    .class_init = hello_class_init,
    .class_size = sizeof(HelloClass)
};

// Setup options to configure the plugin
static QemuOptsList qemu_hello_opts = {
    .name = HELLO_OPTS,
    .implied_opt_name = "message",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_hello_opts.head),
    .desc = { 
        {
            .name = "message",
            .type = QEMU_OPT_STRING,
            .help = "Provides information needed to load a plugin",
        },
        { /* end of list */ }
    },
};

// These functions are required to setup the plugins
bool plugin_setup(void *plugin, const char *path)
{
    qemu_plugin_register_type(plugin, &hello_info);
    qemu_plugin_register_options(plugin, &qemu_hello_opts);

    return true;
}
