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

// This is the interface to QEMU
#include "qemu/qemu-plugin.hpp"
#include "printer.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "plugin/plugin-object.h"

#ifdef __cplusplus
}
#endif

// These macros define object operations
#define TYPE_HELLO_CPP "HELLO_CPP"
#define HELLO_CPP(obj)                                    \
    OBJECT_CHECK(HelloCPP, (obj), TYPE_HELLO_CPP)
#define HELLO_CPP_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(HelloCPPClass, klass, TYPE_HELLO_CPP)
#define HELLO_CPP_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(HelloCPPClass, obj, TYPE_HELLO_CPP)

// This is for opts
#define HELLO_CPP_OPTS  ("hello-cpp")

// Object type data
typedef struct HelloCPP HelloCPP;
typedef struct HelloCPPClass HelloCPPClass;

struct HelloCPP 
{
    PluginObject obj;
    char message[256];
    printer *p;
};

struct HelloCPPClass
{
    PluginObjectClass parent;
    void (*print_message)(HelloCPP *self, const char *dest);
};

// Object setup: Object info
static TypeInfo hello_cpp_info;

/**
 * These are the call back functions that QEMU will use to 
 * talk to the plugins. It is not required to implement all
 * of them; QEMU should be smart in calling only the set 
 * callbacks. For more information on these functions and
 * how the behave, see qemu/qemu-plugin.h. There is 
 * documentation on each function that is currently implemented.
 */
static void hello_cpp_on_ra_start(void *opaque, CommsWorkItem* work)
{
    HelloCPP *h = HELLO_CPP(opaque);
    HelloCPPClass *h_klass = HELLO_CPP_GET_CLASS(h);
    h_klass->print_message(h, "hello_on_ra_start\n");
}

static void hello_cpp_on_packet_send(void *opaque, uint8_t**packet, uint32_t *size)
{
    HelloCPP *h = HELLO_CPP(opaque);
    HelloCPPClass *h_klass = HELLO_CPP_GET_CLASS(h);
    h_klass->print_message(h, "hello_cpp_on_packet_send\n");
}

static void hello_cpp_on_packet_recv(void *opaque, uint8_t**packet, uint32_t *size)
{
    HelloCPP *h = HELLO_CPP(opaque);
    HelloCPPClass *h_klass = HELLO_CPP_GET_CLASS(h);
    h_klass->print_message(h, "hello_cpp_on_packet_recv\n");
}

static bool hello_cpp_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    printf("Plugin init for hello-cpp\n");
    HelloCPP *h = HELLO_CPP(opaque);
    snprintf(h->message, sizeof(h->message) -1, "%s", qemu_opt_get(opts, "message"));
    return true;
}

static void hello_cpp_set_callbacks(void *opaque, PluginCallbacks *cb)
{
    cb->on_ra_start = hello_cpp_on_ra_start;
    cb->on_packet_send = hello_cpp_on_packet_send;
    cb->on_packet_recv = hello_cpp_on_packet_recv;
}

// class functions
static void hello_cpp_print_message(HelloCPP *self, const char *dest)
{
    char msg[1000];
    snprintf(msg, sizeof(msg), "%s from %s\n", self->message, dest);
    self->p->do_print(msg);   
}

// Object setup: constructor
static void hello_cpp_initfn(Object *obj)
{
    HelloCPP *h = HELLO_CPP(obj);
    memset(h->message, 0x00, sizeof(h->message));
    h->p = new printer();
}

// Object setup: destructor
static void hello_cpp_finalize(Object *obj)
{
    HelloCPP *h = HELLO_CPP(obj);
    memset(h->message, 0x00, sizeof(h->message));
    delete h->p;
}

// Object setup: class constructor 
static void hello_cpp_class_init(ObjectClass *klass,
                                 void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->init_plugin = hello_cpp_init_plugin;
    p_klass->set_callbacks = hello_cpp_set_callbacks;

    HelloCPPClass *h_klass = HELLO_CPP_CLASS(klass);
    h_klass->print_message = hello_cpp_print_message;
}
static QemuOptDesc qemu_hello_cpp_desc[2] = {
         {"message", QEMU_OPT_STRING, "Provides information needed to load a plugin", NULL},
         { /* end of list */ }
};

// Setup options to configure the plugin
static QemuOptsList qemu_hello_cpp_opts = {
    HELLO_CPP_OPTS,
    "message",
    false,
    QTAILQ_HEAD_INITIALIZER(qemu_hello_cpp_opts.head)
};

// These functions are required to setup the plugins
bool plugin_setup(void *plugin, const char *path)
{
    hello_cpp_info.parent = TYPE_PLUGIN_OBJECT;
    hello_cpp_info.name = TYPE_HELLO_CPP;
    hello_cpp_info.instance_size = sizeof(HelloCPP);
    hello_cpp_info.instance_init = hello_cpp_initfn;
    hello_cpp_info.instance_finalize = hello_cpp_finalize;
    hello_cpp_info.class_init = hello_cpp_class_init;
    hello_cpp_info.class_size = sizeof(HelloCPPClass);
    
    // Sorry, I'll add a proper C++ interface soon.
    char *opts_list = (char *) malloc(sizeof(qemu_hello_cpp_opts) + sizeof(qemu_hello_cpp_desc));
    memcpy(opts_list, &qemu_hello_cpp_opts, sizeof(qemu_hello_cpp_opts));
    memcpy(opts_list+sizeof(qemu_hello_cpp_opts), qemu_hello_cpp_desc, sizeof(qemu_hello_cpp_desc));

    qemu_plugin_register_type(plugin, &hello_cpp_info);
    qemu_plugin_register_options(plugin, reinterpret_cast<QemuOptsList*>(opts_list));

    return true;
}
