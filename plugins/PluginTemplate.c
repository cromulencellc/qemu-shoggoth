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
 *  Change Me <changeme@email.com>
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
#define TYPE_${NAME} "${name}"
#define ${NAME}(obj)                                    \
    OBJECT_CHECK(${Name}, (obj), TYPE_${NAME})
#define ${NAME}_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(${Name}Class, klass, TYPE_${NAME})
#define ${NAME}_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(${Name}Class, obj, TYPE_${NAME})

// This is for opts
#define ${NAME}_OPTS  ("${name}-opts")

// Object type data
typedef struct ${Name} ${Name};
typedef struct ${Name}Class ${Name}Class;

struct ${Name}
{
    PluginObject obj;
};

struct ${Name}Class
{
    PluginObjectClass parent;
};

// Object setup: constructor
static void ${name}_initfn(Object *obj)
{
    ${Name} *h = ${NAME}(obj);
    (void) h;
}

// Object setup: destructor
static void ${name}_finalize(Object *obj)
{
    ${Name} *h = ${NAME}(obj);
    (void) h;
}

## option to add callbacks to skeleton
% if callback:
    % if 'memory_read' in callback:

static void ${name}_on_memory_read(void *opaque, uint64_t paddr, uint64_t vaddr, uint8_t *value, void *addr, int size)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}

    % endif
    % if 'memory_write' in callback:

static void ${name}_on_memory_write(void *opaque, uint64_t paddr, uint64_t vaddr, const uint8_t *value, void *addr, int size)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    
    % endif
    % if 'state_change' in callback:

static void ${name}_on_state_change(void *opaque, int running, RunState state)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    
    % endif
    % if 'ra_start' in callback:

static void ${name}_on_ra_start(void *opaque, CommsWorkItem* work) 
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    
    % endif
    % if 'ra_stop' in callback:

static void ${name}_on_ra_stop(void *opaque, CommsResultsItem *work)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    
    % endif
    % if 'ra_idle' in callback:

static void ${name}_on_ra_idle(void *opaque)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    
    % endif
    % if 'interrupt' in callback:

static void ${name}_on_interrupt(void *opaque, int mask)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    
    % endif
    % if 'exception' in callback:
    
static void ${name}_on_exception(void *opaque, int32_t exception)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    
    % endif
    % if 'syscall' in callback:

static void ${name}_on_syscall(void *opaque, uint64_t number, va_list args) 
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}

    % endif
    % if 'command' in callback:

static bool ${name}_on_command(void *opaque, const char *cmd, const char *args)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
    return false;
}
    % endif
    % if 'breakpoint' in callback:

static void ${name}_on_breakpoint(void *opaque, int cpu_idx, uint64_t vaddr, int bp_id)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    % endif
    % if 'syscall_exit' in callback:

static void ${name}_on_syscall_exit(void *opaque, uint64_t number, va_list args)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    % endif
    % if 'instructions' in callback:

static void ${name}_on_execute_instruction(void *opaque, uint64_t vaddr, void *addr)
{
    ${Name} *h = ${NAME}(opaque);
    ${Name}Class *h_klass = ${NAME}_GET_CLASS(h);
    (void) h_klass;
}
    % endif
% endif

static bool ${name}_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    ${Name} *h = ${NAME}(opaque);
    (void) h;
    return true;
}

static void ${name}_set_callbacks(void *opaque, PluginCallbacks *callbacks)
{
    ## add callbacks
    % for func in callback:
    % if 'state_change' == func:
    callbacks->change_state_handler = ${name}_on_state_change;
    % elif 'instructions' == func:
    callbacks->on_execute_instruction = ${name}_on_execute_instruction;
    % else:
    callbacks->on_${func} = ${name}_on_${func};
    % endif
    % endfor
}

// Object setup: class constructor 
static void ${name}_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->init_plugin = ${name}_init_plugin;
    p_klass->set_callbacks = ${name}_set_callbacks;

    ${Name}Class *h_klass = ${NAME}_CLASS(klass);
    (void) h_klass;
}

// Object setup: Object info
static TypeInfo ${name}_info = {
    .parent = TYPE_PLUGIN_OBJECT,
    .name = TYPE_${NAME},
    .instance_size = sizeof(${Name}),
    .instance_init = ${name}_initfn,
    .instance_finalize = ${name}_finalize,
    .class_init = ${name}_class_init,
    .class_size = sizeof(${Name}Class)
};

// Setup options to configure the plugin
static QemuOptsList qemu_${name}_opts = {
    .name = ${NAME}_OPTS,
    .implied_opt_name = "message",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_${name}_opts.head),
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
    qemu_plugin_register_type(plugin, &${name}_info);
    qemu_plugin_register_options(plugin, &qemu_${name}_opts);

    return true;
}
