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

#ifndef __PLUGIN_COMMAND_H__
#define __PLUGIN_COMMAND_H__

#include "qemu/osdep.h"
#include "monitor/monitor.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef void (*COMMAND_PRINTF)(void *opaque, const char *fmt, ...);

typedef struct CommandItem{
    void *opaque;
    const char *name;
    const char *desc;
    bool (*cmd_handler)(void *opaque, const char *cmd, const char *args);
    QTAILQ_ENTRY(CommandItem) next;
} CommandItem;

typedef struct PluginCommand{
    void *printf_obj;
    void *pretty_printf_obj;
    Monitor *monitor;
    QTAILQ_HEAD(,CommandItem) cmd_list;
    COMMAND_PRINTF pretty_printf;
    COMMAND_PRINTF printf;
} PluginCommand;

PluginCommand *plugin_command_get_instance(void);
void plugin_command_init(void);
void plugin_command_attach_monitor(Monitor *mon);
void plugin_command_detach_monitor(void);
void plugin_command_destroy(void);

#define qemu_command_printf(fmt, args...) \
    plugin_command_get_instance()->printf( \
        plugin_command_get_instance()->printf_obj, fmt, ##args)
#define qemu_command_pretty_printf(fmt, args...) \
    plugin_command_get_instance()->pretty_printf( \
        plugin_command_get_instance()->pretty_printf_obj, fmt, ##args)

void qemu_command_set_printf(void *opaque, void(*p)(void *opaque, const char *fmt, ...));
void qemu_command_set_pretty_printf(void *opaque, void(*p)(void *opaque, const char *fmt, ...));
void qemu_command_add(void *opaque, const char *cmd, const char *desc, bool (*handler)(void *opaque, const char *cmd, const char *args));
void qemu_command_remove(void *opaque, const char *cmd);
void qemu_command_send(const char *cmdline);

#ifdef __cplusplus
}
#endif

#endif