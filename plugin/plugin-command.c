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


#include "qemu/osdep.h"
#include "qemu-common.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "chardev/char-io.h"
#include "chardev/char-mux.h"

#include "plugin/plugin_mgr.h"
#include "plugin/plugin-command.h"
#include "plugin/plugin-object.h"
#include "plugin/cli_cb.h"
#include "plugin/qemu-vm.h"

static PluginCommand *global_pc = NULL;

PluginCommand *plugin_command_get_instance(void)
{
    return global_pc;
}

static void command_dispatch(PluginObject *ns, const char *cmd, const char *args)
{
    bool handled = false;
    if(ns){
        if(ns->cb.on_command){
            handled = ns->cb.on_command(ns, cmd, args);
        }
    }else{
        CommandItem *result;

        // Look for a specific handler...
        QTAILQ_FOREACH(result, &global_pc->cmd_list, next)
        {
            if(!strcmp(result->name, cmd) && result->cmd_handler){
                handled = result->cmd_handler(result->opaque, cmd, args);
            }

            if(handled){
                break;
            }
        }
    }

    // Nothing handled this command so just broadcast it to plugins...
    if(!handled){
        handled = notify_command(cmd, args);
    }

    if(!handled){
        qemu_command_printf("Failed to find handler for %s\n", cmd);
    }
}

static void command_puts(const char *str)
{
    puts(str);
}

static void command_vprintf(const char *fmt, va_list ap)
{
    char *buf = g_strdup_vprintf(fmt, ap);
    command_puts(buf);
    g_free(buf);
}

static void command_printf(void *opaque, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    command_vprintf(fmt, ap);
    va_end(ap);
}

void qemu_command_set_printf(void *opaque, void(*p)(void *opaque, const char *fmt, ...))
{
    global_pc->printf_obj = opaque;
    global_pc->printf = p;
}

void qemu_command_set_pretty_printf(void *opaque, void(*p)(void *opaque, const char *fmt, ...))
{
    global_pc->pretty_printf_obj = opaque;
    global_pc->pretty_printf = p;
}

static bool command_exit_to_monitor(void *opaque, const char *cmd, const char *args)
{
    plugin_command_detach_monitor();
    return true;
}

static bool command_help_listing(void *opaque, const char *cmd, const char *args)
{
    CommandItem *result;

    qemu_command_printf("Command\tProvider\tDescription\n");
    QTAILQ_FOREACH(result, &global_pc->cmd_list, next)
    {
        const char *provider = "builtin";
        if(result->opaque){
            provider = object_get_typename(OBJECT(result->opaque));
        }
        qemu_command_printf("%s\t%s\t%s\n", result->name, provider, result->desc);
    }
    qemu_command_printf("\n");

    return true;
}

static bool command_quit_qemu(void *opaque, const char *cmd, const char *args)
{
    qemu_vm_quit();

    return true;
}

void qemu_command_add(void *opaque, const char *cmd, const char *desc, bool (*handler)(void *opaque, const char *cmd, const char *args))
{
    if(!global_pc)
    {
        return;
    }

    CommandItem *c = g_new0(CommandItem, 1);
    c->opaque = opaque;
    c->name = cmd;
    c->desc = desc;
    c->cmd_handler = handler;

    QTAILQ_INSERT_HEAD(&global_pc->cmd_list, c, next);
}

void qemu_command_remove(void *opaque, const char *cmd)
{
    CommandItem *entry;
    CommandItem *next_entry;

    if(!global_pc)
    {
        return;
    }

    QTAILQ_FOREACH_SAFE(entry, &global_pc->cmd_list, next, next_entry) {
        if(entry->opaque == opaque && !strcmp(cmd, entry->name))
        {
            QTAILQ_REMOVE(&global_pc->cmd_list, entry, next);
            g_free(entry);
        }
    }
}

void qemu_command_send(const char *cmdline)
{
    const char *cmd_begin;
    PluginObject *po = NULL;

    cmd_begin = strchr(cmdline, '.');
    if( cmd_begin ){
        PluginInstanceList *pil;
        int array_num = 0;
        int array_cur = 0;
        char *obj_ns = g_strndup(cmdline, cmd_begin-cmdline);
        char *lbracket = strchr(obj_ns,'[');
        if(lbracket)
        {
            char *elem = lbracket + 1;
            char *rbracket = strchr(elem,']');
            if(rbracket)
            {
                *lbracket = '\0';
                *rbracket = '\0';
                array_num = strtoull(elem, NULL, 10);
            }
        }

        PLUGIN_FOREACH(pil) {
            PluginObject *plugin = pil->instance;
            if(object_dynamic_cast(OBJECT(plugin), obj_ns)){
                if(array_cur == array_num){
                    po = plugin;
                    break;
                }
                array_cur++;
            }

        }

        if(!po){
            qemu_command_printf("Failed to find provider %s at %d\n", obj_ns, array_num);
            g_free(obj_ns);
            return;
        }

        g_free(obj_ns);

        cmd_begin++;
    }else{
        cmd_begin = cmdline;
    }

    char *cmd = g_strdup(cmd_begin);
    char *cmd_end = strchr(cmd, ' ');
    char *args = NULL;

    if( !cmd_end ){
        cmd_end = strchr(cmd, '\t');
    }

    if( cmd_end ){
        *cmd_end = '\0';
        args = cmd_end + 1;
    }

    command_dispatch(po, cmd, args);

    g_free(cmd);
}

void plugin_command_init(void)
{
    if(!global_pc)
    {
        global_pc = g_malloc0(sizeof(PluginCommand));
        QTAILQ_INIT(&global_pc->cmd_list);
        qemu_command_set_printf(NULL, command_printf);
        qemu_command_set_pretty_printf(NULL, command_printf);

        // Register global help
        qemu_command_add(NULL, "quit", "Shutdown and quit this QEMU session.", command_quit_qemu);
        qemu_command_add(NULL, "help", "Display this help listing.", command_help_listing);
    }
}

void plugin_command_attach_monitor(Monitor *mon)
{
    if(global_pc && mon)
    {
        qemu_command_set_printf(mon, (COMMAND_PRINTF)monitor_printf);
        qemu_command_set_pretty_printf(mon, (COMMAND_PRINTF)monitor_printf);
        qemu_command_add(NULL, "exit", "Exit debug and go back to monitor.", command_exit_to_monitor);
        monitor_redirect_handler(mon, qemu_command_send);
        global_pc->monitor = mon;
    }
}

void plugin_command_detach_monitor(void)
{
    if(global_pc && global_pc->monitor)
    {
        qemu_command_remove(NULL, "exit");
        monitor_redirect_handler(global_pc->monitor, NULL);
        global_pc->monitor = NULL;
    }
}

void plugin_command_destroy(void)
{
    if(global_pc)
    {
        if(global_pc->monitor){
            plugin_command_detach_monitor();
        }
        g_free(global_pc);
        global_pc = NULL;
    }
}