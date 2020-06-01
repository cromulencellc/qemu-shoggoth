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

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "plugin/plugin_mgr.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/help_option.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "plugin/plugin-error.h"
#include "sysemu/sysemu.h"
#include <fnmatch.h>
#include "ra.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

#define PLUGIN_OPTS  ("plugin-opts")

// Forward declare some prototypes
bool is_memread_instrumentation_enabled(void);
bool is_memwrite_instrumentation_enabled(void);
bool is_exec_instrumentation_enabled(void);
bool is_syscall_instrumentation_enabled(void);
bool is_syscall_exit_instrumentation_enabled(void);
bool is_interrupt_instrumentation_enabled(void);
bool is_recvpacket_instrumentation_enabled(void);
bool is_sendpacket_instrumentation_enabled(void);
bool is_vm_startup_instrumentation_enabled(void);
bool is_vm_shutdown_instrumentation_enabled(void);
bool is_ra_stop_instrumentation_enabled(void);

static bool memread_instrumentation_enabled = false;
static bool memwrite_instrumentation_enabled = false;
static bool exec_instrumentation_enabled = false;
static bool syscall_instrumentation_enabled = false;
static bool syscall_exit_instrumentation_enabled = false;
static bool interrupt_instrumentation_enabled = false;
static bool packetrecv_instrumentation_enabled = false;
static bool packetsend_instrumentation_enabled = false;
static bool vm_startup_instrumentation_enabled = false;
static bool vm_shutdown_instrumentation_enabled = false;
static bool ra_stop_instrumentation_enabled = false;

Plugins plugin_list;
PluginInstances plugin_instance_list;

QemuOptsList qemu_plugin_opts = {
    .name = PLUGIN_OPTS,
    .implied_opt_name = "module",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_plugin_opts.head),
    .desc = { 
        {
            .name = "module",
            .type = QEMU_OPT_STRING,
            .help = "Provides information needed to load a plugin",
        },{
            .name = "arg",
            .type = QEMU_OPT_STRING,
            .help = "Provides arguments to the plugin",
        },
        { /* end of list */ }
    },
};

static void probe_plugin_dir(const char *plugin_dir)
{
    char plugin_path[PATH_MAX] = {};
    // Get information about the plugin directory
    struct dirent *entry;
    DIR *dir = opendir(plugin_dir);
    // Exists or permission issues?
    if (dir)
    {
        // Search the directory
        while ((entry = readdir(dir)) != NULL) 
        {
            char *file_ext = strrchr(entry->d_name,'.');
            // Make sure that we're only looking for supported types.
            if( file_ext && !strcmp(file_ext, ".so") )
            {
                // Build plugin file list.
                snprintf(plugin_path, sizeof(plugin_path), "%s/%s", plugin_dir, entry->d_name);
                char *name = strtok(entry->d_name, ".");

                // Load the plugin and init the types, options, commands, etc...
                Plugin *p = plugin_create(name, plugin_path);
                if(p)
                {
                    // Add the plugin to the plugin list 
                    PluginList *pl = g_new(PluginList, 1);
                    pl->plugin = p;
                    QLIST_INSERT_HEAD(&plugin_list, pl, next);
                }
            }
        }
        // Close the directory
        closedir(dir);
    }
}

static void probe_extended_plugin_dir(const char *plugin_dir)
{
    // Loop through our plugin nodes and find the
    // ones that offer a loader for extended plugins.
    PluginList *p = NULL;
    QLIST_FOREACH(p, &plugin_list, next)
    {
        Plugin *plugin = p->plugin;
        // Does this plugin extend the plugin system?
        if (plugin->loader_pattern && plugin->loader_type)
        {
            // Get information about the plugin directory
            char plugin_path[PATH_MAX] = {};
            struct dirent *entry;
            DIR *dir = opendir(plugin_dir);
            // Exists or permission issues?
            if (dir)
            {
                // Search the directory
                while ((entry = readdir(dir)) != NULL)
                {
                    // Make sure that we're only looking for supported types.
                    if ( !fnmatch(plugin->loader_pattern, entry->d_name, FNM_EXTMATCH) )
                    {
                        // Build plugin file list.
                        snprintf(plugin_path, sizeof(plugin_path), "%s/%s", plugin_dir, entry->d_name);
                        char *name = strtok(entry->d_name, ".");

                        // Create a plugin
                        Plugin *xp = plugin_create_extended(plugin, name, plugin_path);
                        if(xp)
                        {
                            // Add the plugin type to the plugin list
                            PluginList *pl = g_new(PluginList, 1);
                            pl->plugin = xp;
                            QLIST_INSERT_AFTER(p, pl, next);
                        }
                    }
                }
                // Close the directory
                closedir(dir);
            }
        }
    }
}

static void build_plugin_dir_contents(void)
{
    // We'll need path information
    const char plugin_path[] = "/plugins";
    char cwd[PATH_MAX] = {};
    char plugin_dir[PATH_MAX+sizeof(plugin_path)] = {};

    // Search the directory from the env var for plugins.
    const char *env_plugin_dir = getenv( "QEMU_PLUGIN_DIR" );
    if (env_plugin_dir != NULL) {
        probe_plugin_dir(env_plugin_dir);
    }

    // Search the directory configured with "plugin-dir"
    probe_plugin_dir(CONFIG_QEMU_PLUGINDIR);

    // And search the current directory
    if (getcwd(cwd, sizeof(cwd)) != NULL)
    {
        // We want to use the plugins subdirectory from our current directory
        struct stat info;
        snprintf(plugin_dir, sizeof(plugin_dir), "%s%s", cwd, plugin_path);
        if(stat( plugin_dir, &info ) == 0 && (info.st_mode & S_IFDIR))
        {
            probe_plugin_dir(plugin_dir);
            probe_extended_plugin_dir(plugin_dir);
        }
    }

    // Finally search for extended plugins.
    probe_extended_plugin_dir(CONFIG_QEMU_PLUGINDIR);

    if (env_plugin_dir != NULL) {
        probe_extended_plugin_dir(env_plugin_dir);
    }
}

void plugin_init_globals(void)
{
    QLIST_INIT(&plugin_list);
    QLIST_INIT(&plugin_instance_list);
    build_plugin_dir_contents();
    qemu_plugin_last_error = NULL;
}

void plugin_init_plugins(void)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Instantiate the plugins and register plugins
        PluginObject *pi = p->instance;
        PluginCallbacks *cb = &(pi->cb);
        if (cb)
        {
            // Check if certains callbacks are set. This allows us to speedup
            // execution and abstract the class callbacks away from QEMU code.
            memread_instrumentation_enabled |= cb->on_memory_read != NULL;
            memwrite_instrumentation_enabled |= cb->on_memory_write != NULL;
            exec_instrumentation_enabled |= cb->on_execute_instruction != NULL;
            syscall_instrumentation_enabled |= cb->on_syscall != NULL;
            syscall_exit_instrumentation_enabled |= cb->on_syscall_exit != NULL;
            interrupt_instrumentation_enabled |= cb->on_interrupt != NULL;
            packetrecv_instrumentation_enabled |= cb->on_packet_recv != NULL;
            packetsend_instrumentation_enabled |= cb->on_packet_send != NULL;
            vm_startup_instrumentation_enabled |= cb->on_vm_startup != NULL;
            vm_shutdown_instrumentation_enabled |= cb->on_vm_shutdown != NULL;
            ra_stop_instrumentation_enabled |= cb->on_ra_stop != NULL;

            if (cb->change_state_handler)
            {
                qemu_add_vm_change_state_handler(cb->change_state_handler, pi);
            }

            // If we ever need to dynamically toggle cpu instruction callbacks
            // then we'll need this to clear the cache of the generated TCG
            // with built-in callback code.
            // cpu_tb_jmp_cache_clear(cpu);
        }
    }
}

bool plugin_create_plugin(const char *optstr)
{
    // loop through our plugin nodes and find the
    // one we are attempting to configure
    PluginList *p = NULL;
    QLIST_FOREACH(p, &plugin_list, next)
    {
        // The names should match
        PluginClass *p_klass = PLUGIN_GET_CLASS(p->plugin);
        size_t offset = p_klass->name_equals(p->plugin, optstr);
        if (offset)
        {
            // Put the instance in a list so we can manage it
            PluginInstanceList *pil = g_new(PluginInstanceList, 1);
            pil->instance = p_klass->create_instance(p->plugin, &optstr[offset]);
            if( pil->instance )
            {
                QLIST_INSERT_HEAD(&plugin_instance_list, pil, next);
                return true;
            }

            g_free(pil);

            // error creating instance
            error_report("Could not create plugin instance!");
            return false;
        }
    }

    // not found
    error_report("Could not find plugin!");
    return false;
}

bool is_memread_instrumentation_enabled(void)
{
    return memread_instrumentation_enabled;
}

bool is_memwrite_instrumentation_enabled(void)
{
    return memwrite_instrumentation_enabled;
}

bool is_exec_instrumentation_enabled(void)
{
    return exec_instrumentation_enabled;
}

bool is_syscall_instrumentation_enabled(void)
{
    return syscall_instrumentation_enabled;
}

bool is_syscall_exit_instrumentation_enabled(void)
{
    return syscall_exit_instrumentation_enabled;
}

bool is_interrupt_instrumentation_enabled(void)
{
    return interrupt_instrumentation_enabled;
}

bool is_recvpacket_instrumentation_enabled(void)
{
    return packetrecv_instrumentation_enabled;
}

bool is_sendpacket_instrumentation_enabled(void)
{
    return packetsend_instrumentation_enabled;
}

bool is_vm_startup_instrumentation_enabled(void)
{
    return vm_startup_instrumentation_enabled;
}

bool is_vm_shutdown_instrumentation_enabled(void)
{
    return vm_shutdown_instrumentation_enabled;
}

bool is_ra_stop_instrumentation_enabled(void)
{
    return ra_stop_instrumentation_enabled;
}
