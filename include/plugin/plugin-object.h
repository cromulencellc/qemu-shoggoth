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

#ifndef __PLUGIN_OBJECT_H__
#define __PLUGIN_OBJECT_H__

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/object.h"
#include "racomms/interface.h"
#include "racomms/racomms-types.h"
#include "qapi/qapi-types-run-state.h"

// ****************************************************** //
// **********       Plugin Class Setup        ********** //
// **************************************************** //

#define TYPE_PLUGIN_OBJECT "PluginObject"
#define PLUGIN_OBJECT(obj)                                    \
    OBJECT_CHECK(PluginObject, (obj), TYPE_PLUGIN_OBJECT)
#define PLUGIN_OBJECT_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(PluginObjectClass, klass, TYPE_PLUGIN_OBJECT)
#define PLUGIN_OBJECT_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(PluginObjectClass, obj, TYPE_PLUGIN_OBJECT)

typedef struct PluginObject PluginObject;
typedef struct PluginObjectClass PluginObjectClass;
typedef struct PluginCallbacks PluginCallbacks;

struct PluginCallbacks {
    /**
     * Alerts the plugin to VM state changes.
     *
     * @param opaque "This" pointer to the state 
     * @param running Determines if the VM is running
     * @param state The current state of the VM
     */
    void (*change_state_handler)(void *opaque, int running, RunState state);

    /**
     * Gets the information required to request a report from
     * the RA system. This comes in the form of a bitmask.
     *
     * @param opaque "This" pointer to the state 
     * @return The bitmask that contains requested information from RA
     */
    JOB_REPORT_TYPE (*get_ra_report_type)(void *opaque);
    
    /**
     * Alerts the plugin to memory reads. Called after read occurs.
     *
     * @param opaque "This" pointer to the state 
     * @param paddr Physical address in guest memory
     * @param vaddr Virtual address in guest memory
     * @param value Value from read (host endianess)
     * @param addr Address in host memory (if one...)
     * @param size Size of read access
     */
    void (*on_memory_read)(void *opaque, uint64_t paddr, uint64_t vaddr, uint8_t *value, void *addr, int size);

    /**
     * Alerts the plugin to memory writes. Called before write occurs.
     *
     * @param opaque "This" pointer to the state 
     * @param paddr Physical address in guest memory
     * @param vaddr Virtual address in guest memory
     * @param value Value to write (host endianess)
     * @param addr Address in host memory (if one...)
     * @param size Size of write access
     */    
    void (*on_memory_write)(void *opaque, uint64_t paddr, uint64_t vaddr, const uint8_t *value, void *addr, int size);
    
    /**
     * This callback is executed when the RA system has started. Add an
     * implementation for this callback if monitoring of started RA system
     * is desired. work will be freed after the call back returns, if
     * data from it is required to be persistent, it should be copied. 
     *
     * @param opaque "This" pointer to the state
     * @param work The configuration of this analysis sesstion
     */
    void (*on_ra_start)(void *opaque, CommsWorkItem *work);
    
    /**
     * This callback is executed when the RA system is stopped. Add an
     * implementation for this callback if monitoring of stopped RA system
     * is desired. work_results will be freed after the call back returns, if
     * data from it is required to be persistent, it should be copied.
     *
     * @param opaque "This" pointer to the state
     * @param work_results The report on the current analysis session
     */
    void (*on_ra_stop)(void *opaque, CommsResultsItem *work_results);
    
    /**
     * This callback is executed when the RA system is idle. Add an
     * implementation for this callback if monitoring of idle RA system
     * is desired.
     *
     * @param opaque "This" pointer to the state
     */
    void (*on_ra_idle)(void *opaque);
    
    /**
     * This callback is executed when there is an interrupt.
     *
     * @param opaque "This" pointer to the state
     * @param mask The mask the gives interrupt state.
     */
    void (*on_interrupt)(void *opaque, int mask);
    
    /**
     * This callback is executed when there is an exception
     *
     * @param plugin "This" pointer to plugin state
     * @param exception The exception index
     */
    void (*on_exception)(void *opaque, int32_t exception);

    /**
     * This callback is executed when a syscall occours.
     *
     * @param plugin "This" pointer to plugin state
     * @param number The number of args being passed in.
     * @param ... The argument values passed to the syscall
     */
    void (*on_syscall)(void *opaque, uint64_t number, va_list args);

    /**
     * This callback is executed when a syscall exits.
     *
     * @param plugin "This" pointer to plugin state
     * @param number The number of args being passed in.
     * @param ... The argument values upon syscall exit
     */
    void (*on_syscall_exit)(void *opaque, uint64_t number, va_list args);

    /**
     * This callback is executed when a registered command is issued from the CLI.
     *
     * @param plugin "This" pointer to plugin state
     * @param cmd String for command
     * @param args String of arguments for command
     */
    bool (*on_command)(void *opaque, const char *cmd,  const char *args);

    /**
     * This callback is executed when the CPU hits a breakpoint.
     *
     * @param plugin "This" pointer to plugin state
     * @param cpu_idx The index of the cpu that hit the breakpoint
     * @param vaddr The address of the current breakpoint
     * @param bp_id The breakpoint ID
     */
    void (*on_breakpoint)(void *opaque, int cpu_idx, uint64_t vaddr, int bp_id);

    /**
     * This callback is executed when an instruction is executed.
     *
     * @param plugin "This" pointer to plugin state
     * @param vaddr The address of the instruction
     * @param addr The segment of code
     */
    void (*on_execute_instruction)(void *opaque, uint64_t vaddr, void *addr);

    /**
     * This callback is executed when a packet is received from an external interface.
     *
     * @param plugin "This" pointer to plugin state
     * @param pkt_buf The address of the packet buffer
     * @param pkt_size The size of the packet
     */
    void (*on_packet_recv)(void *opaque, uint8_t **pkt_buf, uint32_t *pkt_size);

    /**
     * This callback is executed when a packet is sent to an external interface.
     *
     * @param plugin "This" pointer to plugin state
     * @param pkt_buf The address of the packet buffer
     * @param pkt_size The size of the packet
     */
    void (*on_packet_send)(void *opaque, uint8_t **pkt_buf, uint32_t *pkt_size);

    /**
     * This callback is executed when the VM is ready to start.
     *
     * @param plugin "This" pointer to plugin state
     */
    void (*on_vm_startup)(void *opaque);

    /**
     * This callback is executed when the VM exits.
     *
     * @param plugin "This" pointer to plugin state
     */
    void (*on_vm_shutdown)(void *opaque);
};

struct PluginObject {
    Object obj;
    PluginCallbacks cb;
    const char *args;
};

struct PluginObjectClass {
    ObjectClass parent;
    bool (*init_plugin)(void *opaque, const char *path, QemuOpts *opts);
    void (*set_callbacks)(void *opaque, PluginCallbacks *opts);
    const char *(*get_args)(void *opaque);
};

// ******************************************************** //
// **********       Plugin Class Helpers         ********* //
// ****************************************************** //

PluginObject *plugin_object_create(const char *obj_name, const char *args);

#endif
