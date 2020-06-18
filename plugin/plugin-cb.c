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
#include "qemu-common.h"
#include "plugin/ra_cb.h"
#include "plugin/cpu_cb.h"
#include "plugin/net_cb.h"
#include "plugin/vm_cb.h"
#include "plugin/display_cb.h"
#include "plugin/cli_cb.h"
#include "plugin/plugin_mgr.h"
#include "migration/snapshot.h"
#include "cpu.h"
#include "exec/ram_addr.h"
#include "oshandler/oshandler.h"
#include "qapi/qmp/qpointer.h"
#include "sysemu/hw_accel.h"
#include "ui/console.h"
#include "ui/input.h"
#include "sysemu/sysemu.h"


void notify_ra_start(CommsWorkItem* work)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the on_ra_start callback is set
        if (p->instance->cb.on_ra_start)
        {
            // Call the plugin callback
            p->instance->cb.on_ra_start(p->instance, work);
        }
    }
}

void notify_ra_stop(CPUState *cpu, SHA1_HASH_TYPE job_hash)
{
    // Collect the current state of rapid analysis 
    RSaveTree *rst = rapid_analysis_get_instance(cpu);

    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Variable
        CommsResultsItem *work_results = NULL;
        
        // Check if the on_ra_stop callback is set
        if (p->instance->cb.on_ra_stop)
        {
            // Initialize request to something meaningful
            JOB_REPORT_TYPE request = rst->job_report_mask;

            // Get the mask for the work result
            if (p->instance->cb.get_ra_report_type)
            {
                // Instead use the report requested by the plugin.
                request = p->instance->cb.get_ra_report_type(p->instance);
            }

            // request a report
            CommsMessage *result_message = build_rsave_report(rst, job_hash, request, NULL);

            if (result_message)
            {
                // Put together the work results
                work_results = g_new(CommsResultsItem, 1);

                // Set the message field in the work result.
                work_results->msg = result_message;   

                // Call the plugin callback
                p->instance->cb.on_ra_stop(p->instance, work_results);

                // Free the pointers (not RST though)
                if (result_message) g_free(result_message);
                if (work_results) g_free(work_results);                    
            }
        }
    }
}

void notify_ra_idle(void)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the on_ra_stop callback is set
        if (p->instance->cb.on_ra_idle)
        {
            // Call the plugin callback
            p->instance->cb.on_ra_idle(p->instance);
        }
    }
}

void notify_exec_instruction(CPUState *cs, uint64_t vaddr)
{
    // Perform the translation from vaddr to paddr.
    hwaddr paddr = cpu_get_phys_page_debug(cs, vaddr);
    if (paddr == -1) {
        printf("notify_exec_instruction: No virtual translation for code address %lX!\n", vaddr);
        return;
    }

    // Get the pointer to executing code in host memory.
    void *code = qemu_map_ram_ptr_nofault(NULL, paddr + (~TARGET_PAGE_MASK & vaddr), NULL);
    if (!code) {
        printf("notify_exec_instruction: No host memory for code address %lX!\n", paddr);
        return;
    }

    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the callback is set
        if(p->instance->cb.on_execute_instruction)
        {
            // Call the plugin callback
            p->instance->cb.on_execute_instruction(p->instance, vaddr, code);
        }
    }
}

void notify_read_memory(CPUState *cs, uint64_t paddr, uint64_t vaddr, uint8_t *value, int size)
{
    // Get the pointer to data in host memory. Could fail with RAM_ADDR_INVALID...
    void *ram_ptr = NULL;
    if(paddr != RAM_ADDR_INVALID){
        ram_ptr = qemu_map_ram_ptr_nofault(NULL, paddr, NULL);
    }


    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the callback is set
        if (p->instance->cb.on_memory_read)
        {
            // Call the plugin callback
            p->instance->cb.on_memory_read(p->instance, paddr, vaddr, value, ram_ptr, size);
        }
    }
}

void notify_write_memory(CPUState *cs, uint64_t paddr, uint64_t vaddr, const uint8_t *value, int size)
{
   // Get the pointer to data in host memory. Could fail with RAM_ADDR_INVALID...
    void *ram_ptr = NULL;
    if(paddr != RAM_ADDR_INVALID){
        ram_ptr = qemu_map_ram_ptr_nofault(NULL, paddr, NULL);
    }

   PluginInstanceList *p = NULL;
   QLIST_FOREACH(p, &plugin_instance_list, next)
   {
       // Check if the callback is set
       if (p->instance->cb.on_memory_write)
       {
           // Call the plugin callback
           p->instance->cb.on_memory_write(p->instance, paddr, vaddr, value, ram_ptr, size);
       }
   }
}

void notify_breakpoint_hit(CPUState *cs, OSBreakpoint* bp)
{
    CPUClass *cpu_class = CPU_GET_CLASS(cs);
    cpu_synchronize_state(cs);

    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the callback is set
        if (p->instance->cb.on_breakpoint)
        {
            vaddr pc = cpu_class->get_pc(cs);
            int bp_id = -1;
            if(bp){
                bp_id = bp->id;
            }

            // Call the plugin callback
            p->instance->cb.on_breakpoint(p->instance, cs->cpu_index, pc, bp_id);
        }
    }
}

void notify_exception(int32_t exception)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the callback is set
        if (p->instance->cb.on_exception)
        {
            // Call the plugin callback
            p->instance->cb.on_exception(p->instance, exception);
        }
    }
}

void notify_syscall(uint64_t number, ...)
{
    va_list valist;
    va_start(valist, number);

    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the callback is set
        if (p->instance->cb.on_syscall)
        {
            // Call the plugin callback
            p->instance->cb.on_syscall(p->instance, number, valist);
        }
    }

    va_end(valist);
}

void notify_syscall_exit(uint64_t number, ...)
{
    va_list valist;
    va_start(valist, number);

    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the callback is set
        if (p->instance->cb.on_syscall_exit)
        {
            // Call the plugin callback
            p->instance->cb.on_syscall_exit(p->instance, number, valist);
        }
    }

    va_end(valist);
}

void notify_interrupt(int mask)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the callback is set
        if (p->instance->cb.on_interrupt)
        {
            // Call the plugin callback
            p->instance->cb.on_interrupt(p->instance, mask);
        }
    }
}

void notify_receving_packet(uint8_t **pkt_buf, uint32_t *pkt_size)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the on_packet_recv callback is set
        if (p->instance->cb.on_packet_recv)
        {
            // Call the plugin callback
            p->instance->cb.on_packet_recv(p->instance, pkt_buf, pkt_size);
        }
    }
}

void notify_sending_packet(uint8_t **pkt_buf, uint32_t *pkt_size)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the on_packet_send callback is set
        if (p->instance->cb.on_packet_send)
        {
            // Call the plugin callback
            p->instance->cb.on_packet_send(p->instance, pkt_buf, pkt_size);
        }
    }
}

void notify_vm_startup(void)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the on_vm_startup callback is set
        if (p->instance->cb.on_vm_startup)
        {
            // Call the plugin callback
            p->instance->cb.on_vm_startup(p->instance);                
        }
    }
}

void notify_vm_shutdown(void)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the on_vm_shutdown callback is set
        if (p->instance->cb.on_vm_shutdown)
        {
            // Call the plugin callback
            p->instance->cb.on_vm_shutdown(p->instance);                
        }
    }
}

void display_request_shutdown(void)
{
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_UI);
}

void display_register(QemuDisplay *ui)
{
    qemu_display_register(ui);
}

void display_register_DisplayChangeListener(DisplayChangeListener *dcl)
{
    register_displaychangelistener(dcl);
}

void display_add_mouse_mode_change_notifier(Notifier *notify)
{
    qemu_add_mouse_mode_change_notifier(notify);
}

void *display_surface_get_image(DisplaySurface *s)
{
    return surface_data(s);
}

int display_surface_get_width(DisplaySurface *s)
{
    return surface_width(s);
}

int display_surface_get_height(DisplaySurface *s)
{
    return surface_height(s);
}

PixelFormat display_get_pixelformat(DisplaySurface *s)
{
    return qemu_pixelformat_from_pixman(s->format);
}

pixman_format_code_t display_get_display_format(DisplaySurface *s)
{
    return s->format;
}

QemuConsole *display_console_lookup_by_index(unsigned int index)
{
    return qemu_console_lookup_by_index(index);
}

void *display_get_display_plugin(void)
{
    return qemu_get_display_plugin();
}

void display_graphic_hw_update(QemuConsole *con)
{
    graphic_hw_update(con);
}

void display_console_set_window_id(QemuConsole *con, int window_id)
{
    qemu_console_set_window_id(con, window_id);
}

bool display_console_is_graphic(QemuConsole *con)
{
    return qemu_console_is_graphic(con);
}

void display_process_graphic_key_event(QemuConsole *con, int keycode, bool key_down)
{
    qemu_input_event_send_key_qcode(con, keycode, key_down);
}

const guint16 *display_get_xorg_input_map(int *maplen)
{
    if (maplen)
    {
       *maplen = qemu_input_map_xorgevdev_to_qcode_len;
       return qemu_input_map_xorgevdev_to_qcode;
    }
    return NULL;
}

bool notify_command(const char *cmd, const char *args)
{
    // Loop through the plugins
    PluginInstanceList *p = NULL;
    QLIST_FOREACH(p, &plugin_instance_list, next)
    {
        // Check if the on_command callback is set
        if (p->instance->cb.on_command)
        {
            // Call the plugin callback
            if(p->instance->cb.on_command(p->instance, cmd, args)){
                return true;
            }
        }
    }

    return false;
}
