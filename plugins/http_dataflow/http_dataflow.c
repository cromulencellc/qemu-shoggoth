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

#include <glib.h>
#include "oshandler/oshandler.h"
#include "qom/cpu.h"

// These macros define object operations
#define TYPE_HTTP_DATAFLOW "Http_Dataflow"
#define HTTP_DATAFLOW(obj) OBJECT_CHECK(Http_Dataflow, (obj), TYPE_HTTP_DATAFLOW)
#define HTTP_DATAFLOW_CLASS(klass) OBJECT_CLASS_CHECK(Http_DataflowClass, klass, TYPE_HTTP_DATAFLOW)
#define HTTP_DATAFLOW_GET_CLASS(obj) OBJECT_GET_CLASS(Http_DataflowClass, obj, TYPE_HTTP_DATAFLOW)

// This is for opts
#define HTTP_DATAFLOW_OPTS  ("http_dataflow")

// Object type data
typedef struct Http_Dataflow Http_Dataflow;
typedef struct Http_DataflowClass Http_DataflowClass;
typedef struct read_flow read_flow;
typedef struct write_flow write_flow;

struct read_flow{
    void *unit;
    size_t size;
    read_flow *next;
    write_flow *prev;
};

struct write_flow{
    void *unit;
    size_t size;
    read_flow *flow;
    write_flow *next;
};

struct Http_Dataflow
{
    PluginObject obj;
    uint8_t *pkt_data;
    size_t pkt_size;
    write_flow *first;
};

struct Http_DataflowClass
{
    PluginObjectClass parent;
};

// Object setup: constructor
static void http_dataflow_initfn(Object *obj)
{
    Http_Dataflow *h = (Http_Dataflow *) obj;
    h->pkt_data = NULL;
    h->pkt_size = 0;
    h->first = NULL;
}

// Object setup: destructor
static void http_dataflow_finalize(Object *obj)
{
    Http_Dataflow *h = (Http_Dataflow *) obj;
    (void) h;
}

static void http_dataflow_on_packet_recv(void *opaque, uint8_t **pkt_buf, uint32_t *pkt_size)
{
    Http_Dataflow *h = HTTP_DATAFLOW(opaque);
    Http_DataflowClass *h_klass = HTTP_DATAFLOW_GET_CLASS(h);
    (void) h_klass;
    const uint8_t *raw_pkt = *pkt_buf;

    if(!h->pkt_data){
        const char *eth_pkt = (const char*)raw_pkt;
        const uint16_t eth_type = g_ntohs(*((const uint16_t*)&eth_pkt[12]));
        // if IPv4
        if(eth_type == 0x0800){
            const uint8_t ip_type = *((const uint8_t*)&eth_pkt[23]);
            // if TCP
            if(ip_type == 6){
                const uint16_t dest_port = g_ntohs(*((const uint16_t*)&eth_pkt[36]));
                const uint8_t tcp_flags = *((const uint8_t*)&eth_pkt[47]);
                // Dest 8000 and PSH, ACK flags
                if(dest_port == 8000 && tcp_flags == 0x18){
                    h->pkt_size = *pkt_size;
                    h->pkt_data = g_memdup(raw_pkt, h->pkt_size);
                    h->pkt_size = *pkt_size;
                    printf("Found target HTTP packet...\n");
                    for(int i=0; i< h->pkt_size; i++){
                        printf("%02X ", h->pkt_data[i]);
                    }
                    printf("\n");
                }
            }
        }
    }
}

static void http_dataflow_on_memory_read(void *opaque, uint64_t paddr, uint64_t vaddr, uint8_t *value, void *addr, int size)
{
    Http_Dataflow *h = HTTP_DATAFLOW(opaque);
    Http_DataflowClass *h_klass = HTTP_DATAFLOW_GET_CLASS(h);
    (void) h_klass;

    if(h->first){
        write_flow *cur = h->first;
        while(cur){
            read_flow *flowed = NULL;
            void *start = cur->unit;
            void *end = cur->unit + cur->size;

            if( start <= addr && addr < end ){
                flowed = g_new0(read_flow, 1);
                flowed->prev = cur;
                flowed->unit = addr;
                flowed->size = MIN(size, end - addr);
            }else if( start <= (addr + size) && (addr + size) < end ){
                flowed = g_new0(read_flow, 1);
                flowed->prev = cur;
                flowed->unit = start;
                flowed->size = MIN(size, (addr + size) - start);
            }else if( start <= addr && (addr + size) < end ){
                flowed = g_new0(read_flow, 1);
                flowed->prev = cur;
                flowed->unit = addr;
                flowed->size = size;
            }

            if(flowed){
                ProcessInfo *pi = NULL;
                if( is_oshandler_active() && current_cpu ){
                    OSHandler *os = oshandler_get_instance();
                    OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os);
                    pi = os_cc->get_processinfo_by_active(os, current_cpu);
                }
                if( pi ){
                    printf("Found read flow at %p of size %ld for pid %d at offset %ld\n", flowed->unit, flowed->size, pi->pid, (flowed->unit - start));
                }else{
                    printf("Found read flow at %p of size %ld at offset %ld\n", flowed->unit, flowed->size, (flowed->unit - start));
                }
                flowed->next = cur->flow;
                cur->flow = flowed;
                break;
            }

            cur = cur->next;
        }
    }
}


static void http_dataflow_on_memory_write(void *opaque, uint64_t paddr, uint64_t vaddr, const uint8_t *value, void *addr, int size)
{
    Http_Dataflow *h = HTTP_DATAFLOW(opaque);
    Http_DataflowClass *h_klass = HTTP_DATAFLOW_GET_CLASS(h);
    (void)h_klass;
    if(h->pkt_data){
        // Find the first full packet write (DMA) into vm memory
        if(!h->first){
            if(!memcmp(h->pkt_data, value, size)){
                printf("Found match at %p of size %d\n", addr, size);

                h->first = g_new0(write_flow, 1);
                h->first->unit = addr;
                h->first->size = size;
            }
        }
    }
}
    

static bool http_dataflow_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    Http_Dataflow *h = HTTP_DATAFLOW(opaque);
    (void) h;
    return true;
}

static void http_dataflow_set_callbacks(void *opaque, PluginCallbacks *callbacks)
{
    callbacks->on_memory_write = http_dataflow_on_memory_write;
    callbacks->on_memory_read = http_dataflow_on_memory_read;
    callbacks->on_packet_recv = http_dataflow_on_packet_recv;
}

// Object setup: class constructor 
static void http_dataflow_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->init_plugin = http_dataflow_init_plugin;
    p_klass->set_callbacks = http_dataflow_set_callbacks;

    Http_DataflowClass *h_klass = HTTP_DATAFLOW_CLASS(klass);
    (void) h_klass;
}

// Object setup: Object info
static TypeInfo http_dataflow_info = {
    .parent = TYPE_PLUGIN_OBJECT,
    .name = TYPE_HTTP_DATAFLOW,
    .instance_size = sizeof(Http_Dataflow),
    .instance_init = http_dataflow_initfn,
    .instance_finalize = http_dataflow_finalize,
    .class_init = http_dataflow_class_init,
    .class_size = sizeof(Http_DataflowClass)
};

// Setup options to configure the plugin
static QemuOptsList qemu_http_dataflow_opts = {
    .name = HTTP_DATAFLOW_OPTS,
    .implied_opt_name = "message",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_http_dataflow_opts.head),
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
    qemu_plugin_register_type(plugin, &http_dataflow_info);
    qemu_plugin_register_options(plugin, &qemu_http_dataflow_opts);

    return true;
}
