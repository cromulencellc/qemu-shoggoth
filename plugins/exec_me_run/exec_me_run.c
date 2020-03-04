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
 *  Adam Critchley
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
#define TYPE_EM_RUN "exec_me_run"
#define EM_RUN(obj)                                    \
    OBJECT_CHECK(EMRun, (obj), TYPE_EM_RUN)
#define EM_RUN_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(EMRunClass, klass, TYPE_EM_RUN)
#define EM_RUN_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(EMRunClass, obj, TYPE_EM_RUN)

// This is for opts
#define EM_RUN_OPTS  ("em_run_opts")

// Object type data
typedef struct EMRun EMRun;
typedef struct EMRunClass EMRunClass;

struct EMRun 
{
    PluginObject obj;
    int runs;
};

struct EMRunClass
{
    PluginObjectClass parent;
};

/**
 * These are the call back functions that QEMU will use to 
 * talk to the plugins. It is not required to implement all
 * of them; QEMU should be smart in calling only the set 
 * callbacks. For more information on these functions and
 * how the behave, see qemu/qemu-plugin.h. There is 
 * documentation on each function that is currently implemented.
 */

static JOB_REPORT_TYPE em_get_ra_report_type(void *opaque)
{
    return JOB_REPORT_PROCESSOR | JOB_REPORT_ERROR | JOB_REPORT_EXCEPTION;
}

static void em_on_ra_start(void *opaque, CommsWorkItem* work) 
{
    EMRun *h = EM_RUN(opaque);
    EMRunClass *h_klass = EM_RUN_GET_CLASS(h);
    (void)h;
    (void)h_klass;
}

static void string_to_hash(const char *str, SHA1_HASH_TYPE hash)
{
    uint8_t len = 0, pos = 0;
    char part[256];
    uint32_t partv;

    while(*str && (pos < sizeof(SHA1_HASH_TYPE)/sizeof(uint32_t)))
    {
        if(isalnum(*str)){
            part[len] = *str;
            len++;
        }
        if(len == 8){
            part[len] = '\0';
            len = 0;
            partv = strtol(part, NULL, 16);
            memcpy(&hash[pos], &partv, sizeof(uint32_t));
            pos++;
        }
        str++;
    }
}

static void print_comms_report_message(CommsMessage *in)
{
    int count = 1;
    JOB_REPORT_TYPE report_type;

    printf("\nComms Report Message:\n");

    CommsResponseJobReportMsg *crjrin = (CommsResponseJobReportMsg*)(in + 1);
    printf("\tQueue Number: %d, ", crjrin->queue);
    printf("Instructions: %u, ", crjrin->num_insns);
    printf("Job ID: %d\n", crjrin->job_id);

    char *buffer = (char*)crjrin;
    char *end = buffer + (in->size - sizeof(CommsMessage));
    buffer += sizeof(CommsResponseJobReportMsg);   

    do
    {
        report_type = *((JOB_REPORT_TYPE *)buffer);

        switch (report_type)
        {
            case JOB_REPORT_PROCESSOR:
                {
                    CommsResponseJobReportProcessorEntry *proc = (CommsResponseJobReportProcessorEntry *)buffer;
                    printf("\tProcessor (%d): %s\n", proc->cpu_id, proc->cpu_name);
                    buffer += sizeof(CommsResponseJobReportProcessorEntry);
                }
                break;
            case JOB_REPORT_REGISTER:
                {
                    CommsResponseJobReportRegisterEntry *reg = (CommsResponseJobReportRegisterEntry *)buffer;
                    buffer += (sizeof(CommsResponseJobReportRegisterEntry) + reg->size - 1);

                    switch(reg->size)
                    {
                        //case 16:
                        //    printf("%s (uint128_t): %lx\n", reg->name, *((uint128_t *)reg->value));
                        //    break;
                        case 8:
                            printf("\t%s (%x): %lx\n", reg->name, reg->id, *((uint64_t *)reg->value));
                            break;
                        case 4:
                            printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint32_t *)reg->value));
                            break;
                        case 2:
                            printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint16_t *)reg->value));
                            break;
                        case 1:
                            printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint8_t *)reg->value));
                            break;
                        default:
                            printf("\t%s (%x): %x\n", reg->name, reg->id, reg->size);
                            break;
                    }
                }
                break;
            case JOB_REPORT_VIRTUAL_MEMORY...JOB_REPORT_PHYSICAL_MEMORY:
                {
                    CommsResponseJobReportMemoryEntry *mem = (CommsResponseJobReportMemoryEntry *)buffer;
                    buffer += (sizeof(CommsResponseJobReportMemoryEntry) + mem->size - 1);

                    printf("\t%lx (%xh B): %lx...\n", mem->offset, mem->size, *((uint64_t *)mem->value));
                }
                break;
            case JOB_REPORT_ERROR:
                {
                    CommsResponseJobReportErrorEntry *err = (CommsResponseJobReportErrorEntry *)buffer;
                    buffer += sizeof(CommsResponseJobReportErrorEntry);

                    printf("\tError %x [%lx]: %s\n", err->error_id, err->error_loc, err->error_text);
                }
                break;
            case JOB_REPORT_EXCEPTION:
                {
                    CommsResponseJobReportExceptionEntry *ee = (CommsResponseJobReportExceptionEntry *)buffer;
                    buffer += sizeof(CommsResponseJobReportExceptionEntry);

                    printf("\tException Mask: %lx\n", ee->exception_mask);
                }
                break;
            default:
                printf("\n\tUnknown Report Type: %d\n", report_type);
                printf("\tEnding Report Here.\n");
                count = 0;
                break;
        }

    } while(buffer < end && count);

    printf("End Report\n");
}

static void em_on_ra_stop(void *opaque, CommsResultsItem *work_results) 
{
    EMRun *h = EM_RUN(opaque);
    EMRunClass *h_klass = EM_RUN_GET_CLASS(h);
    (void)h_klass;

    h->runs++;
    CommsMessage *in = work_results->msg;
    print_comms_report_message(in);
}

static void em_on_ra_idle(void *opaque) 
{
    EMRun *h = EM_RUN(opaque);
    EMRunClass *h_klass = EM_RUN_GET_CLASS(h);
    (void)h_klass;

    if( h->runs > 0 ){
        return;
    }

    printf("Starting new job...\n");
    SHA1_HASH_TYPE run_hash;
    CommsQueue *q = get_comms_queue(0);
    CommsWorkItem *work_item = g_new(CommsWorkItem, 1);
    QLIST_INIT(&work_item->entry_list);
    
    string_to_hash("be9f86320f28ec64fa257f6c57a61dc90ded648b", run_hash);

    CommsMessage *out;

    out = racomms_create_job_add_msg(1, 1, run_hash, 0);

    WorkEntryItem *work_entry = g_new(WorkEntryItem, 1);
    const char *d = "\x90\x90\x90\x90\x90\xcc";
    work_entry->offset = out->size;
    work_entry->entry_type = JOB_ADD_MEMORY;
    QLIST_INSERT_HEAD(&work_item->entry_list, work_entry, next);
    out = racomms_msg_job_add_put_MemorySetup(out, 0x7FFFF7FE0000, strlen(d), (uint8_t*)d, MEMORY_VIRTUAL);

    work_item->msg = out;
    queue_push_work(q, work_item);
}

// Object setup: constructor
static void em_initfn(Object *obj)
{
    EMRun *h = (EMRun *) obj;
    h->runs = 0;
}

// Object setup: destructor
static void em_finalize(Object *obj)
{
    EMRun *h = (EMRun *) obj;
    (void)h;
}

static bool em_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    EMRun *h = EM_RUN(opaque);
    (void)h;
   return true;
}

static void em_set_callbacks(void *opaque, PluginCallbacks *callbacks)
{
    callbacks->get_ra_report_type = em_get_ra_report_type;
    callbacks->on_ra_start = em_on_ra_start;
    callbacks->on_ra_stop = em_on_ra_stop;
    callbacks->on_ra_idle = em_on_ra_idle;
}

// Object setup: class constructor 
static void em_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->init_plugin = em_init_plugin;
    p_klass->set_callbacks = em_set_callbacks;
}

// Object setup: Object info
static TypeInfo em_info = {
    .parent = TYPE_PLUGIN_OBJECT,
    .name = TYPE_EM_RUN,
    .instance_size = sizeof(EMRun),
    .instance_init = em_initfn,
    .instance_finalize = em_finalize,
    .class_init = em_class_init,
    .class_size = sizeof(EMRunClass)
};

// Setup options to configure the plugin
static QemuOptsList em_opts = {
    .name = EM_RUN_OPTS,
    .head = QTAILQ_HEAD_INITIALIZER(em_opts.head),
    .desc = { 
        { /* end of list */ }
    },
};

// These functions are required to setup the plugins
bool plugin_setup(void *plugin, const char *path)
{
    qemu_plugin_register_type(plugin, &em_info);
    qemu_plugin_register_options(plugin, &em_opts);
    return true;
}
