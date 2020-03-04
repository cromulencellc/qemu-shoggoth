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
#include "qemu/qemu-plugin.h"
#include "plugin/plugin-object.h"

// These macros define object operations
#define TYPE_PWNME_SOLVE "pwnme_lots_solve"
#define PWNME_SOLVE(obj)                                    \
    OBJECT_CHECK(PwnMeSolve, (obj), TYPE_PWNME_SOLVE)
#define PWNME_SOLVE_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(PwnMeSolveClass, klass, TYPE_PWNME_SOLVE)
#define PWNME_SOLVE_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(PwnMeSolveClass, obj, TYPE_PWNME_SOLVE)

// This is for opts
#define PWNME_SOLVE_OPTS  ("pwnme_lots_solve_opts")

// Object type data
typedef struct PwnMeSolve PwnMeSolve;
typedef struct PwnMeSolveClass PwnMeSolveClass;

#define NBINS (0x8faf2 - 0x7aa)

struct PwnMeSolve 
{
    PluginObject obj;
    bool stop;
    int runs;
    int exec;
    int cum_old;
    bool new_insn;
    uint64_t base;
    int insn_bins[NBINS];
    uint8_t input[256];
};

struct PwnMeSolveClass
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

static JOB_REPORT_TYPE this_get_ra_report_type(void *opaque)
{
    return JOB_REPORT_PROCESSOR | JOB_REPORT_EXCEPTION;
}

static void this_on_ra_start(void *opaque, CommsWorkItem* work) 
{
    PwnMeSolve *h = PWNME_SOLVE(opaque);
    PwnMeSolveClass *h_klass = PWNME_SOLVE_GET_CLASS(h);
    (void)h_klass;
    if((h->runs % 0x3F) == 0){
        printf("Fuzzing job:  %d\n", h->runs+1);
    }
}

static void randomize_input(PwnMeSolve *h)
{
   for( int i = 0; i < 256; i++){
       h->input[i] = rand() / (RAND_MAX / 256);
   }
}

static void rollover_input(PwnMeSolve *h)
{
   h->input[0]++;

   for( int i = 0; i < 256; i++){
      if( h->input[i] == 0xFF ){
          if(i < 255){
              h->input[i+1]++;
          }
          h->input[i] = 0;
      }
   }
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

static void print_comms_report_message(PwnMeSolve *h, CommsMessage *in)
{
    int count = 1;
    JOB_REPORT_TYPE report_type;

    // printf("\nComms Report Message:\n");

    CommsResponseJobReportMsg *crjrin = (CommsResponseJobReportMsg*)(in + 1);
    // printf("\tQueue Number: %d, ", crjrin->queue);
    // printf("Instructions: %lu, ", crjrin->num_insns);
    // printf("Job ID: %d\n", crjrin->job_id);

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
                    // CommsResponseJobReportProcessorEntry *proc = (CommsResponseJobReportProcessorEntry *)buffer;
                    // printf("\tProcessor (%d): %s\n", proc->cpu_id, proc->cpu_name);
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
                            // printf("\t%s (%x): %lx\n", reg->name, reg->id, *((uint64_t *)reg->value));
                            break;
                        case 4:
                            // printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint32_t *)reg->value));
                            break;
                        case 2:
                            // printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint16_t *)reg->value));
                            break;
                        case 1:
                            // printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint8_t *)reg->value));
                            break;
                        default:
                            // printf("\t%s (%x): %x\n", reg->name, reg->id, reg->size);
                            break;
                    }
                }
                break;
            case JOB_REPORT_VIRTUAL_MEMORY...JOB_REPORT_PHYSICAL_MEMORY:
                {
                    CommsResponseJobReportMemoryEntry *mem = (CommsResponseJobReportMemoryEntry *)buffer;
                    buffer += (sizeof(CommsResponseJobReportMemoryEntry) + mem->size - 1);

                    // printf("\t%lx (%xh B): %lx...\n", mem->offset, mem->size, *((uint64_t *)mem->value));
                }
                break;
            case JOB_REPORT_ERROR:
                {
                    // CommsResponseJobReportErrorEntry *err = (CommsResponseJobReportErrorEntry *)buffer;
                    buffer += sizeof(CommsResponseJobReportErrorEntry);

                    // printf("\tError %x [%lx]: %s\n", err->error_id, err->error_loc, err->error_text);
                }
                break;
            case JOB_REPORT_EXCEPTION:
                {
                    CommsResponseJobReportExceptionEntry *ee = (CommsResponseJobReportExceptionEntry *)buffer;
                    buffer += sizeof(CommsResponseJobReportExceptionEntry);

                    // printf("\tException Mask: %lx\n", ee->exception_mask);

                    if(ee->exception_mask & (1<<13)){
                        h->stop = true;
                    }
                }
                break;
            default:
                // printf("\n\tUnknown Report Type: %d\n", report_type);
                // printf("\tEnding Report Here.\n");
                count = 0;
                break;
        }

    } while(buffer < end && count);

    // printf("End Report\n");
}

static void this_on_ra_stop(void *opaque, CommsResultsItem *work_results) 
{
    PwnMeSolve *h = PWNME_SOLVE(opaque);
    PwnMeSolveClass *h_klass = PWNME_SOLVE_GET_CLASS(h);
    (void)h_klass;

    h->runs++;
    if( h->new_insn == false ){
        h->cum_old++;
    }else{
        h->cum_old = 0;
    }

    if(h->cum_old > 5){
        randomize_input(h);
    }else{
        rollover_input(h);
    }

    CommsMessage *in = work_results->msg;
    print_comms_report_message(h, in);
}

static void this_on_ra_idle(void *opaque) 
{
    PwnMeSolve *h = PWNME_SOLVE(opaque);
    PwnMeSolveClass *h_klass = PWNME_SOLVE_GET_CLASS(h);
    (void)h_klass;

    if( h->stop ){
        printf("Found segfault after %d runs\n\n", h->runs);
        printf("Crashing input is: ");
        for( int i = 0; i < 256; i++){
            printf("%02x ", h->input[i]);
        }
        printf("\n");
        exit(1);
        return;
    }

    h->exec = 0;
    h->base = 0;
    h->new_insn = false;
    SHA1_HASH_TYPE run_hash;
    
    string_to_hash("2cfa4aafd5904143d61fbf795b215da016f70cf5", run_hash);

    CommsMessage *out = racomms_create_job_add_msg(1, h->runs+1, run_hash, 0);
    out = racomms_msg_job_add_put_MemorySetup(out, 0x7fffffffe580, sizeof(h->input), (uint8_t*)h->input, MEMORY_VIRTUAL);

    if( (h->runs % 0x3F) == 0){
        printf("Starting job: %d\n", h->runs+1);
        printf("Input is: ");
        for( int i = 0; i < 256; i++){
            printf("%02x ", h->input[i]);
        }
        printf("\nCoverage is: ");
        const uint64_t scale = NBINS / 68;
        printf("scale is %lu\n", scale);
        for( int i = 0; i < NBINS; i+=scale){
            uint64_t bin_sum = 0;
            for( int j = 0; j < scale; j++){
                bin_sum += h->insn_bins[j+i];
            }
            printf("%lu ", bin_sum);
        }
        printf("\nStale path count: %d\n", h->cum_old);
    }

    CommsQueue *q = get_comms_queue(0);
    racomms_queue_add_job(q, out);
}

static void this_on_execute_instruction(void *opaque, uint64_t vaddr, void *addr)
{
   PwnMeSolve *h = PWNME_SOLVE(opaque);
   (void)h;

   if(h->exec == 0){
       h->base = vaddr;
   }else{
       const int bin_hit = vaddr - h->base;
       if( bin_hit > 0 && bin_hit < NBINS){
           if(h->insn_bins[bin_hit] == 0){
               h->new_insn = true;
           }
           h->insn_bins[bin_hit]++;
       }
   }

   h->exec++;
}

static bool pwnme_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
   PwnMeSolve *h = PWNME_SOLVE(opaque);

   h->stop = false;
   h->cum_old = 0;

   for( int i = 0; i < NBINS; i++){
      h->insn_bins[i] = 0;
   }

   for( int i = 0; i < 256; i++){
      h->input[i] = 0;
   }

   return true;
}

static void pwnme_set_callbacks(void *opaque, PluginCallbacks *callbacks)
{
    callbacks->get_ra_report_type = this_get_ra_report_type;
    callbacks->on_ra_start = this_on_ra_start;
    callbacks->on_ra_stop = this_on_ra_stop;
    callbacks->on_ra_idle = this_on_ra_idle;
    callbacks->on_execute_instruction = this_on_execute_instruction;
}

// Object setup: constructor
static void pwnme_initfn(Object *obj)
{
    PwnMeSolve *h = PWNME_SOLVE(obj);
    h->runs = 0;
}

// Object setup: destructor
static void pwnme_finalize(Object *obj)
{
    PwnMeSolve *h = PWNME_SOLVE(obj);
    (void)h;
}

// Object setup: class constructor 
static void pwnme_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->init_plugin = pwnme_init_plugin;
    p_klass->set_callbacks = pwnme_set_callbacks;

    PwnMeSolveClass *h_klass = PWNME_SOLVE_CLASS(klass);
    (void)h_klass;
}

// Object setup: Object info
static TypeInfo pwnme_info = {
    .parent = TYPE_PLUGIN_OBJECT,
    .name = TYPE_PWNME_SOLVE,
    .instance_size = sizeof(PwnMeSolve),
    .instance_init = pwnme_initfn,
    .instance_finalize = pwnme_finalize,
    .class_init = pwnme_class_init,
    .class_size = sizeof(PwnMeSolveClass)
};

// Setup options to configure the plugin
static QemuOptsList pwnme_opts = {
    .name = PWNME_SOLVE_OPTS,
    .head = QTAILQ_HEAD_INITIALIZER(pwnme_opts.head),
    .desc = { 
        { /* end of list */ }
    },
};

// These functions are required to setup the plugins
bool plugin_setup(void *plugin, const char *path)
{
    srand(time(NULL));
    srand(rand());

    qemu_plugin_register_type(plugin, &pwnme_info);
    qemu_plugin_register_options(plugin, &pwnme_opts);
    return true;
}
