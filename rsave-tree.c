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

#include "rsave-tree.h"
#include "migration/rsave-tree-node.h"
#include "migration/ram_rapid.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qpointer.h"
#include "oshandler/oshandler.h"
#include "tcg/tcg.h"

#include <stdlib.h>
#include <string.h>

struct RAMRapidReferenceCache{
    ram_addr_t addr;
    SHA1_HASH_TYPE hash;
    uint8_t *pageptr;
};

struct StreamHook {
    int fileno;
    size_t input_len;
    uint8_t *input;
    int64_t offset;
};

static void rsave_tree_prepare_tb(RSaveTree *rst, TranslationBlock *tb)
{
    if( rst->istep != 0 ) {
        tcg_tb_set_cflags_count(tb, rst->istep);
    }
}

static void rsave_tree_lock(RSaveTree *rst)
{
    qemu_mutex_lock_impl(&rst->tree_mutex, __FILE__, __LINE__);
}

static void rsave_tree_unlock(RSaveTree *rst)
{
    qemu_mutex_unlock_impl(&rst->tree_mutex, __FILE__, __LINE__);
}

static void rsave_tree_init_ram_cache(RSaveTree *rst, uint64_t size, Error **errp)
{
    // Align the cache to the target page size.
    uint64_t asize = QEMU_ALIGN_UP(size, TARGET_PAGE_SIZE);

    // Set the number of table entries.
    // Using modulus for the table index only works because a load won't have two
    // reference page requests for the same address. Chance of collision is small.
    rst->ntables = asize >> TARGET_PAGE_BITS;

    // Allocate memory for the table and pages. We'll separate them so the pages
    // accessed most frequently will stay in the CPU's cache.
    rst->reftable = g_new0(RAMRapidReferenceCache, rst->ntables);
    if (!rst->reftable) {
        error_setg(errp, "Cannot allocate reference table of capacity %" PRIu64, rst->ntables);
        return;
    }
    rst->pagemem = g_malloc(asize);
    if (!rst->pagemem) {
        error_setg(errp, "Cannot allocate reference cache of size %" PRIu64, asize);
        return;
    }
    rst->memend = rst->pagemem;
}

static bool rsave_tree_search_ram_cache(RSaveTree *rst,
    ram_addr_t offset,
    SHA1_HASH_TYPE ref_hash,
    uint8_t *host_buf)
{
    if( !rst->pagemem || !rst->reftable ){
        return false;
    }

    size_t page = (offset >> TARGET_PAGE_BITS) % rst->ntables;
    const RAMRapidReferenceCache *refcache = &rst->reftable[page];

    if( offset == refcache->addr &&
        !memcmp(ref_hash, refcache->hash, sizeof(SHA1_HASH_TYPE)) )
    {
        memcpy(host_buf, refcache->pageptr, TARGET_PAGE_SIZE);
        return true;
    }

    return false;
}

static void rsave_tree_update_ram_cache(RSaveTree *rst,
    ram_addr_t offset,
    SHA1_HASH_TYPE ref_hash,
    uint8_t *host_buf)
{
    if( !rst->pagemem || !rst->reftable ){
        return;
    }

    size_t page = (offset >> TARGET_PAGE_BITS) % rst->ntables;
    RAMRapidReferenceCache *refcache = &rst->reftable[page];

    refcache->addr = offset;
    memcpy(refcache->hash, ref_hash, sizeof(SHA1_HASH_TYPE));
    // Do we need to assign this entry some memory?
    if(!refcache->pageptr){
        // Newly populated cache entry.
        refcache->pageptr = rst->memend;
        rst->memend += TARGET_PAGE_SIZE;
    }

    memcpy(refcache->pageptr, host_buf, TARGET_PAGE_SIZE);
}

static bool rsave_tree_validate_state(RSaveTree *rst, CPUState *cpu)
{
    bool is_valid = false;
    CPUClass *cpu_class = CPU_GET_CLASS(cpu); 

    is_valid = true;

    // Check the executing address
    if( cpu_class->get_pc )
    {
        vaddr pc = cpu_class->get_pc(cpu);

        // Check that segment endpoints are set.
        if (rst->segment_begin && 
            rst->segment_end   &&
            pc)
        {
            is_valid = false;

            // make sure that the PC falls between 
            if (pc >= rst->segment_begin && 
                pc <= rst->segment_end)
            {
                is_valid = true;
            }
        }
    }

    // If os handlers are initialized, check for valid user process space as well.
    if( is_valid && is_oshandler_active() )
    {
        OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

        is_valid = false;

        if( rst->target_process != NULL_PID &&
            os_cc->is_active_process(
                os_handler,
                cpu,
                os_cc->get_processinfo_by_ospid(os_handler, rst->target_process)) )
        {
            is_valid = true;
        }
    }
 
    return is_valid;
}

static bool rsave_tree_validate_iteration(RSaveTree *rst)
{
    return !rst->job_ilimit || rst->icount < rst->job_ilimit;
}

static bool rsave_tree_validate_exception(RSaveTree *rst)
{
    return !(rst->exceptions_occurred & rst->exception_mask);
}

static bool rsave_tree_final_iteration(RSaveTree *rst)
{
    return rst->icount == rst->job_ilimit;
}

static void rsave_tree_increment_iteration(RSaveTree *rst, TranslationBlock *tb) 
{
    rst->icount += tcg_tb_get_icount(tb);
}

static void rsave_tree_write_node(RSaveTree *rst, RSaveTreeNode *node, uint64_t *out_index)
{
    // Add the current node to the vm state file
    VMStateFileClass *vmstate_file_class = VMSTATE_FILE_GET_CLASS(rst->vm_state_file);
    vmstate_file_class->save_data(
        rst->vm_state_file,
        node,
        out_index,
        rst->skip_save && !(rst->job_flags & JOB_FLAG_FORCE_SAVE));
}

static QEMUFile *rsave_tree_load_from_node(RSaveTree *rst, RSaveTreeNode *node)
{
    // Prepare the file container with the VM state and load procedure.
    memcpy(rst->active_hash, node->hash, sizeof(SHA1_HASH_TYPE));
    return qemu_fopen_ops(node->vm_state, &memory_channel_input_ops);
}

static void free_node_link(void *obj)
{
    object_unref(OBJECT(obj));
}

/**
 * The RSaveTree consists of two lists, a linked list of states which serves
 * as a timeline; and, a dictionary that keys off of the id which lists 
 * states at different occourances of the id. 
 * 
 * We will do the following things when adding a state node
 * 1 - Add the snapshot to the list of states
 * 2 - Add the snapshot to the dictionary of states, keyed off of the id
 */
static void rsave_tree_insert_analysis_node(RSaveTree *rst, RSaveTreeNode *new_child, const char* key_id)
{
    RSaveTreeNodeLink *parent_link = rst->last_state_link;
    RSaveTreeNodeLink *rstl = rsave_tree_node_link_new(parent_link, new_child);

    // Check if the key exists in the dictionary
    if(qdict_haskey(rst->node_reference, key_id))
    {
        // We've seen this instruction before
        // Add the new node to the existing list
        QList *occurrence_list = qdict_get_qlist(rst->node_reference, key_id);
        QPointer *lptr = qpointer_from_pointer(rstl, free_node_link);

        qlist_append(occurrence_list, lptr);
    }
    else
    {
        // We haven't seen this instruction yet
        // We will make a new list, add this node to it
        // and add the list to the dictionary
        QList *occurrence_list = qlist_new();
        QPointer *lptr = qpointer_from_pointer(rstl, free_node_link);

        qlist_append(occurrence_list, lptr);
        qdict_put(rst->node_reference, key_id, occurrence_list);
    }

    if( rst->last_state_link ) {
        object_unref(OBJECT(rst->last_state_link));
    }

    object_ref(OBJECT(rstl));
    rst->last_state_link = rstl;
}

static void rsave_tree_load_new_analysis(RSaveTree *rst, RSaveTreeNode *node)
{
    if(rst->last_state_link) {
        object_unref(OBJECT(rst->last_state_link));
        rst->last_state_link = NULL;
    }

    rst->last_state_link = rsave_tree_node_link_new(NULL, node);
}

static void rsave_tree_start_analysis(RSaveTree *rst)
{
    RSaveTreeNodeLink *rstl = rst->last_state_link;

    QPointer *lptr = qpointer_from_pointer(rstl, free_node_link);
    qlist_append(rst->root_list, lptr);

    object_ref(OBJECT(rstl));
    rst->last_state_link = rstl;
}

static StreamHook *rsave_tree_set_stream_data(RSaveTree *rst, uint32_t fileno, uint8_t *data, uint32_t count)
{
    StreamHook *hp = g_new0(StreamHook, 1);

    hp->fileno = fileno;
    hp->input = data;
    hp->input_len = count;

    qlist_append(rst->stream_hook_list, qpointer_from_pointer((void *)hp, g_free));

    return hp;
}

static StreamHook *rsave_tree_get_stream_data(RSaveTree *rst, int fd)
{
    QListEntry *e;
    QLIST_FOREACH_ENTRY(rst->stream_hook_list, e) {
        QPointer *this_qptr = qobject_to(QPointer, qlist_entry_obj(e));
        StreamHook* this_stream = qpointer_get_pointer(this_qptr);
        if(this_stream->fileno == fd) {
            return this_stream;
        }
    }
    return false;
}

static bool rsave_tree_write_stream_data(RSaveTree *rst, CPUState *cs, int fileno, ram_addr_t buf, size_t count)
{
    StreamHook *hp = rsave_tree_get_stream_data(rst, fileno);
    size_t size = count;

    if (hp == false || hp->offset == -1)
        return false;

    if (hp->offset+count > hp->input_len) {
        size = hp->offset+count - hp->input_len;
        ram_rapid_set_ram_block(cs,
                                buf,
                                size,
                                (hp->input)+hp->offset,
                                false);
        hp->offset = -1;
        return true;
    }

    ram_rapid_set_ram_block(cs,
                            buf,
                            size,
                            (hp->input)+hp->offset,
                            false);

    hp->offset += count;
    return true;
}

static void rsave_tree_reset_job(RSaveTree *rst, uint8_t queue, int32_t job_id, JOB_FLAG_TYPE job_flags)
{
    rst->icount = 0;
    rst->job_id = job_id;
    rst->job_flags = job_flags;
    rst->message_queue_number = queue;
    rst->job_ilimit = rst->ilimit;
    rst->job_timeout = rst->config_timeout;
    rst->job_report_mask = rst->report_mask;
    rst->exceptions_occurred = 0;

    QListEntry *e;
    QLIST_FOREACH_ENTRY(rst->stream_hook_list, e) {
        QPointer *this_qptr = qobject_to(QPointer, qlist_entry_obj(e));
        StreamHook* this_stream = qpointer_get_pointer(this_qptr);
        this_stream->offset = 0;
    }
}

static void rsave_tree_reset(RSaveTree *rst)
{
    // Zero memory buffers
    memset(rst->backing_file_path, 0, sizeof(rst->backing_file_path));
    memset(rst->block_file_path, 0, sizeof(rst->block_file_path));
    memset(rst->vmstate_file_path, 0, sizeof(rst->vmstate_file_path));
    memset(rst->job_hash, 0, sizeof(rst->job_hash));

    rst->target_process = NULL_PID;
    rst->istep = 0;
    rst->icount = 0;
    rst->ilimit = 0;
    rst->report_mask = JOB_REPORT_PROCESSOR | JOB_REPORT_REGISTER | JOB_REPORT_PHYSICAL_MEMORY;
    rst->job_ilimit = 0;
    rst->job_report_mask = 0;
    rst->segment_begin = 0;
    rst->segment_end =  0;
    rst->message_queue_number = 0;
    rst->job_id = -1;
    rst->exception_mask = 0;
    rst->exceptions_occurred = 0;
    rst->has_work = false;
    rst->job_flags = 0;

    rst->last_state_link = NULL;
    rst->node_reference = NULL;
    rst->vm_state_file = NULL;

    rst->ntables = 0;
    rst->pagemem = NULL;
    rst->reftable = NULL;
    rst->memend = NULL;

    rst->stream_hook_list = qlist_new();
}

static void rsave_tree_initfn(Object *obj)
{
    RSaveTree *rst = RSAVE_TREE(obj);

    // Zero out primatives
    rsave_tree_reset(rst);

    // Setup the tree data structures
    rst->root_list = qlist_new();
    rst->node_reference = qdict_new();
    qemu_mutex_init(&rst->tree_mutex);
}

static void rsave_tree_finalize(Object *obj)
{
    RSaveTree *rst = RSAVE_TREE(obj);

    // Destroy the mutex
    qemu_mutex_destroy(&rst->tree_mutex);

    // Free up tree structures
    qobject_unref(rst->root_list);
    rst->root_list = NULL;
    qobject_unref(rst->node_reference);
    rst->node_reference = NULL;

    // Free stream hook entries
    qobject_unref(rst->stream_hook_list);
    rst->stream_hook_list = NULL;

    if(rst->last_state_link) {
        object_unref(OBJECT(rst->last_state_link));
        rst->last_state_link = NULL;
    }

    // Close out the VM State File
    if(rst->vm_state_file) {
        object_unref(OBJECT(rst->vm_state_file));
    }

    // Free the RAM cache, if allocated
    if(rst->reftable) {
        g_free(rst->reftable);
    }

    if(rst->pagemem) {
        g_free(rst->pagemem);
    }

    // Zero out primatives
    rsave_tree_reset(rst);
}

static void rsave_tree_class_init(ObjectClass *klass, void *class_data)
{
    RSaveTreeClass *rst_class = RSAVE_TREE_CLASS(klass);

    rst_class->prepare_tb = rsave_tree_prepare_tb;
    rst_class->lock_tree = rsave_tree_lock;
    rst_class->unlock_tree = rsave_tree_unlock;
    rst_class->validate_state = rsave_tree_validate_state;
    rst_class->validate_iteration = rsave_tree_validate_iteration;
    rst_class->validate_exception = rsave_tree_validate_exception;
    rst_class->final_iteration = rsave_tree_final_iteration;
    rst_class->increment_iteration = rsave_tree_increment_iteration;
    rst_class->write_node_state = rsave_tree_write_node;
    rst_class->load_new_analysis = rsave_tree_load_new_analysis;
    rst_class->start_analysis = rsave_tree_start_analysis;
    rst_class->insert_analysis = rsave_tree_insert_analysis_node;
    rst_class->load_from_node = rsave_tree_load_from_node;
    rst_class->init_ram_cache = rsave_tree_init_ram_cache;
    rst_class->search_ram_cache = rsave_tree_search_ram_cache;
    rst_class->update_ram_cache = rsave_tree_update_ram_cache;
    rst_class->set_stream_data = rsave_tree_set_stream_data;
    rst_class->get_stream_data = rsave_tree_get_stream_data;
    rst_class->write_stream_data = rsave_tree_write_stream_data;
    rst_class->reset_job = rsave_tree_reset_job;
}

static const TypeInfo rsave_tree_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_RSAVE_TREE,
    .instance_size = sizeof(RSaveTree),
    .instance_init = rsave_tree_initfn,
    .instance_finalize = rsave_tree_finalize,
    .class_init = rsave_tree_class_init,
    .class_size = sizeof(RSaveTreeClass),
};

static void rsave_tree_register_types(void)
{
    type_register_static(&rsave_tree_info);
}

type_init(rsave_tree_register_types);

RSaveTree* rsave_tree_create(void)
{
    RSaveTree *rst;
    rst = RSAVE_TREE(object_new(TYPE_RSAVE_TREE));
    return rst;
}
