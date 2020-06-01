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

#ifndef RSAVE_TREE_H
#define RSAVE_TREE_H

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "qom/object.h"
#include "migration/vmstate-file.h"
#include "migration/qemu-memory-channel.h"
#include "qemu/thread.h"
#include "qom/cpu.h"
#include "exec/tb-context.h"
#include "qapi/qmp/qdict.h"
#include "racomms/racomms-types.h"
#include "oshandler/ostypes.h"


#define SNAPSHOT_PATH_MAX (PATH_MAX+9)

typedef struct RSaveTree RSaveTree;
typedef struct RSaveTreeClass RSaveTreeClass;
typedef struct RAMRapidReferenceCache RAMRapidReferenceCache;
typedef struct StreamHook StreamHook;

#define TYPE_RSAVE_TREE "rsave-tree"
#define RSAVE_TREE(obj)                                    \
    OBJECT_CHECK(RSaveTree, (obj), TYPE_RSAVE_TREE)
#define RSAVE_TREE_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(RSaveTreeClass, klass, TYPE_RSAVE_TREE)
#define RSAVE_TREE_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(RSaveTreeClass, obj, TYPE_RSAVE_TREE)

struct RSaveTree {
    Object obj; 
    
    // Tree state information
    QList *root_list;
    RSaveTreeNodeLink *last_state_link;
    QDict *node_reference;
    SHA1_HASH_TYPE active_hash;

    // Data Protection
    QemuMutex tree_mutex;

    // File Storage information
    FILE *rsave_file_pointer;
    FILE *blocks_file_pointer;
    VMStateFile *vm_state_file;
    char backing_file_path[SNAPSHOT_PATH_MAX];
    char block_file_path[SNAPSHOT_PATH_MAX];
    char vmstate_file_path[SNAPSHOT_PATH_MAX];
    bool skip_trace;
    bool skip_tree;
    bool skip_save;
    bool enable_interrupts;
    bool skip_blocks;
    bool send_to_queue;

    // Execution State Trackers
    uint64_t istep;
    uint64_t icount;
    uint64_t ilimit;
    uint64_t msgsz_limit;
    uint64_t config_timeout;
    JOB_REPORT_TYPE report_mask;
    vaddr segment_begin;
    vaddr segment_end;
    OSPid target_process;

    // Job Reporting Information
    uint8_t message_queue_number;
    int32_t job_id;
    // End on defined exception
    uint64_t job_ilimit;
    uint64_t exception_mask;
    uint64_t exceptions_occurred;
    JOB_REPORT_TYPE job_report_mask;
    SHA1_HASH_TYPE job_hash;
    JOB_FLAG_TYPE job_flags;
    uint64_t job_timeout;

    // State Machine
    bool has_work;

    // Bookkeeping and memory for the reference cache
    size_t ntables;
    RAMRapidReferenceCache *reftable;
    uint8_t *pagemem;
    uint8_t *memend;

    // Stream Information
    QList *stream_hook_list;
};

struct RSaveTreeClass {
    ObjectClass parent;

    void (*prepare_tb)(RSaveTree *rst, TranslationBlock *tb);
    void (*lock_tree)(RSaveTree *rst);
    void (*unlock_tree)(RSaveTree *rst);
    bool (*validate_state)(RSaveTree *rst, CPUState *cpu);
    bool (*validate_iteration)(RSaveTree *rst);
    bool (*validate_exception)(RSaveTree *rst);
    bool (*final_iteration)(RSaveTree *rst);
    void (*increment_iteration)(RSaveTree *rst, TranslationBlock *tb);
    void (*write_node_state)(RSaveTree *rst, RSaveTreeNode *node, uint64_t *out_index);
    void (*load_new_analysis)(RSaveTree *rst, RSaveTreeNode *node);
    void (*start_analysis)(RSaveTree *rst);
    void (*insert_analysis)(RSaveTree *rst, RSaveTreeNode *new_child, const char* key_id);
    QEMUFile* (*load_from_node)(RSaveTree *rst, RSaveTreeNode *new_child);
    void (*init_ram_cache)(RSaveTree *rst, uint64_t size, Error **errp);
    bool (*search_ram_cache)(RSaveTree *rst, ram_addr_t offset, SHA1_HASH_TYPE ref_hash, uint8_t *host_buf);
    void (*update_ram_cache)(RSaveTree *rst, ram_addr_t offset, SHA1_HASH_TYPE ref_hash, uint8_t *host_buf);
    StreamHook *(*set_stream_data)(RSaveTree *rst, uint32_t fileno, uint8_t *data, uint32_t size);
    StreamHook *(*get_stream_data)(RSaveTree *rst, int fd);
    bool (*write_stream_data)(RSaveTree *rst, CPUState *cs, int fileno, ram_addr_t buf, size_t count);
    void (*reset_job)(RSaveTree *rst, uint8_t queue, int32_t job_id, JOB_FLAG_TYPE job_flags);
};

RSaveTree* rsave_tree_create(void);

#endif
