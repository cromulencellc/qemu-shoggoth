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

#ifndef RSAVE_TREE_NODE_H
#define RSAVE_TREE_NODE_H

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "qom/object.h"
#include "vmstate-file.h"
#include "qemu-memory-channel.h"

typedef struct RSaveTreeNode RSaveTreeNode;
typedef struct RSaveTreeNodeMeta RSaveTreeNodeMeta;
typedef struct RSaveTreeNodeClass RSaveTreeNodeClass;
typedef struct RSaveTreeNodeLink RSaveTreeNodeLink;

#define TYPE_RSAVE_TREE_NODE_LINK (stringify(TYPE_##RSaveTreeNodeLink))
#define RSAVE_TREE_NODE_LINK(obj)                                    \
    OBJECT_CHECK(RSaveTreeNodeLink, (obj), TYPE_RSAVE_TREE_NODE_LINK)

RSaveTreeNodeLink* rsave_tree_node_link_new(RSaveTreeNodeLink *parent, RSaveTreeNode *node);

#define TYPE_RSAVE_TREE_NODE "rsave-tree-node"
#define RSAVE_TREE_NODE(obj)                                    \
    OBJECT_CHECK(RSaveTreeNode, (obj), TYPE_RSAVE_TREE_NODE)
#define RSAVE_TREE_NODE_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(RSaveTreeNodeClass, klass, TYPE_RSAVE_TREE_NODE)
#define RSAVE_TREE_NODE_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(RSaveTreeNodeClass, obj, TYPE_RSAVE_TREE_NODE)

typedef struct VMStateIndexEntry{
    char idstr[256];
    uint32_t instance_id;
    uint32_t section_id;
    uint64_t offset;
    QLIST_ENTRY(VMStateIndexEntry) next;
} VMStateIndexEntry;

struct RSaveTreeNodeMeta {
    int64_t timestamp;
    uint64_t instruction_number;
    uint64_t cpu_exception_index;
    int32_t job_id;
    int32_t reserved;
};

struct RSaveTreeNode {
    Object obj;

    // State stuff
    uint32_t num_devices;
    QLIST_HEAD(,VMStateIndexEntry) device_list;
    uint64_t cpu_exception_index;
    uint64_t instruction_number;
    int64_t timestamp;
    int32_t job_id;
    SHA1_HASH_TYPE parent_hash;
    SHA1_HASH_TYPE hash;
    MemoryChannel *vm_state;
    QList *link_list;
};

struct RSaveTreeNodeClass {
    ObjectClass parent;
    void (*write_tree_node)(RSaveTreeNode *rst, FILE *fp);
    void (*read_tree_node)(RSaveTreeNode *rst, FILE *fp, size_t node_size);
    void (*calculate_hash)(RSaveTreeNode *rst);
};

RSaveTreeNode* rsave_tree_node_new(void);

#endif