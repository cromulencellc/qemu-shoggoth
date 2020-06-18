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

#include "rsave-tree-node.h"
#include "migration/ram_rapid.h"
#include "crypto/hash.h"
#include "qemu/timer.h"
#include "qemu/error-report.h"
#include "migration/rsave-tree-node.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qpointer.h"
#include "cromulence/inlines.h"

struct RSaveTreeNodeLink {
    Object obj;
    RSaveTreeNodeLink *next;
    RSaveTreeNodeLink *previous;
    RSaveTreeNode *node;
    SHA1_HASH_TYPE hash;
};

static void rsave_tree_node_write_tree_node(RSaveTreeNode *rstn, FILE* fp)
{
    VMStateIndexEntry *e;

    // Farm out some of the work.
    MemoryChannelClass *mcc = MEMORY_CHANNEL_GET_CLASS(rstn->vm_state);
    
    // Then write the instruction number
    fwrite(&rstn->instruction_number, sizeof(rstn->instruction_number), 1, fp);

    // First write the exception index.
    fwrite(&rstn->cpu_exception_index, sizeof(rstn->cpu_exception_index), 1, fp);

    // Lastly write the job id.
    fwrite(&rstn->job_id, sizeof(rstn->job_id), 1, fp);

    // Then write the parent hash
    fwrite(&rstn->parent_hash, sizeof(SHA1_HASH_TYPE), 1, fp);

    // Write the timestamp.
    fwrite(&rstn->timestamp, sizeof(rstn->timestamp), 1, fp);

    // Write the index table
    fwrite(&rstn->num_devices, sizeof(rstn->num_devices), 1, fp);
    QLIST_FOREACH(e, &rstn->device_list, next)
    {
        fwrite(&e->section_id, sizeof(e->section_id), 1, fp);
        fwrite(&e->instance_id, sizeof(e->instance_id), 1, fp);
        fwrite(e->idstr, sizeof(e->idstr), 1, fp);
        fwrite(&e->offset, sizeof(e->offset), 1, fp);
    }

    // Then write the vm-state.
    mcc->write_to_file(rstn->vm_state, fp);
}

static void rsave_tree_node_read_tree_node(RSaveTreeNode *rstn, FILE *fp, size_t node_size)
{
    // Farm out some of the work.
    size_t amount_remaining = node_size;
    MemoryChannel *vm_state = memory_channel_create();
    MemoryChannelClass *mcc = MEMORY_CHANNEL_GET_CLASS(vm_state);

    // Then read the instruction number and adjust the size.
    fread_checked(&rstn->instruction_number, sizeof(rstn->instruction_number), fp);
    amount_remaining -= sizeof(rstn->instruction_number);

    // Read the exception index and adjust our size.
    fread_checked(&rstn->cpu_exception_index, sizeof(rstn->cpu_exception_index), fp);
    amount_remaining -= sizeof(rstn->cpu_exception_index);

    // Read the job id.
    fread_checked(&rstn->job_id, sizeof(rstn->job_id), fp);
    amount_remaining -= sizeof(rstn->job_id);

    // Read the parent hash.
    fread_checked(&rstn->parent_hash, sizeof(SHA1_HASH_TYPE), fp);
    amount_remaining -= sizeof(SHA1_HASH_TYPE);

    // Read the timestamp.
    fread_checked(&rstn->timestamp, sizeof(rstn->timestamp), fp);
    amount_remaining -= sizeof(rstn->timestamp);

    // Read the number of elements in the VM State index table.
    fread_checked(&rstn->num_devices, sizeof(rstn->num_devices), fp);
    amount_remaining -= sizeof(rstn->num_devices);

    // Read in each element of the vm state index table, making sure to 
    // keep track of the amount of data left in the overall entry.
    for(int i=0; i<rstn->num_devices; i++){

        VMStateIndexEntry *e = g_new0(VMStateIndexEntry,1);
        
        if(e == NULL){
            return;
        }

        fread_checked(&e->section_id, sizeof(e->section_id), fp);
        amount_remaining -= sizeof(e->section_id);

        fread_checked(&e->instance_id, sizeof(e->instance_id), fp);
        amount_remaining -= sizeof(e->instance_id);

        fread_checked(e->idstr, sizeof(e->idstr), fp);
        amount_remaining -= sizeof(e->idstr);

        fread_checked(&e->offset, sizeof(e->offset), fp);
        amount_remaining -= sizeof(e->offset);
        
        QLIST_INSERT_HEAD(&rstn->device_list, e, next);
    }

    // Then read the vm-state
    mcc->read_from_file(vm_state, fp, amount_remaining);

    // We want this to be a fresh state,
    // So, we're going to free the vm state if it exists.
    // This really should be called on an empty node
    if (rstn->vm_state)
    {
        mcc->close(rstn->vm_state);
    }

    // Store the loaded data
    rstn->vm_state = vm_state;
}

static void rsave_tree_node_calculate_hash(RSaveTreeNode *rstn)
{
    // Variables
    uint8_t *result;
    size_t resultlen;
    MemoryChannel *vm_state;
    MemoryChannelClass *vm_state_class;
    QEMUIOVector *qiov;
    RSaveTreeNodeMeta meta_data;

    // Initialization
    vm_state = rstn->vm_state;
    result = (uint8_t *) rstn->hash;
    resultlen = sizeof(SHA1_HASH_TYPE);
    vm_state_class = MEMORY_CHANNEL_GET_CLASS(vm_state);

    // Add our own modifiers for the node metadata
    vm_state_class->remove_meta(vm_state);

    // hash in CPU Exception, controller job id, instruction number wrt analysis session, time wrt epoch
    memset(&meta_data, 0, sizeof(RSaveTreeNodeMeta));
    meta_data.cpu_exception_index = rstn->cpu_exception_index;
    meta_data.job_id = rstn->job_id;
    meta_data.instruction_number = rstn->instruction_number;
    meta_data.timestamp = rstn->timestamp;

    meta_data.reserved = 0;
    vm_state_class->add_meta(vm_state, &meta_data, sizeof(RSaveTreeNodeMeta));

    // Get the iovs for hashing the memory channel
    size_t qiov_size = vm_state_class->get_stream(vm_state, &qiov);

    qcrypto_hash_bytesv(QCRYPTO_HASH_ALG_SHA1,
                        qiov->iov,
                        qiov_size,
                        &result,
                        &resultlen,
                        NULL);

    vm_state_class->remove_meta(vm_state);
}

static void rsave_tree_node_initfn(Object *obj)
{
    RSaveTreeNode *rstn = RSAVE_TREE_NODE(obj);

    rstn->vm_state = NULL;
    rstn->instruction_number = 0;
    rstn->cpu_exception_index = 0;
    rstn->num_devices = 0;
    rstn->timestamp = 0;
    rstn->job_id = -1;
    rstn->link_list = qlist_new();
}

static void rsave_tree_node_finalize(Object *obj)
{
    RSaveTreeNode *rstn = RSAVE_TREE_NODE(obj);
    VMStateIndexEntry *e, *next;
    QListEntry *qe = NULL;

    QLIST_FOREACH_SAFE(e, &rstn->device_list, next, next)
    {
        QLIST_REMOVE(e, next);
        g_free(e);
    }

    if (rstn->vm_state)
    {
        object_unref(OBJECT(rstn->vm_state));
    }

    rstn->cpu_exception_index = 0;

    // Detach links.
    QLIST_FOREACH_ENTRY(rstn->link_list, qe){
        QPointer *this_qptr = qobject_to(QPointer, qlist_entry_obj(qe));
        RSaveTreeNodeLink* this_link = qpointer_get_pointer(this_qptr);
        this_link->node = NULL;
    }

    object_unref(OBJECT(rstn->link_list));
}

static void rsave_tree_node_class_init(ObjectClass *klass, void *class_data)
{
    RSaveTreeNodeClass *rstn_class = RSAVE_TREE_NODE_CLASS(klass);

    rstn_class->write_tree_node = rsave_tree_node_write_tree_node;
    rstn_class->read_tree_node = rsave_tree_node_read_tree_node;
    rstn_class->calculate_hash = rsave_tree_node_calculate_hash;
}

static const TypeInfo rsave_tree_node_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_RSAVE_TREE_NODE,
    .instance_size = sizeof(RSaveTreeNode),
    .instance_init = rsave_tree_node_initfn,
    .instance_finalize = rsave_tree_node_finalize,
    .class_init = rsave_tree_node_class_init,
    .class_size = sizeof(RSaveTreeNodeClass),
};

static void rsave_tree_node_register_types(void)
{
    type_register_static(&rsave_tree_node_info);
}

type_init(rsave_tree_node_register_types);

RSaveTreeNode* rsave_tree_node_new(void)
{
    RSaveTreeNode *rstn;
    rstn = RSAVE_TREE_NODE(object_new(TYPE_RSAVE_TREE_NODE));
    return rstn; 
}

static void rsave_tree_link_initfn(Object *obj)
{
    RSaveTreeNodeLink *l = RSAVE_TREE_NODE_LINK(obj);

    l->next = NULL;
    l->previous = NULL;
    l->node = NULL;
}

static void rsave_tree_link_finalize(Object *obj)
{
    RSaveTreeNodeLink *l = RSAVE_TREE_NODE_LINK(obj);

    // Stich up the gap
    if(l->previous) {
        l->previous->next = l->next;
    }
    if(l->next){
        l->next->previous = l->previous;
    }

    // Remove this link from the node
    if(l->node){
        QPointer *qptr = NULL;
        QListEntry *qe = NULL;
        
        QLIST_FOREACH_ENTRY(l->node->link_list, qe){
            QPointer *this_qptr = qobject_to(QPointer, qlist_entry_obj(qe));
            RSaveTreeNodeLink* this_link = qpointer_get_pointer(this_qptr);
            if(this_link == l){
                qptr = this_qptr;
                break;
            }
        }

        if(qptr)
        {
            QTAILQ_REMOVE(&l->node->link_list->head, qe, next);
            qobject_unref(qptr);
            g_free(qe);
        }
    }
}

static const TypeInfo rsave_tree_link_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_RSAVE_TREE_NODE_LINK,
    .instance_size = sizeof(RSaveTreeNodeLink),
    .instance_init = rsave_tree_link_initfn,
    .instance_finalize = rsave_tree_link_finalize
};

static void rsave_tree_link_register_types(void)
{
    type_register_static(&rsave_tree_link_info);
}

type_init(rsave_tree_link_register_types);

RSaveTreeNodeLink* rsave_tree_node_link_new(RSaveTreeNodeLink *parent, RSaveTreeNode *node)
{
    RSaveTreeNodeLink *l = RSAVE_TREE_NODE_LINK(object_new(TYPE_RSAVE_TREE_NODE_LINK));
    if(l) {
        l->next = NULL;
        l->previous = parent;
        memcpy(l->hash, node->hash, sizeof(SHA1_HASH_TYPE));

        // Add this new link to the node.
        QPointer *lptr = qpointer_from_pointer(l, NULL);
        qlist_append(node->link_list, lptr);
        l->node = node;

        if(parent){
            parent->next = l;
        }
    }

    return l;
}