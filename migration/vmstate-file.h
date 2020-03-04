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

#ifndef VMSTATE_FILE_H
#define VMSTATE_FILE_H

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu-memory-channel.h"
#include "block/qapi.h"
#include "racomms/racomms-types.h"
#include "migration/rsave-tree-node.h"

#define SEGMENTS_PER_HEADER (1000)

#define TYPE_VMSTATE_FILE "vmstate-file"
#define VMSTATE_FILE(obj)                                            \
    OBJECT_CHECK(VMStateFile, (obj), TYPE_VMSTATE_FILE)
#define VMSTATE_FILE_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(VMStateFileClass, klass, TYPE_VMSTATE_FILE)
#define VMSTATE_FILE_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(VMStateFileClass, obj, TYPE_VMSTATE_FILE)

typedef struct FileSegment       FileSegment; 
typedef struct VMFileHeader      VMFileHeader;
typedef struct VMStateFile       VMStateFile;
typedef struct VMStateFileClass  VMStateFileClass;
typedef struct RSaveTreeNode     RSaveTreeNode;

struct FileSegment {
    SHA1_HASH_TYPE hash;
    int32_t job_id;
    uint64_t segment_pointer;
    size_t segment_size;
}; 

struct VMFileHeader {
    uint64_t num_segments;
    FileSegment segments[SEGMENTS_PER_HEADER];
    uint64_t next_header;
};

struct VMStateFileClass {
    ObjectClass parent;
    void (*add_header)(VMStateFile *file);
    void (*save_data)(VMStateFile *file, RSaveTreeNode *node, uint64_t *out_index, bool nosave);
    bool (*load_from_index)(VMStateFile *file, RSaveTreeNode **node, uint64_t index);
    bool (*load_from_hash)(VMStateFile *file, RSaveTreeNode **node, SHA1_HASH_TYPE hash);
    bool (*load_from_job)(VMStateFile *file, RSaveTreeNode **node, int32_t job_id);
    void (*find_current_header)(VMStateFile *file);
    void (*query_image_info)(VMStateFile *file, ImageInfoList **list);
};

VMStateFile* vmstate_file_new(const char *file_path);

#endif