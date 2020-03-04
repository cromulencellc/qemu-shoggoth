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

#ifndef INDEXED_FILE_H
#define INDEXED_FILE_H

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/object.h"
#include "block/qapi.h"
#include "racomms/racomms-types.h"

#define SEGMENTS_PER_HEADER (1000)

#define TYPE_INDEXED_FILE "indexed-file"
#define INDEXED_FILE(obj)                                            \
    OBJECT_CHECK(IndexedFile, (obj), TYPE_INDEXED_FILE)
#define INDEXED_FILE_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(IndexedFileClass, klass, TYPE_INDEXED_FILE)
#define INDEXED_FILE_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(IndexedFileClass, obj, TYPE_INDEXED_FILE)

typedef struct IndexedFileSegment  IndexedFileSegment; 
typedef struct FileIndex           FileIndex;
typedef struct IndexedFile         IndexedFile;
typedef struct IndexedFileClass    IndexedFileClass;
typedef struct IFVisitor           IFVisitor;

struct IndexedFileSegment {
    SHA1_HASH_TYPE hash;
    uint32_t reserved;
    uint64_t segment_pointer;
    size_t segment_size;
}; 

struct FileIndex {
    uint64_t num_segments;
    IndexedFileSegment segments[SEGMENTS_PER_HEADER];
    uint64_t next_header;
};

struct IndexedFile {
    Object obj; 
    FILE *fp;
    uint64_t current_header_loc;
};

struct IFVisitor {
    void *opaque;
    void (*if_read)(void *opaque, FILE *fp, size_t read_size_hint, SHA1_HASH_TYPE *hash);
    void (*if_write)(void *opaque, FILE *fp);
    void (*calculate_hash)(void *opaque, SHA1_HASH_TYPE *hash);
};

struct IndexedFileClass {
    ObjectClass parent;
    void (*add_header)(IndexedFile *file);
    void (*write_data)(IndexedFile *file, IFVisitor *visitor, SHA1_HASH_TYPE *out_hash, uint64_t *out_index);
    bool (*load_from_index)(IndexedFile *file, IFVisitor *visitor, uint64_t index);
    bool (*load_from_hash)(IndexedFile *file, IFVisitor *visitor, SHA1_HASH_TYPE hash);
    void (*find_current_header)(IndexedFile *file);
    void (*query_image_info)(IndexedFile *file, ImageInfoList **list);
    int64_t (*get_length)(IndexedFile *file);
};

IndexedFile* indexed_file_new(const char *file_path);

#endif
