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

#ifndef QEMU_MEMORY_CHANNEL_H
#define QEMU_MEMORY_CHANNEL_H

#include <string.h>

// TODO remove me
#include <stdio.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "qom/object.h"
#include "qemu-file.h"
#include "qemu/iov.h"
#include "qapi/qmp/qlist.h"

// ************************************************************* //
// **********       Memory Channel Class Setup        ********** //
// ************************************************************* //


#define TYPE_MEMORY_CHANNEL "memory-channel"
#define MEMORY_CHANNEL(obj)                                    \
    OBJECT_CHECK(MemoryChannel, (obj), TYPE_MEMORY_CHANNEL)
#define MEMORY_CHANNEL_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(MemoryChannelClass, klass, TYPE_MEMORY_CHANNEL)
#define MEMORY_CHANNEL_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(MemoryChannelClass, obj, TYPE_MEMORY_CHANNEL)

typedef struct MemoryChannel MemoryChannel;
typedef struct MemoryChannelClass MemoryChannelClass;

struct MemoryChannel {
    Object obj;
    QEMUIOVector iov_list;
    QList *used_allocations;
    size_t main_size;
    size_t main_iovs;
    size_t meta_size;
    size_t meta_iovs;
    int64_t iov_pos;
};

struct MemoryChannelClass {
    ObjectClass parent;
    void (*write_to_file)(MemoryChannel *mc, FILE *fp);
    void (*read_from_file)(MemoryChannel *mc, FILE *fp, size_t image_size);
    void (*remove_meta)(MemoryChannel *mc);
    void (*add_meta)(MemoryChannel *mc, void *buf, size_t size);
    size_t (*get_stream)(MemoryChannel *mc, QEMUIOVector **qiov);
    size_t (*get_size)(MemoryChannel *mc);
    ssize_t (*get_buffer)(void *opaque, uint8_t *buf, int64_t pos, size_t size);
    ssize_t (*writev_buffer)(void *opaque, struct iovec *iov, int iovcnt, int64_t pos);
    int (*close)(void *opaque);
};

extern const QEMUFileOps memory_channel_input_ops;
extern const QEMUFileOps memory_channel_output_ops;

// ************************************************************* //
// **********                Helpers                  ********** //
// ************************************************************* //

/**
 * Creates a new memory channel.
 */
MemoryChannel* memory_channel_create(void);
void memory_channel_alloc_pool(size_t pool_size, size_t pool_limit);
void memory_channel_free_pool(void);
bool memory_channel_test_and_set_pool_limit(void);

#endif