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

#include "qemu-memory-channel.h"
#include "qapi/qmp/qpointer.h"
#include "qemu/error-report.h"
#include "cromulence/debug.h"

#define MAX_IOV_SIZE      (262144)
#define MAX_IOVS_IN_CHUNK (40)

typedef struct MemoryChannelGlobalState{
    QList *pool_allocations;
    size_t pool_limit;
    size_t pool_size;
    size_t pool_used;
} MemoryChannelGlobalState;

static MemoryChannelGlobalState *global_mc = NULL;

// ************************************************************* //
// **********       Memory Channel Class Setup        ********** //
// ************************************************************* //

static void qemu_memory_channel_write_to_file(MemoryChannel *mc, FILE *fd)
{
    // Loop over the nodes and dump data to the file
    for (size_t i = 0; i < mc->main_iovs; ++i)
    {
        // Write the IOVs to the file.
        fwrite(mc->iov_list.iov[i].iov_base, sizeof(uint8_t), mc->iov_list.iov[i].iov_len, fd);
    }
}

static size_t reserved_size(MemoryChannel *mc)
{
    return mc->iov_list.niov;
}

static void allocate_chunks(size_t pool_size)
{
    // Align the pool size to a factor of the chunk size (rounding up).
    size_t num_chunks = (pool_size + MAX_IOVS_IN_CHUNK * MAX_IOV_SIZE - 1) / (MAX_IOVS_IN_CHUNK * MAX_IOV_SIZE);
    for(int chunk = 0; chunk < num_chunks; chunk++)
    {
        // Add allocations to our global pool.
        void *chunk_base = g_malloc0(MAX_IOVS_IN_CHUNK * MAX_IOV_SIZE);
        qlist_append(global_mc->pool_allocations, qpointer_from_pointer(chunk_base, NULL));
    }
    global_mc->pool_size += num_chunks * MAX_IOVS_IN_CHUNK * MAX_IOV_SIZE;
}

static void add_iovs(MemoryChannel *mc, size_t new_iovs)
{
    // Allocate the total memory for this group of iovs
    const int num_chunks = (new_iovs + MAX_IOVS_IN_CHUNK - 1) / MAX_IOVS_IN_CHUNK;

    // Split our iov allocations in chunks
    // This will speed up allocation and improve cache efficiency
    for(int chunk = 0; chunk < num_chunks; chunk++)
    {
        QPointer *iov_qptr = NULL;
        if( qlist_empty(global_mc->pool_allocations) )
        {
            iov_qptr = qpointer_from_pointer(g_malloc0(MAX_IOVS_IN_CHUNK * MAX_IOV_SIZE), NULL);
            global_mc->pool_size += MAX_IOVS_IN_CHUNK * MAX_IOV_SIZE;
        }else{
            iov_qptr = qobject_to(QPointer, qlist_pop(global_mc->pool_allocations));
        }

        if(iov_qptr){
            // Save our raw allocation so we can free it during finalize
            global_mc->pool_used += MAX_IOVS_IN_CHUNK * MAX_IOV_SIZE;
            qlist_append(mc->used_allocations, iov_qptr);
            uint8_t *iov_base = qpointer_get_pointer(iov_qptr);
            for(size_t i = 0; i < MAX_IOVS_IN_CHUNK; i++ )
            {
                // Add a chunk of the allocation to the iov list and zero the length
                qemu_iovec_add(&mc->iov_list, &iov_base[i * MAX_IOV_SIZE], 0);
            }
        }else{
            error_report("%s: failed to allocate iov @ line %d\n", __func__, __LINE__);
        }
    }
}

static size_t add_meta_memory(MemoryChannel *mc, size_t added_size)
{
    // Pre-allocate our qiov (meta data is appended at the end of the qiov)
    int new_meta_iovs = (added_size + MAX_IOV_SIZE - 1) / MAX_IOV_SIZE;
    int new_num_iovs = new_meta_iovs + mc->main_iovs + mc->meta_iovs;
    qemu_iovec_resize(&mc->iov_list, new_num_iovs);

    // Reset the lengths of our existing *meta* iovs that we're going to use
    int allocated_iovs = MIN(new_num_iovs, reserved_size(mc));
    int meta_start = mc->main_iovs + mc->meta_iovs;
    for (size_t i = meta_start; i < allocated_iovs; ++i)
    {
        mc->iov_list.iov[i].iov_len = 0;
    }

    // Now allocate the rest of the iovs
    if( allocated_iovs < new_num_iovs )
    {
        add_iovs(mc, new_num_iovs - allocated_iovs);
    }

    return new_meta_iovs;
}

static size_t add_main_memory(MemoryChannel *mc, size_t added_size)
{
    // Pre-allocate our qiov
    int new_main_iovs = (added_size + MAX_IOV_SIZE - 1) / MAX_IOV_SIZE;
    int new_num_iovs = new_main_iovs + mc->main_iovs;
    qemu_iovec_resize(&mc->iov_list, new_num_iovs);

    // Reset the lengths of our existing iovs that we're going to use
    int allocated_iovs = MIN(new_num_iovs, reserved_size(mc));
    for (size_t i = mc->main_iovs; i < allocated_iovs; ++i)
    {
        mc->iov_list.iov[i].iov_len = 0;
    }

    // Now allocate the rest of the iovs
    if( allocated_iovs < new_num_iovs )
    {
        add_iovs(mc, new_num_iovs - allocated_iovs);
    }

    return new_main_iovs;
}

static size_t set_main_memory(MemoryChannel *mc, size_t new_size)
{
    // Pre-allocate our qiov
    int new_num_iovs = (new_size + MAX_IOV_SIZE - 1) / MAX_IOV_SIZE;
    qemu_iovec_resize(&mc->iov_list, new_num_iovs);

    // Reset the lengths of our existing iovs that we're going to use
    int allocated_iovs = MIN(new_num_iovs, reserved_size(mc));
    for (size_t i = 0; i < allocated_iovs; ++i)
    {
        mc->iov_list.iov[i].iov_len = 0;
    }

    // Now allocate the rest of the iovs
    if( allocated_iovs < new_num_iovs )
    {
        add_iovs(mc, new_num_iovs - allocated_iovs);
    }

    return new_num_iovs;
}

static void qemu_memory_channel_read_from_file(MemoryChannel *mc, FILE *file, size_t image_size)
{
    // Allocate enough iovs to handle our image_size
    set_main_memory(mc, image_size);

    // Loading memory from a channel works by requesting available memory
    // If the current request needs more memory than we have loaded, QEMU will
    // ask the channel for more. With that said, there is no requirement to honor
    // original IOV boundries here. We'll use an arbitrary IOV size and it should
    // work out through the load process.
    mc->meta_size = 0;
    mc->meta_iovs = 0;
    mc->main_iovs = 0;
    mc->main_size = 0;
    mc->iov_pos = 0;
    do
    {
        // Calculate the current iov and it's offset
        size_t iov_pos = mc->main_size / MAX_IOV_SIZE;
        size_t iov_offset = mc->main_size - (iov_pos * MAX_IOV_SIZE);

        // We want to read the smaller of the remaining image and remaining buffer size.
        size_t bytes_left = MIN(image_size - mc->main_size, MAX_IOV_SIZE - iov_offset);
        struct iovec *cur_vec = &mc->iov_list.iov[iov_pos];
        uint8_t *cur_offset = &((uint8_t*)cur_vec->iov_base)[iov_offset];

        // Start by filling the buffer from the file.
        size_t bytes_read = fread(cur_offset, sizeof(uint8_t), bytes_left, file);
        if (bytes_read == 0){
            error_report("%s: failed to receive data @ line %d\n", __func__, __LINE__);
            return;
        }

        cur_vec->iov_len += bytes_read;
        mc->main_size += bytes_read;
        mc->main_iovs++;
    } while(mc->main_size < image_size);
}

static void qemu_memory_channel_remove_meta(MemoryChannel *mc)
{
    mc->meta_size = 0;
    mc->meta_iovs = 0;
}

static void qemu_memory_channel_add_meta(MemoryChannel *mc, void *buf, size_t size)
{
    // Allocate enough iovs to handle our meta data size
    size_t size_in_iov = add_meta_memory(mc, size);

    size_t meta_start = mc->main_iovs + mc->meta_iovs;

    // Set the size for these iovs
    for( size_t i = 0; i < size_in_iov; i++ ){
        mc->iov_list.iov[meta_start+i].iov_len = MIN(MAX_IOV_SIZE, size - (i * MAX_IOV_SIZE));
    }
    // Copy data into the iovs
    size_t copied = iov_from_buf(&mc->iov_list.iov[meta_start], size_in_iov, 0, buf, size );
    if( copied != size ){
        error_report("%s: copied fewer than intended bytes @ line %d\n", __func__, __LINE__);
    }

    mc->meta_iovs += size_in_iov;
    mc->meta_size += size;
}

static size_t qemu_memory_channel_get_stream(MemoryChannel *mc, QEMUIOVector **qiov)
{
    *qiov = &mc->iov_list;
    return (mc->main_iovs + mc->meta_iovs);
}

static size_t qemu_memory_channel_get_size(MemoryChannel *mc)
{
    return mc->main_size;
}

// ************************************************************* //
// **********             I/O Operations              ********** //
// ************************************************************* //

static size_t qemu_memory_channel_find_offset(MemoryChannel *mc, int64_t pos)
{

    mc->iov_pos = pos / MAX_IOV_SIZE;
    return (pos - (mc->iov_pos * MAX_IOV_SIZE));
}

static ssize_t qemu_memory_channel_get_buffer(void *opaque,
                                         uint8_t *buf,
                                         int64_t pos,
                                         size_t size)
{
    // We don't have to fill the buffer. The data we provide will be used and
    // we will be asked for more once the data we provide is used. With that in
    // mind, we'll only send up one IOV.
    MemoryChannel *mc = MEMORY_CHANNEL(opaque);
    size_t total_copied = 0;

    // Find the respective iov and offset for this pos
    size_t offset = qemu_memory_channel_find_offset(mc, pos);

    // If the current position in the iov list is valid...
    if (mc->iov_pos < mc->main_iovs) {

        struct iovec *cur_iov = (struct iovec *) &mc->iov_list.iov[mc->iov_pos];

        // Copy the iov to the buffer
        size_t copied = iov_to_buf(cur_iov, (mc->main_iovs - mc->iov_pos), offset, buf, size);

        // We will report to the caller the amount copied.
        total_copied = copied;
    }

    // Done!
    return total_copied;
}

static ssize_t qemu_memory_channel_writev_buffer(void *opaque,
                                            struct iovec *iov,
                                            int iovcnt,
                                            int64_t pos)
{
    MemoryChannel *mc = MEMORY_CHANNEL(opaque);

    // This needs to be a direct copy instead...

    // Meta data is not preserved
    mc->meta_size = 0;
    mc->meta_iovs = 0;

    int cur_iov = 0;
    size_t iov_copied = 0;
    size_t total_copied = 0;
    while( cur_iov < iovcnt )
    {
        // Find the respective iov and offset for this pos
        size_t offset = qemu_memory_channel_find_offset(mc, pos + total_copied);

        // Do we already have memory at this iov position?
        if (mc->iov_pos >= mc->main_iovs) {
            // Nope, see if we need to reserve more iovs.
            size_t added_size = iov_size(&iov[cur_iov], iovcnt - cur_iov) - iov_copied + offset;
            size_t skipped_size = (mc->iov_pos - mc->main_iovs) * MAX_IOV_SIZE;
            size_t total_size = added_size + skipped_size;
            size_t num_iovs = add_main_memory(mc, total_size);

            // Make the last iov in the iov_list the max size.
            if(mc->main_iovs > 0){
                mc->iov_list.iov[mc->main_iovs-1].iov_len = MAX_IOV_SIZE;
            }

            // Then proceed to set the rest of the sizes.
            for( int64_t i = 0; i < num_iovs; i++ ){
                mc->iov_list.iov[mc->main_iovs+i].iov_len = MIN(MAX_IOV_SIZE, total_size - (i * MAX_IOV_SIZE));
            }

            // Increase our max iovs used.
            mc->main_size += total_size;
            mc->main_iovs += num_iovs;
        }else if( mc->iov_pos == (mc->main_iovs - 1) ){
            // We're writing into the last iov so may need to increase its size.
            size_t last_iov_size = MIN(offset + iov[cur_iov].iov_len - iov_copied, MAX_IOV_SIZE);
            if( last_iov_size > mc->iov_list.iov[mc->main_iovs-1].iov_len )
            {
                // Increase the size.
                mc->main_size += last_iov_size - mc->iov_list.iov[mc->main_iovs-1].iov_len;
                mc->iov_list.iov[mc->main_iovs-1].iov_len = last_iov_size;
            }
        }

        // Continue writing our iovs.
        size_t copied = iov_from_buf(&mc->iov_list.iov[mc->iov_pos], 1, offset,
                                    iov[cur_iov].iov_base + iov_copied, iov[cur_iov].iov_len - iov_copied );
        iov_copied += copied;
        total_copied += copied;

        if( iov_copied >= iov[cur_iov].iov_len ){
            iov_copied = 0;
            cur_iov++;
        }
    }

    return total_copied;
}

static int qemu_memory_channel_close(void *opaque)
{
    MemoryChannel *mc = MEMORY_CHANNEL(opaque);

    // Reset our iov pos, otherwise leave the data untouched.
    // This assumes we don't write, close, write or...
    // don't read, close, write.
    mc->iov_pos = 0;

    return 0;
}

const QEMUFileOps memory_channel_input_ops = {
    .get_buffer = qemu_memory_channel_get_buffer,
    .close = qemu_memory_channel_close
};

const QEMUFileOps memory_channel_output_ops = {
    .writev_buffer  = qemu_memory_channel_writev_buffer,
    .close          = qemu_memory_channel_close
};

static void memory_channel_initfn(Object *obj)
{
    MemoryChannel *mc = MEMORY_CHANNEL(obj);

    // This will hold our raw allocations
    mc->used_allocations = qlist_new();

    // Inc the refcount because we're using the pool.
    qobject_ref(global_mc->pool_allocations);

    // Pre-allocate one chunks worth of iovs
    qemu_iovec_init(&mc->iov_list, MAX_IOVS_IN_CHUNK);

    // The total number of used iovs in iov_list
    mc->main_iovs = 0;
    // The total size of all iovs in iov_list
    mc->main_size = 0;
    // Our current index into the iov_list
    mc->iov_pos = 0;
    // The number of meta iovs used in the iov_list
    mc->meta_iovs = 0;
    // The total size of meta data in the iov_list
    mc->meta_size = 0;
}

static void memory_channel_finalize(Object *obj)
{
    QListEntry *e;

    // Capture the MC object
    MemoryChannel *mc = MEMORY_CHANNEL(obj);

    // Inc the refcount for the qpointers and assign to the free pool.
    QLIST_FOREACH_ENTRY(mc->used_allocations, e){
        QPointer *qptr = qobject_to(QPointer, qlist_entry_obj(e));
        qobject_ref(qptr);
        qlist_append(global_mc->pool_allocations, qptr);
        global_mc->pool_used -= MAX_IOVS_IN_CHUNK * MAX_IOV_SIZE;
    }

    // Dec the refcount because we're not using the pool anymore.
    qobject_unref(global_mc->pool_allocations);

    // This will free all the entries but not the qpointers...
    qobject_unref(mc->used_allocations);

    qemu_iovec_destroy(&mc->iov_list);

    // reset everything
    mc->meta_iovs = 0;
    mc->meta_size = 0;
    mc->main_iovs = 0;
    mc->main_size = 0;
    mc->iov_pos = 0;
}

static void memory_channel_class_init(ObjectClass *klass,
                                      void *class_data G_GNUC_UNUSED)
{
    MemoryChannelClass *mc_klass = MEMORY_CHANNEL_CLASS(klass);
    mc_klass->write_to_file = qemu_memory_channel_write_to_file;
    mc_klass->read_from_file = qemu_memory_channel_read_from_file;
    mc_klass->remove_meta = qemu_memory_channel_remove_meta;
    mc_klass->add_meta = qemu_memory_channel_add_meta;
    mc_klass->get_stream = qemu_memory_channel_get_stream;
    mc_klass->get_buffer = qemu_memory_channel_get_buffer;
    mc_klass->get_size = qemu_memory_channel_get_size;
    mc_klass->writev_buffer = qemu_memory_channel_writev_buffer;
    mc_klass->close = qemu_memory_channel_close;
}

static const TypeInfo memory_channel_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_MEMORY_CHANNEL,
    .instance_size = sizeof(MemoryChannel),
    .instance_init = memory_channel_initfn,
    .instance_finalize = memory_channel_finalize,
    .class_init = memory_channel_class_init,
    .class_size = sizeof(MemoryChannelClass)
};

static void memory_channel_register_types(void)
{
    type_register_static(&memory_channel_info);
}

type_init(memory_channel_register_types);

// ************************************************************* //
// **********                Helpers                  ********** //
// ************************************************************* //

MemoryChannel* memory_channel_create(void)
{
    // Variables!
    MemoryChannel *mc;
    
    // Initialization!
    mc = MEMORY_CHANNEL(object_new(TYPE_MEMORY_CHANNEL));

    // Thats it!
    return mc;
}

void memory_channel_alloc_pool(size_t pool_size, size_t pool_limit)
{
    if( !global_mc ) {
        global_mc = g_new0(MemoryChannelGlobalState, 1);
        global_mc->pool_allocations = qlist_new();
        global_mc->pool_limit = pool_limit;
        global_mc->pool_size = 0;
        global_mc->pool_used = 0;

        allocate_chunks(pool_size);
    }
}

void memory_channel_free_pool(void)
{
    if( global_mc ){
        qobject_unref(global_mc->pool_allocations);
        g_free(global_mc);
        global_mc = NULL;
    }
}

bool memory_channel_test_and_set_pool_limit(void)
{
    if( global_mc->pool_limit != 0 && global_mc->pool_used > global_mc->pool_limit )
    {
        return true;
    }

    return false;
}
