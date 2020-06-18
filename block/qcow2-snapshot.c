/*
 * Block driver for the QCOW version 2 format
 *
 * Copyright (c) 2004-2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "block/block_int.h"
#include "qcow2.h"
#include "qemu/bswap.h"
#include "qemu/error-report.h"
#include "qemu/cutils.h"

//#define DUMP_DEBUG


typedef struct QCow2Dump {
    uint64_t l1_table_size;
    uint64_t *l1_table;
    uint64_t num_entries;
    QLIST_HEAD(dump_entries, QCow2DumpRecord) dump_entries;
} QCow2Dump;

typedef struct QCow2DumpRecord {
    uint64_t l1_index;
    uint64_t l2_offset;
    uint64_t l2_slice_mod;
    uint64_t entry_count;
    QLIST_HEAD(slice_entries, QCow2DumpSliceEntry) slice_entries;
    QLIST_ENTRY(QCow2DumpRecord) next;
} QCow2DumpRecord;

typedef struct QCow2DumpSliceEntry {
    uint64_t entry_index;
    uint64_t slice_index;
    uint64_t data_offset;
    uint64_t data_size;
    void *data;
    QLIST_ENTRY(QCow2DumpSliceEntry) next;
} QCow2DumpSliceEntry;

static int add_dump_record(QCow2Dump *dump, QCow2DumpRecord *record)
{
    int ret_val = -EFBIG;
    if (dump && record)
    {
        dump->num_entries++;
        QLIST_INSERT_HEAD(&dump->dump_entries, record, next);
        ret_val = 0;
    }
    return ret_val;
}

static int add_slice_entry(QCow2DumpRecord *record, QCow2DumpSliceEntry *entry)
{
    int ret_val = -EFBIG;
    if (record && entry)
    {
        record->entry_count++;
        QLIST_INSERT_HEAD(&record->slice_entries, entry, next);
        ret_val = 0;
    }
    return ret_val;
}

static int serialize_slice_entry(QCow2DumpSliceEntry *entry, uint8_t **buffer, uint64_t *size)
{
    int ret = -EFBIG;
    uint8_t *write_buff;
    uint32_t data_size = sizeof(entry->entry_index) +
                         sizeof(entry->slice_index) + 
                         sizeof(entry->data_offset) + 
                         sizeof(entry->data_size) +
                         entry->data_size;

    *buffer = g_realloc(*buffer, *size +  data_size);
    
    if (*buffer)
    {
        write_buff = *buffer + *size;
        *size += data_size;

        memcpy(write_buff, &entry->entry_index, sizeof(entry->entry_index));
        write_buff += sizeof(entry->entry_index);

        memcpy(write_buff, &entry->slice_index, sizeof(entry->slice_index));
        write_buff += sizeof(entry->slice_index);

        memcpy(write_buff, &entry->data_offset, sizeof(entry->data_offset));
        write_buff += sizeof(entry->data_offset);

        memcpy(write_buff, &entry->data_size, sizeof(entry->data_size));
        write_buff += sizeof(entry->data_size);

        memcpy(write_buff, entry->data, entry->data_size);
        write_buff += entry->data_size;
        
        ret = 0;
    }
    return ret;
}

static int serialize_dump_record(QCow2DumpRecord *record, uint8_t **buffer, uint64_t *size)
{
    int ret = -EFBIG;
    uint8_t *write_buff;
    uint32_t data_size = sizeof(record->l1_index) + 
                         sizeof(record->l2_offset) + 
                         sizeof(record->l2_slice_mod) +
                         sizeof(record->entry_count);

    *buffer = g_realloc(*buffer, *size +  data_size);
 
    if (*buffer)
    {
        QCow2DumpSliceEntry *slice;

        write_buff = *buffer + *size;
        *size += data_size;

        memcpy(write_buff, &record->l1_index, sizeof(record->l1_index));
        write_buff += sizeof(record->l1_index);

        memcpy(write_buff, &record->l2_offset, sizeof(record->l2_offset));
        write_buff += sizeof(record->l2_offset);

        memcpy(write_buff, &record->l2_slice_mod, sizeof(record->l2_slice_mod));
        write_buff += sizeof(record->l2_slice_mod);

        memcpy(write_buff, &record->entry_count, sizeof(record->entry_count));
        write_buff += sizeof(record->entry_count);

        QLIST_FOREACH(slice, &record->slice_entries, next)
        {
            ret = serialize_slice_entry(slice, buffer, size);
            if (ret != 0)
            {
                break;
            }
        }        
    }
    return ret;
}

static int serialize_dump(QCow2Dump *dump, uint8_t **buffer, uint64_t *size)
{
    int ret = -EFBIG;
    uint8_t *write_buff;
    uint64_t l1_bytes = sizeof(uint64_t) * dump->l1_table_size;
    uint32_t data_size = sizeof(dump->l1_table_size) +
                         l1_bytes +
                         sizeof(dump->num_entries);

    *size = 0;
    if (*buffer)
    {
        *buffer = g_realloc(*buffer, *size + data_size);
    }
    else
    {
        *buffer = g_new(uint8_t, data_size); 
    }

    if (*buffer)
    {
        QCow2DumpRecord *rec;

        write_buff = *buffer;
        *size += data_size;

        memcpy(write_buff, &dump->l1_table_size, sizeof(dump->l1_table_size));
        write_buff += sizeof(dump->l1_table_size); 

        memcpy(write_buff, dump->l1_table, l1_bytes);
        write_buff += l1_bytes; 

        memcpy(write_buff, &dump->num_entries, sizeof(dump->num_entries));
        write_buff += sizeof(dump->num_entries);        

        QLIST_FOREACH(rec, &dump->dump_entries, next)
        {
            ret = serialize_dump_record(rec, buffer, size);
            if (ret != 0)
            {
                break;
            }
        }
    }

    return ret;
}

static int deserialize_slice_entry(QCow2DumpSliceEntry *entry, uint8_t *buffer, uint64_t *size)
{
    int ret = -EFBIG;
    uint8_t *read_buff = buffer;
    uint32_t initial_read_size = sizeof(entry->entry_index) +  
                                 sizeof(entry->slice_index) +
                                 sizeof(entry->data_offset) +
                                 sizeof(entry->data_size);
 

    if (*size >= initial_read_size)
    {
        *size -= initial_read_size;

        memcpy(&entry->entry_index, read_buff, sizeof(entry->entry_index));
        read_buff += sizeof(entry->entry_index);

        memcpy(&entry->slice_index, read_buff, sizeof(entry->slice_index));
        read_buff += sizeof(entry->slice_index);
        
        memcpy(&entry->data_offset, read_buff, sizeof(entry->data_offset));
        read_buff += sizeof(entry->data_offset);

        memcpy(&entry->data_size, read_buff, sizeof(entry->data_size));
        read_buff += sizeof(entry->data_size);
    }

    if (*size >= entry->data_size)
    {
        entry->data = g_new(uint8_t, entry->data_size);
        memcpy(entry->data, read_buff, entry->data_size);
        *size -= entry->data_size;
        ret = 0;
    }
    return ret;
}

static int deserialize_dump_record(QCow2DumpRecord *record, uint8_t *buffer, uint64_t *size)
{
    int i, ret = -EFBIG;
    uint8_t *read_buff = buffer;
    uint64_t recs;
    uint32_t initial_read_size = sizeof(record->l1_index) +
                                 sizeof(record->l2_offset) +
                                 sizeof(record->l2_slice_mod) +
                                 sizeof(record->entry_count);


    record->entry_count = 0;

    if (*size >= initial_read_size)
    {
        *size -= initial_read_size; 

        memcpy(&record->l1_index, read_buff, sizeof(record->l1_index));
        read_buff += sizeof(record->l1_index);
           
        memcpy(&record->l2_offset, read_buff, sizeof(record->l2_offset));
        read_buff += sizeof(record->l2_offset);

        memcpy(&record->l2_slice_mod, read_buff, sizeof(record->l2_slice_mod));
        read_buff += sizeof(record->l2_slice_mod);

        memcpy(&recs, read_buff, sizeof(recs));
        read_buff += sizeof(recs);

        QCow2DumpSliceEntry *entry;
        QLIST_INIT(&record->slice_entries);

        for (i = 0; i < recs; ++i)
        {
            entry = g_new0(QCow2DumpSliceEntry, 1);

            uint64_t delta_size = *size;
            ret = deserialize_slice_entry(entry, read_buff, size);
            if (ret != 0)
            {
                break;
            }

            delta_size -= *size;
            read_buff += delta_size;
            
            ret = add_slice_entry(record, entry);
            if (ret != 0)
            {
                break;
            }
        }    
    }
    return ret;                                                     
}

static int deserialize_dump(QCow2Dump *dump, uint8_t *buffer, uint64_t size)
{    
    int i, ret = -EFBIG;
    uint8_t *read_buff = buffer;
    uint64_t ents, size_remaining = size;
    uint32_t l1_size_size = sizeof(dump->l1_table_size);
    uint32_t initial_read_size = sizeof(dump->num_entries);

    if (size_remaining >= l1_size_size)
    {
        memcpy(&dump->l1_table_size, read_buff, l1_size_size);
        read_buff += l1_size_size;
        size_remaining -= l1_size_size;

        if (size_remaining >= dump->l1_table_size)
        {
            uint64_t l1_bytes = sizeof(uint64_t) * dump->l1_table_size;

            dump->l1_table = g_new0(uint64_t, dump->l1_table_size);
            memcpy(dump->l1_table, read_buff, l1_bytes);
            read_buff += l1_bytes;
            size_remaining -= l1_bytes;
            ret = 0;
        }
    }

    dump->num_entries = 0;

    if (size_remaining >= initial_read_size && ret == 0)
    {
        ret = -EFBIG; 
        size_remaining -= initial_read_size; 

        memcpy(&ents, read_buff, sizeof(ents));
        read_buff += sizeof(ents);

        QCow2DumpRecord *records;
        QLIST_INIT(&dump->dump_entries);

        for (i = 0; i < ents; ++i)
        {
            records = g_new0(QCow2DumpRecord, 1);

            uint64_t delta_size = size_remaining;
            ret = deserialize_dump_record(records, read_buff, &size_remaining);
            if (ret != 0)
            {
                break;
            }

            delta_size -= size_remaining;
            read_buff += delta_size;

            ret = add_dump_record(dump, records);
            if (ret != 0)
            {
                break;
            }
        }
    }
    return ret;
}

#ifdef DUMP_DEBUG

static void pretty_print_slice_entry(QCow2DumpSliceEntry *slice)
{
    int x;
    printf("\t\tSlice Entry:\n");
    printf("\t\tEntry Index: %lu\n", slice->entry_index); 
    printf("\t\tSlice Index: %lu\n", slice->slice_index);
    printf("\t\tData Offset: %lx\n", slice->data_offset);
    printf("\t\tData Size: %lx\n", slice->data_size);
    printf("\t\tData:");
    for (x = 0; x < 32; ++x)
    {
        if (x % 32 == 0) printf("\n\t\t\t");
        printf("%.2x", ((uint8_t *)slice->data)[x]);
    }
    printf("\n");
}

static void pretty_print_dump_record(QCow2DumpRecord *rec)
{
    QCow2DumpSliceEntry *slice;

    printf("\tRecord:\n");
    printf("\tL1 Index: %lu\n", rec->l1_index);
    printf("\tL2 Offset: %lx\n", rec->l2_offset);
    printf("\tL2 Slize Location: %lx\n", rec->l2_slice_mod);
    printf("\tNumber of slice entries: %lu\n", rec->entry_count);
    QLIST_FOREACH(slice, &rec->slice_entries, next)
    {
        pretty_print_slice_entry(slice);
    }
}

static void pretty_print_dump(QCow2Dump *dump)
{
    int x;
    QCow2DumpRecord *rec;

    printf("Dump Data:\n");
    printf("L1 Table Size: %lu\n", dump->l1_table_size);
    printf("L1 Table:\n");
    for (x = 0; x < dump->l1_table_size; ++x )
    {
        printf("\t%.16lx\n", dump->l1_table[x]);
    }
    printf("Number of entries: %lu\n", dump->num_entries);
    QLIST_FOREACH(rec, &dump->dump_entries, next)
    {
        pretty_print_dump_record(rec);
    }
}

#endif

static void free_dump_memory(QCow2Dump *dump)
{
    QCow2DumpRecord *rec, *rec_next;

    dump->l1_table_size = 0;
    g_free(dump->l1_table);

    dump->num_entries = 0;
    QLIST_FOREACH_SAFE(rec, &dump->dump_entries, next, rec_next)
    {
        QCow2DumpSliceEntry *slice, *slice_next;
        QLIST_FOREACH_SAFE(slice, &rec->slice_entries, next, slice_next)
        {
            g_free(slice->data);
            QLIST_REMOVE(slice, next);
            g_free(slice);
        }

        QLIST_REMOVE(rec, next);
        g_free(rec);
    }
}

void qcow2_free_snapshots(BlockDriverState *bs)
{
    BDRVQcow2State *s = bs->opaque;
    int i;

    for(i = 0; i < s->nb_snapshots; i++) {
        g_free(s->snapshots[i].name);
        g_free(s->snapshots[i].id_str);
    }
    g_free(s->snapshots);
    s->snapshots = NULL;
    s->nb_snapshots = 0;
}

int qcow2_read_snapshots(BlockDriverState *bs)
{
    BDRVQcow2State *s = bs->opaque;
    QCowSnapshotHeader h;
    QCowSnapshotExtraData extra;
    QCowSnapshot *sn;
    int i, id_str_size, name_size;
    int64_t offset;
    uint32_t extra_data_size;
    int ret;

    if (!s->nb_snapshots) {
        s->snapshots = NULL;
        s->snapshots_size = 0;
        return 0;
    }

    offset = s->snapshots_offset;
    s->snapshots = g_new0(QCowSnapshot, s->nb_snapshots);

    for(i = 0; i < s->nb_snapshots; i++) {
        /* Read statically sized part of the snapshot header */
        offset = ROUND_UP(offset, 8);
        ret = bdrv_pread(bs->file, offset, &h, sizeof(h));
        if (ret < 0) {
            goto fail;
        }

        offset += sizeof(h);
        sn = s->snapshots + i;
        sn->l1_table_offset = be64_to_cpu(h.l1_table_offset);
        sn->l1_size = be32_to_cpu(h.l1_size);
        sn->vm_state_size = be32_to_cpu(h.vm_state_size);
        sn->date_sec = be32_to_cpu(h.date_sec);
        sn->date_nsec = be32_to_cpu(h.date_nsec);
        sn->vm_clock_nsec = be64_to_cpu(h.vm_clock_nsec);
        extra_data_size = be32_to_cpu(h.extra_data_size);

        id_str_size = be16_to_cpu(h.id_str_size);
        name_size = be16_to_cpu(h.name_size);

        /* Read extra data */
        ret = bdrv_pread(bs->file, offset, &extra,
                         MIN(sizeof(extra), extra_data_size));
        if (ret < 0) {
            goto fail;
        }
        offset += extra_data_size;

        if (extra_data_size >= 8) {
            sn->vm_state_size = be64_to_cpu(extra.vm_state_size_large);
        }

        if (extra_data_size >= 16) {
            sn->disk_size = be64_to_cpu(extra.disk_size);
        } else {
            sn->disk_size = bs->total_sectors * BDRV_SECTOR_SIZE;
        }

        /* Read snapshot ID */
        sn->id_str = g_malloc(id_str_size + 1);
        ret = bdrv_pread(bs->file, offset, sn->id_str, id_str_size);
        if (ret < 0) {
            goto fail;
        }
        offset += id_str_size;
        sn->id_str[id_str_size] = '\0';

        /* Read snapshot name */
        sn->name = g_malloc(name_size + 1);
        ret = bdrv_pread(bs->file, offset, sn->name, name_size);
        if (ret < 0) {
            goto fail;
        }
        offset += name_size;
        sn->name[name_size] = '\0';

        if (offset - s->snapshots_offset > QCOW_MAX_SNAPSHOTS_SIZE) {
            ret = -EFBIG;
            goto fail;
        }
    }

    assert(offset - s->snapshots_offset <= INT_MAX);
    s->snapshots_size = offset - s->snapshots_offset;
    return 0;

fail:
    qcow2_free_snapshots(bs);
    return ret;
}

/* add at the end of the file a new list of snapshots */
static int qcow2_write_snapshots(BlockDriverState *bs)
{
    BDRVQcow2State *s = bs->opaque;
    QCowSnapshot *sn;
    QCowSnapshotHeader h;
    QCowSnapshotExtraData extra;
    int i, name_size, id_str_size, snapshots_size;
    struct {
        uint32_t nb_snapshots;
        uint64_t snapshots_offset;
    } QEMU_PACKED header_data;
    int64_t offset, snapshots_offset = 0;
    int ret;

    /* compute the size of the snapshots */
    offset = 0;
    for(i = 0; i < s->nb_snapshots; i++) {
        sn = s->snapshots + i;
        offset = ROUND_UP(offset, 8);
        offset += sizeof(h);
        offset += sizeof(extra);
        offset += strlen(sn->id_str);
        offset += strlen(sn->name);

        if (offset > QCOW_MAX_SNAPSHOTS_SIZE) {
            ret = -EFBIG;
            goto fail;
        }
    }

    assert(offset <= INT_MAX);
    snapshots_size = offset;

    /* Allocate space for the new snapshot list */
    snapshots_offset = qcow2_alloc_clusters(bs, snapshots_size);
    offset = snapshots_offset;
    if (offset < 0) {
        ret = offset;
        goto fail;
    }
    ret = bdrv_flush(bs);
    if (ret < 0) {
        goto fail;
    }

    /* The snapshot list position has not yet been updated, so these clusters
     * must indeed be completely free */
    ret = qcow2_pre_write_overlap_check(bs, 0, offset, snapshots_size, false);
    if (ret < 0) {
        goto fail;
    }


    /* Write all snapshots to the new list */
    for(i = 0; i < s->nb_snapshots; i++) {
        sn = s->snapshots + i;
        memset(&h, 0, sizeof(h));
        h.l1_table_offset = cpu_to_be64(sn->l1_table_offset);
        h.l1_size = cpu_to_be32(sn->l1_size);
        /* If it doesn't fit in 32 bit, older implementations should treat it
         * as a disk-only snapshot rather than truncate the VM state */
        if (sn->vm_state_size <= 0xffffffff) {
            h.vm_state_size = cpu_to_be32(sn->vm_state_size);
        }
        h.date_sec = cpu_to_be32(sn->date_sec);
        h.date_nsec = cpu_to_be32(sn->date_nsec);
        h.vm_clock_nsec = cpu_to_be64(sn->vm_clock_nsec);
        h.extra_data_size = cpu_to_be32(sizeof(extra));

        memset(&extra, 0, sizeof(extra));
        extra.vm_state_size_large = cpu_to_be64(sn->vm_state_size);
        extra.disk_size = cpu_to_be64(sn->disk_size);

        id_str_size = strlen(sn->id_str);
        name_size = strlen(sn->name);
        assert(id_str_size <= UINT16_MAX && name_size <= UINT16_MAX);
        h.id_str_size = cpu_to_be16(id_str_size);
        h.name_size = cpu_to_be16(name_size);
        offset = ROUND_UP(offset, 8);

        ret = bdrv_pwrite(bs->file, offset, &h, sizeof(h));
        if (ret < 0) {
            goto fail;
        }
        offset += sizeof(h);

        ret = bdrv_pwrite(bs->file, offset, &extra, sizeof(extra));
        if (ret < 0) {
            goto fail;
        }
        offset += sizeof(extra);

        ret = bdrv_pwrite(bs->file, offset, sn->id_str, id_str_size);
        if (ret < 0) {
            goto fail;
        }
        offset += id_str_size;

        ret = bdrv_pwrite(bs->file, offset, sn->name, name_size);
        if (ret < 0) {
            goto fail;
        }
        offset += name_size;
    }

    /*
     * Update the header to point to the new snapshot table. This requires the
     * new table and its refcounts to be stable on disk.
     */
    ret = bdrv_flush(bs);
    if (ret < 0) {
        goto fail;
    }

    QEMU_BUILD_BUG_ON(offsetof(QCowHeader, snapshots_offset) !=
        offsetof(QCowHeader, nb_snapshots) + sizeof(header_data.nb_snapshots));

    header_data.nb_snapshots        = cpu_to_be32(s->nb_snapshots);
    header_data.snapshots_offset    = cpu_to_be64(snapshots_offset);

    ret = bdrv_pwrite_sync(bs->file, offsetof(QCowHeader, nb_snapshots),
                           &header_data, sizeof(header_data));
    if (ret < 0) {
        goto fail;
    }

    /* free the old snapshot table */
    qcow2_free_clusters(bs, s->snapshots_offset, s->snapshots_size,
                        QCOW2_DISCARD_SNAPSHOT);
    s->snapshots_offset = snapshots_offset;
    s->snapshots_size = snapshots_size;
    return 0;

fail:
    if (snapshots_offset > 0) {
        qcow2_free_clusters(bs, snapshots_offset, snapshots_size,
                            QCOW2_DISCARD_ALWAYS);
    }
    return ret;
}

static void find_new_snapshot_id(BlockDriverState *bs,
                                 char *id_str, int id_str_size)
{
    BDRVQcow2State *s = bs->opaque;
    QCowSnapshot *sn;
    int i;
    unsigned long id, id_max = 0;

    for(i = 0; i < s->nb_snapshots; i++) {
        sn = s->snapshots + i;
        id = strtoul(sn->id_str, NULL, 10);
        if (id > id_max)
            id_max = id;
    }
    snprintf(id_str, id_str_size, "%lu", id_max + 1);
}

static int find_snapshot_by_id_and_name(BlockDriverState *bs,
                                        const char *id,
                                        const char *name)
{
    BDRVQcow2State *s = bs->opaque;
    int i;

    if (id && name) {
        for (i = 0; i < s->nb_snapshots; i++) {
            if (!strcmp(s->snapshots[i].id_str, id) &&
                !strcmp(s->snapshots[i].name, name)) {
                return i;
            }
        }
    } else if (id) {
        for (i = 0; i < s->nb_snapshots; i++) {
            if (!strcmp(s->snapshots[i].id_str, id)) {
                return i;
            }
        }
    } else if (name) {
        for (i = 0; i < s->nb_snapshots; i++) {
            if (!strcmp(s->snapshots[i].name, name)) {
                return i;
            }
        }
    }

    return -1;
}

static int find_snapshot_by_id_or_name(BlockDriverState *bs,
                                       const char *id_or_name)
{
    int ret;

    ret = find_snapshot_by_id_and_name(bs, id_or_name, NULL);
    if (ret >= 0) {
        return ret;
    }
    return find_snapshot_by_id_and_name(bs, NULL, id_or_name);
}

int qcow2_dump_state(BlockDriverState *bs, BlockDriverState *target_bs, SHA1_HASH_TYPE hash)
{
    QCow2Dump dump;
    BDRVQcow2State *s = bs->opaque;
    int i, j, /**k,**/ ret; // nclusters = 0;
    uint8_t *storage_buffer = NULL; //, *cluster_buffer = NULL;
    uint64_t *l2_slice = NULL;
    uint64_t offset;

    // Does the target support this?
    if (target_bs->drv->bdrv_receive_dump)
    {
        uint64_t l1_size2;

        // Initialize the record
        dump.num_entries = 0;
        QLIST_INIT(&dump.dump_entries);
        
        // We will load the L1 table from file
        dump.l1_table_size = s->l1_size;
        l1_size2 = s->l1_size * sizeof(uint64_t);
        dump.l1_table = g_try_malloc0(ROUND_UP(l1_size2, 512)); //TODO free me?
        ret = bdrv_pread(bs->file, s->l1_table_offset, dump.l1_table, l1_size2);
        if (!ret)
        {
            goto failed;
        }
        // Correct indian-ness
        for (i = 0; i < dump.l1_table_size; i++) 
        {
            be64_to_cpus(&dump.l1_table[i]);
        }            

        // Loop over L1 table entries
        for (i = 0; i < dump.l1_table_size; ++i)
        {
            // Calculate l2 slice offset
            uint64_t l2_offset = dump.l1_table[i] & L1E_OFFSET_MASK; // l2 offset may change - possibly shouldn't store

            // Check for success
            if (l2_offset)
            {
                
                // Calculate the number of L2 slices
                // and L2 slice size
                unsigned slice, slice_size2, n_slices;   
                slice_size2 = s->l2_slice_size * sizeof(uint64_t);
                n_slices = s->cluster_size / slice_size2;  

                // Loop over the L2 slices
                for (slice = 0; slice < n_slices; slice++) 
                { 
                    // We will store data about this memory segment
                    QCow2DumpRecord *record; 
                    
                    // Initialize data
                    record = g_new0(QCow2DumpRecord , 1);
                    record->l1_index = i;
                    record->l2_offset = l2_offset;
                    record->l2_slice_mod = slice * slice_size2;
                    record->entry_count = 0;
                    QLIST_INIT(&record->slice_entries);

                    // Read the slice from disk
                    ret = qcow2_cache_get(bs, s->l2_table_cache,
                                        l2_offset + slice * slice_size2,
                                        (void **) &l2_slice);
                    // Check for success                    
                    if (ret < 0)
                    {
                        // In this case, we couldn't pull information from
                        // cache. This may create an invalid dump
                        goto failed;
                    }

                    // Loop over segments in the slice
                    for (j = 0; j < s->l2_slice_size; j++) 
                    {
                        uint64_t entry;

                        // Calculate data offsets for disk read
                        entry = be64_to_cpu(l2_slice[j]);
                        entry &= ~QCOW_OFLAG_COPIED;
                        offset = entry & L2E_OFFSET_MASK;
                    
                        // Don't read 0 offsets
                        if (offset > 0)
                        {
                           // Initialize slice data
                            QCow2DumpSliceEntry *slice_data; 

                            // Initialize data
                            slice_data = g_new0(QCow2DumpSliceEntry, 1);
                            slice_data->entry_index = j;
                            slice_data->data_offset = entry;
                            slice_data->slice_index = offset;
                            slice_data->data = g_new0(uint8_t, s->cluster_size);
                            slice_data->data_size = s->cluster_size;

                            // Read the cluster from disk
                            ret = bdrv_pread(bs->file, offset, slice_data->data, slice_data->data_size);

                            // Check for success
                            if (!ret) 
                            {
                                goto failed;
                            }

                            // Add the slice data to the record for this segment
                            add_slice_entry(record, slice_data);
                        } 
                    }

                    // Let QCOW know that we are done with this slice
                    qcow2_cache_put(s->l2_table_cache, (void **) &l2_slice);

                    // If we have entries in this record, add it
                    // to the dump. Else, delete it.
                    if (record->entry_count > 0)
                    {
                        add_dump_record(&dump, record);
                    }
                    else
                    {
                        g_free(record);
                    }
                    
                }    
            }
        }

        if (dump.num_entries > 0)
        {
            // Initialize the dump size
            uint64_t dump_size = 0;

            // Fill the storage buffer with data
            ret = serialize_dump(&dump, &storage_buffer, &dump_size);
            if (ret != 0)
            {
                goto failed;
            }

#ifdef DUMP_DEBUG
            pretty_print_dump(&dump);
#endif

            // Send the data dump to the target device.
            target_bs->drv->bdrv_receive_dump(target_bs, storage_buffer, dump_size, hash);
        }
    }
failed:
    if(l2_slice) qcow2_cache_put(s->l2_table_cache, (void **) &l2_slice);
    if(storage_buffer) g_free(storage_buffer);
    free_dump_memory(&dump);
    return -1;
}

/* if no id is provided, a new one is constructed */
int qcow2_snapshot_create(BlockDriverState *bs, QEMUSnapshotInfo *sn_info)
{
    BDRVQcow2State *s = bs->opaque;
    QCowSnapshot *new_snapshot_list = NULL;
    QCowSnapshot *old_snapshot_list = NULL;
    QCowSnapshot sn1, *sn = &sn1;
    int i, ret;
    uint64_t *l1_table = NULL;
    int64_t l1_table_offset;

    if (s->nb_snapshots >= QCOW_MAX_SNAPSHOTS) {
        return -EFBIG;
    }

    if (has_data_file(bs)) {
        return -ENOTSUP;
    }

    memset(sn, 0, sizeof(*sn));

    /* Generate an ID */
    find_new_snapshot_id(bs, sn_info->id_str, sizeof(sn_info->id_str));

    /* Populate sn with passed data */
    sn->id_str = g_strdup(sn_info->id_str);
    sn->name = g_strdup(sn_info->name);

    sn->disk_size = bs->total_sectors * BDRV_SECTOR_SIZE;
    sn->vm_state_size = sn_info->vm_state_size;
    sn->date_sec = sn_info->date_sec;
    sn->date_nsec = sn_info->date_nsec;
    sn->vm_clock_nsec = sn_info->vm_clock_nsec;

    /* Allocate the L1 table of the snapshot and copy the current one there. */
    l1_table_offset = qcow2_alloc_clusters(bs, s->l1_size * sizeof(uint64_t));
    if (l1_table_offset < 0) {
        ret = l1_table_offset;
        goto fail;
    }

    sn->l1_table_offset = l1_table_offset;
    sn->l1_size = s->l1_size;

    l1_table = g_try_new(uint64_t, s->l1_size);
    if (s->l1_size && l1_table == NULL) {
        ret = -ENOMEM;
        goto fail;
    }

    for(i = 0; i < s->l1_size; i++) {
        l1_table[i] = cpu_to_be64(s->l1_table[i]);
    }

    ret = qcow2_pre_write_overlap_check(bs, 0, sn->l1_table_offset,
                                        s->l1_size * sizeof(uint64_t), false);
    if (ret < 0) {
        goto fail;
    }

    ret = bdrv_pwrite(bs->file, sn->l1_table_offset, l1_table,
                      s->l1_size * sizeof(uint64_t));
    if (ret < 0) {
        goto fail;
    }

    g_free(l1_table);
    l1_table = NULL;

    /*
     * Increase the refcounts of all clusters and make sure everything is
     * stable on disk before updating the snapshot table to contain a pointer
     * to the new L1 table.
     */
    ret = qcow2_update_snapshot_refcount(bs, s->l1_table_offset, s->l1_size, 1);
    if (ret < 0) {
        goto fail;
    }

    /* Append the new snapshot to the snapshot list */
    new_snapshot_list = g_new(QCowSnapshot, s->nb_snapshots + 1);
    if (s->snapshots) {
        memcpy(new_snapshot_list, s->snapshots,
               s->nb_snapshots * sizeof(QCowSnapshot));
        old_snapshot_list = s->snapshots;
    }
    s->snapshots = new_snapshot_list;
    s->snapshots[s->nb_snapshots++] = *sn;

    ret = qcow2_write_snapshots(bs);
    if (ret < 0) {
        g_free(s->snapshots);
        s->snapshots = old_snapshot_list;
        s->nb_snapshots--;
        goto fail;
    }

    g_free(old_snapshot_list);

    /* The VM state isn't needed any more in the active L1 table; in fact, it
     * hurts by causing expensive COW for the next snapshot. */
    qcow2_cluster_discard(bs, qcow2_vm_state_offset(s),
                          ROUND_UP(sn->vm_state_size, s->cluster_size),
                          QCOW2_DISCARD_NEVER, false);

#ifdef DEBUG_ALLOC
    {
      BdrvCheckResult result = {0};
      qcow2_check_refcounts(bs, &result, 0);
    }
#endif
    return 0;

fail:
    g_free(sn->id_str);
    g_free(sn->name);
    g_free(l1_table);

    return ret;
}

int qcow2_receive_dump(BlockDriverState *bs, uint8_t *data, size_t data_len, SHA1_HASH_TYPE hash)
{
    int cur_l1_bytes, cur_l1_size, new_l1_bytes, x, ret = 0;
    BDRVQcow2State *s = bs->opaque;
    //uint64_t offset, written_cluster_size = s->cluster_size * sizeof(offset);
    //uint64_t *new_l1_table;

    QCow2Dump dump;
    deserialize_dump(&dump, data, data_len);

#ifdef DUMP_DEBUG
    pretty_print_dump(&dump);
#endif 

    // TODO loop through each value in each L2 slice and zero them

    // Calculate the size of the incoming L1 tables in bytes
    new_l1_bytes = dump.l1_table_size * sizeof(uint64_t);

    // Make sure the current L1 table can hold the incoming L1 table
    ret = qcow2_grow_l1_table(bs, dump.l1_table_size, true);
    if (ret < 0) 
    {
        goto load_fail;
    }

    // Collect the new L1 table size
    cur_l1_size = s->l1_size;
    cur_l1_bytes = cur_l1_size * sizeof(uint64_t);

    // The L1 table now in memory should be able to accept the incoming table
    if ( cur_l1_bytes < new_l1_bytes)
    {
        goto load_fail;        
    }

    // We want a clean start with this table, so we'll zero it out
    memset(s->l1_table, 0x00, cur_l1_bytes);

    // Do pre-writr overlap check
    ret = qcow2_pre_write_overlap_check(bs, QCOW2_OL_ACTIVE_L1,
                                        s->l1_table_offset, cur_l1_bytes,
                                        false);
    if (ret < 0) 
    {
        goto load_fail;
    }    

    // copy new L1 into the drive snapshot
    for(x = 0; x < dump.l1_table_size; x++) 
    {
        s->l1_table[x] = dump.l1_table[x];
    }

    // adjust endianness for storage in the file
    for (x = 0; x < dump.l1_table_size; ++x)
    {
        cpu_to_be64s(&dump.l1_table[x]);
    }

    // Write new L1 to disk
    ret = bdrv_pwrite_sync(bs->file, s->l1_table_offset, dump.l1_table,
                           cur_l1_bytes);
    if (ret < 0)
    {
        goto load_fail;
    }    

    // Prepare the disk for migration
    ret = qcow2_prepare_clusters_for_migration(bs);
    if (ret < 0)
    {
        goto load_fail;
    }

    // Loop through each record
    QCow2DumpRecord *rec;
    QLIST_FOREACH(rec, &dump.dump_entries, next)
    {
        uint64_t *l2_slice = NULL;
        uint64_t l2_offset = s->l1_table[rec->l1_index] & L1E_OFFSET_MASK;
        //uint64_t l2_offset = dump.l1_table[rec->l1_index] & L1E_OFFSET_MASK;
        
        // Read the slice from disk
        ret = qcow2_cache_get(bs, s->l2_table_cache,
                              l2_offset + rec->l2_slice_mod,
                              (void **) &l2_slice);
        if (ret < 0)
        {
            goto load_fail;            
        }

        // Loop through the entries and make sure they are in place
        QCow2DumpSliceEntry *slice;
        QLIST_FOREACH(slice, &rec->slice_entries, next)
        {
            // Make sure that the offset is in the lice
            l2_slice[slice->entry_index] = cpu_to_be64(slice->data_offset);

            // Make sure that the data makes its way to the haed drive
            ret = bdrv_pwrite(bs->file, slice->slice_index, slice->data, slice->data_size);
            if (ret < 0)
            {
                goto load_fail;            
            }            
        }  

        // Let QCOW know that we are done with this slice
        qcow2_cache_put(s->l2_table_cache, (void **) &l2_slice);
    }
load_fail:
    free_dump_memory(&dump);
    return ret;
}

/* copy the snapshot 'snapshot_name' into the current disk image */
int qcow2_snapshot_goto(BlockDriverState *bs, const char *snapshot_id)
{
    BDRVQcow2State *s = bs->opaque;
    QCowSnapshot *sn;
    Error *local_err = NULL;
    int i, snapshot_index;
    int cur_l1_bytes, sn_l1_bytes;
    int ret;
    uint64_t *sn_l1_table = NULL;

    if (has_data_file(bs)) {
        return -ENOTSUP;
    }

    /* Search the snapshot */
    snapshot_index = find_snapshot_by_id_or_name(bs, snapshot_id);
    if (snapshot_index < 0) {
        return -ENOENT;
    }
    sn = &s->snapshots[snapshot_index];

    ret = qcow2_validate_table(bs, sn->l1_table_offset, sn->l1_size,
                               sizeof(uint64_t), QCOW_MAX_L1_SIZE,
                               "Snapshot L1 table", &local_err);
    if (ret < 0) {
        error_report_err(local_err);
        goto fail;
    }

    if (sn->disk_size != bs->total_sectors * BDRV_SECTOR_SIZE) {
        error_report("qcow2: Loading snapshots with different disk "
            "size is not implemented");
        ret = -ENOTSUP;
        goto fail;
    }

    /*
     * Make sure that the current L1 table is big enough to contain the whole
     * L1 table of the snapshot. If the snapshot L1 table is smaller, the
     * current one must be padded with zeros.
     */
    ret = qcow2_grow_l1_table(bs, sn->l1_size, true);
    if (ret < 0) {
        goto fail;
    }

    cur_l1_bytes = s->l1_size * sizeof(uint64_t);
    sn_l1_bytes = sn->l1_size * sizeof(uint64_t);

    /*
     * Copy the snapshot L1 table to the current L1 table.
     *
     * Before overwriting the old current L1 table on disk, make sure to
     * increase all refcounts for the clusters referenced by the new one.
     * Decrease the refcount referenced by the old one only when the L1
     * table is overwritten.
     */
    sn_l1_table = g_try_malloc0(cur_l1_bytes);
    if (cur_l1_bytes && sn_l1_table == NULL) {
        ret = -ENOMEM;
        goto fail;
    }

    ret = bdrv_pread(bs->file, sn->l1_table_offset,
                     sn_l1_table, sn_l1_bytes);
    if (ret < 0) {
        goto fail;
    }

    ret = qcow2_update_snapshot_refcount(bs, sn->l1_table_offset,
                                         sn->l1_size, 1);
    if (ret < 0) {
        goto fail;
    }

    ret = qcow2_pre_write_overlap_check(bs, QCOW2_OL_ACTIVE_L1,
                                        s->l1_table_offset, cur_l1_bytes,
                                        false);
    if (ret < 0) {
        goto fail;
    }

    ret = bdrv_pwrite_sync(bs->file, s->l1_table_offset, sn_l1_table,
                           cur_l1_bytes);
    if (ret < 0) {
        goto fail;
    }

    /*
     * Decrease refcount of clusters of current L1 table.
     *
     * At this point, the in-memory s->l1_table points to the old L1 table,
     * whereas on disk we already have the new one.
     *
     * qcow2_update_snapshot_refcount special cases the current L1 table to use
     * the in-memory data instead of really using the offset to load a new one,
     * which is why this works.
     */
    ret = qcow2_update_snapshot_refcount(bs, s->l1_table_offset,
                                         s->l1_size, -1);

    /*
     * Now update the in-memory L1 table to be in sync with the on-disk one. We
     * need to do this even if updating refcounts failed.
     */
    for(i = 0;i < s->l1_size; i++) {
        s->l1_table[i] = be64_to_cpu(sn_l1_table[i]);
    }

    if (ret < 0) {
        goto fail;
    }

    g_free(sn_l1_table);
    sn_l1_table = NULL;

    /*
     * Update QCOW_OFLAG_COPIED in the active L1 table (it may have changed
     * when we decreased the refcount of the old snapshot.
     */
    ret = qcow2_update_snapshot_refcount(bs, s->l1_table_offset, s->l1_size, 0);
    if (ret < 0) {
        goto fail;
    }

#ifdef DEBUG_ALLOC
    {
        BdrvCheckResult result = {0};
        qcow2_check_refcounts(bs, &result, 0);
    }
#endif
    return 0;

fail:
    g_free(sn_l1_table);
    return ret;
}

int qcow2_snapshot_delete(BlockDriverState *bs,
                          const char *snapshot_id,
                          const char *name,
                          Error **errp)
{
    BDRVQcow2State *s = bs->opaque;
    QCowSnapshot sn;
    int snapshot_index, ret;

    if (has_data_file(bs)) {
        return -ENOTSUP;
    }

    /* Search the snapshot */
    snapshot_index = find_snapshot_by_id_and_name(bs, snapshot_id, name);
    if (snapshot_index < 0) {
        error_setg(errp, "Can't find the snapshot");
        return -ENOENT;
    }
    sn = s->snapshots[snapshot_index];

    ret = qcow2_validate_table(bs, sn.l1_table_offset, sn.l1_size,
                               sizeof(uint64_t), QCOW_MAX_L1_SIZE,
                               "Snapshot L1 table", errp);
    if (ret < 0) {
        return ret;
    }

    /* Remove it from the snapshot list */
    memmove(s->snapshots + snapshot_index,
            s->snapshots + snapshot_index + 1,
            (s->nb_snapshots - snapshot_index - 1) * sizeof(sn));
    s->nb_snapshots--;
    ret = qcow2_write_snapshots(bs);
    if (ret < 0) {
        error_setg_errno(errp, -ret,
                         "Failed to remove snapshot from snapshot list");
        return ret;
    }

    /*
     * The snapshot is now unused, clean up. If we fail after this point, we
     * won't recover but just leak clusters.
     */
    g_free(sn.id_str);
    g_free(sn.name);

    /*
     * Now decrease the refcounts of clusters referenced by the snapshot and
     * free the L1 table.
     */
    ret = qcow2_update_snapshot_refcount(bs, sn.l1_table_offset,
                                         sn.l1_size, -1);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Failed to free the cluster and L1 table");
        return ret;
    }
    qcow2_free_clusters(bs, sn.l1_table_offset, sn.l1_size * sizeof(uint64_t),
                        QCOW2_DISCARD_SNAPSHOT);

    /* must update the copied flag on the current cluster offsets */
    ret = qcow2_update_snapshot_refcount(bs, s->l1_table_offset, s->l1_size, 0);
    if (ret < 0) {
        error_setg_errno(errp, -ret,
                         "Failed to update snapshot status in disk");
        return ret;
    }

#ifdef DEBUG_ALLOC
    {
        BdrvCheckResult result = {0};
        qcow2_check_refcounts(bs, &result, 0);
    }
#endif
    return 0;
}

int qcow2_snapshot_list(BlockDriverState *bs, QEMUSnapshotInfo **psn_tab)
{
    BDRVQcow2State *s = bs->opaque;
    QEMUSnapshotInfo *sn_tab, *sn_info;
    QCowSnapshot *sn;
    int i;

    if (has_data_file(bs)) {
        return -ENOTSUP;
    }
    if (!s->nb_snapshots) {
        *psn_tab = NULL;
        return s->nb_snapshots;
    }

    sn_tab = g_new0(QEMUSnapshotInfo, s->nb_snapshots);
    for(i = 0; i < s->nb_snapshots; i++) {
        sn_info = sn_tab + i;
        sn = s->snapshots + i;
        pstrcpy(sn_info->id_str, sizeof(sn_info->id_str),
                sn->id_str);
        pstrcpy(sn_info->name, sizeof(sn_info->name),
                sn->name);
        sn_info->vm_state_size = sn->vm_state_size;
        sn_info->date_sec = sn->date_sec;
        sn_info->date_nsec = sn->date_nsec;
        sn_info->vm_clock_nsec = sn->vm_clock_nsec;
    }
    *psn_tab = sn_tab;
    return s->nb_snapshots;
}

int qcow2_snapshot_load_tmp(BlockDriverState *bs,
                            const char *snapshot_id,
                            const char *name,
                            Error **errp)
{
    int i, snapshot_index;
    BDRVQcow2State *s = bs->opaque;
    QCowSnapshot *sn;
    uint64_t *new_l1_table;
    int new_l1_bytes;
    int ret;

    assert(bs->read_only);

    /* Search the snapshot */
    snapshot_index = find_snapshot_by_id_and_name(bs, snapshot_id, name);
    if (snapshot_index < 0) {
        error_setg(errp,
                   "Can't find snapshot");
        return -ENOENT;
    }
    sn = &s->snapshots[snapshot_index];

    /* Allocate and read in the snapshot's L1 table */
    ret = qcow2_validate_table(bs, sn->l1_table_offset, sn->l1_size,
                               sizeof(uint64_t), QCOW_MAX_L1_SIZE,
                               "Snapshot L1 table", errp);
    if (ret < 0) {
        return ret;
    }
    new_l1_bytes = sn->l1_size * sizeof(uint64_t);
    new_l1_table = qemu_try_blockalign(bs->file->bs,
                                       ROUND_UP(new_l1_bytes, 512));
    if (new_l1_table == NULL) {
        return -ENOMEM;
    }

    ret = bdrv_pread(bs->file, sn->l1_table_offset,
                     new_l1_table, new_l1_bytes);
    if (ret < 0) {
        error_setg(errp, "Failed to read l1 table for snapshot");
        qemu_vfree(new_l1_table);
        return ret;
    }

    /* Switch the L1 table */
    qemu_vfree(s->l1_table);

    s->l1_size = sn->l1_size;
    s->l1_table_offset = sn->l1_table_offset;
    s->l1_table = new_l1_table;

    for(i = 0;i < s->l1_size; i++) {
        be64_to_cpus(&s->l1_table[i]);
    }

    return 0;
}
