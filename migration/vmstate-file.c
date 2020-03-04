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

#include "vmstate-file.h"
#include "rsave-tree-node.h"
#include "qemu/error-report.h"
#include "cromulence/inlines.h"

#include <stdlib.h>
#include <string.h>

typedef struct VMStateNodeCache{
    bool loaded;
    uint64_t index;
    RSaveTreeNode *node;
    QSIMPLEQ_ENTRY(VMStateNodeCache) next;
} VMStateNodeCache;

struct VMStateFile {
    Object obj; 
    FILE *fp;
    uint64_t current_header_loc;
    uint64_t current_index;
    QSIMPLEQ_HEAD(node_cache, VMStateNodeCache) node_cache;
};

static void vmstate_cache_insert(VMStateFile *file, uint64_t index, RSaveTreeNode *node)
{
    VMStateNodeCache *entry;

    entry = g_new0(VMStateNodeCache,1);
    entry->loaded = false;
    entry->node = node;
    entry->index = index;
    QSIMPLEQ_INSERT_TAIL(&file->node_cache, entry, next);
}

static void vmstate_cache_purge(VMStateFile *file)
{
    VMStateNodeCache *entry;
    VMStateNodeCache *next_entry;

    if(!QSIMPLEQ_EMPTY(&file->node_cache)) {
        QSIMPLEQ_FOREACH_SAFE(entry, &file->node_cache, next, next_entry) {
            if(entry->loaded){
                entry->loaded = false;
            }else{
                QSIMPLEQ_REMOVE(&file->node_cache, entry, VMStateNodeCache, next);
                object_unref(OBJECT(entry->node));
                g_free(entry);
            }
        }
    }
}

static void vmstate_cache_force_purge(VMStateFile *file)
{
    VMStateNodeCache *entry;
    VMStateNodeCache *next_entry;

    if(!QSIMPLEQ_EMPTY(&file->node_cache)) {
        QSIMPLEQ_FOREACH_SAFE(entry, &file->node_cache, next, next_entry) {
            QSIMPLEQ_REMOVE(&file->node_cache, entry, VMStateNodeCache, next);
            object_unref(OBJECT(entry->node));
            g_free(entry);
        }
    }
}

/**
 * Supporting Functions
 */
VMStateFile* vmstate_file_new(const char *file_path)
{
    // Variables
    FILE *fp;
    VMStateFile *ret_val;
    VMStateFileClass *ret_class;

    // Allocate the new VM State File
    ret_val = VMSTATE_FILE(object_new(TYPE_VMSTATE_FILE));
    
    // First attempt to open the file if it exists
    fp = fopen(file_path, "r+b");

    // Check for success
    if (!fp)
    {
        // Fail: Try to create a file
        fp = fopen(file_path, "w+b");
        
        // Check for success
        if (!fp)
        {
            // Fail: We will error out
            g_free(ret_val);
            ret_val = NULL;
        }
    }

    // We have a VM State File container and an open file. 
    // Now, we want to hook everything together.
    if (ret_val && fp)
    {
        // Store the file pointer
        ret_val->fp = fp;

        // Now, we set the file pointer to the header in progress
        ret_class = VMSTATE_FILE_GET_CLASS(ret_val);
        ret_class->find_current_header(ret_val);
    }

    // All done
    return ret_val;
}

/**
 * Class Functions
 */
static void vmstate_file_add_header(VMStateFile *file)
{
    // Allocate some variables
    VMFileHeader header;
    uint64_t new_header_loc = 0;

    // Zero out the new header
    memset(&header, 0x00, sizeof(header)); 

    // Get the location of the new header
    fseek(file->fp, 0, SEEK_END);
    new_header_loc = ftell(file->fp);

    // Since we are at the end, we'll write the new header
    fwrite(&header, sizeof(header), 1, file->fp);

    // Are we adding another file header?
    // If so, we'll have to update the previous header.
    if (new_header_loc > 0)
    {
        // calculate the location of the feild that
        // points to the new header
        uint64_t next_header_field = (file->current_header_loc) +
                                     (sizeof(header.num_segments)) +
                                     (sizeof(header.segments));
        fseek(file->fp, next_header_field, SEEK_SET);

        // Write the new header location into the current header
        fwrite(&new_header_loc, sizeof(new_header_loc), 1, file->fp);
    }

    // Update the current header location and set to that 
    fflush(file->fp);
    file->current_header_loc = new_header_loc;
    fseek(file->fp, file->current_header_loc, SEEK_SET);
}

static void vmstate_file_find_current_header(VMStateFile *file)
{
    // Used for sizing.
    VMFileHeader header;
    uint64_t next_header_field_loc, next_header, file_size, skipped_headers;

    // First check to see the size of the file
    fseek(file->fp, 0, SEEK_END);
    file_size = ftell (file->fp); 
    fseek(file->fp, 0, SEEK_SET);

    if (file_size > 0)
    {
        // Initialize the header
        next_header = 0;
        skipped_headers = 0;
     
        // We'll reset to the begenning ad start looking forward.
        fseek(file->fp, 0, SEEK_SET);

        do
        {
            // We'll assume that the first header is
            // the correct one.
            file->current_header_loc = next_header;

            // Navigate to the next header section
            next_header_field_loc = (file->current_header_loc) +
                                    (sizeof(header.num_segments)) +
                                    (sizeof(header.segments));
            fseek(file->fp, next_header_field_loc, SEEK_SET);

            // Read the header location.
            fread_checked(&next_header, sizeof(next_header), file->fp);
            skipped_headers++;
    
        } while(next_header > 0);

        file->current_index = (skipped_headers - 1) * SEGMENTS_PER_HEADER;

        // Advance to the current header
        fseek(file->fp, file->current_header_loc, SEEK_SET);
    }
    else
    {
        // File size zero has no header.
        vmstate_file_add_header(file);
    }
}

static void vmstate_file_save_data(VMStateFile *file, RSaveTreeNode *node, uint64_t *out_index, bool nosave)
{
    uint64_t record_index = 0;
    
    // Should we flush to file? If not, then we'll just cache the save.
    if( !nosave )
    {
        // We'll assume that there is already at least one header.
        FileSegment segment;
        uint64_t num_segments = 0;
        uint64_t new_num_segments = 0;
        uint64_t new_segment = 0;
        uint64_t new_segment_end = 0;

        // Clear the memory
        memset(&segment, 0, sizeof(segment));

        // We'll let the node class do some of the work
        RSaveTreeNodeClass *rstn_class = RSAVE_TREE_NODE_GET_CLASS(node);

        // Read the current number of segments in this header
        fread_checked(&num_segments, sizeof(num_segments), file->fp);

        // Determine if we need to add a new header
        if (num_segments >= SEGMENTS_PER_HEADER)
        {
            // we're about to add the first segment
            // to the new section
            num_segments = 0;

            // There is already code for adding a header
            vmstate_file_add_header(file);
        }

        // Determine where the new segment will go
        fseek(file->fp, 0, SEEK_END);
        new_segment = ftell (file->fp); 

        // Since we are here, go ahead and write data
        rstn_class->write_tree_node(node, file->fp);

        // Collect the endpoint for segment size calculation
        new_segment_end = ftell(file->fp);

        // Calculate the segment size
        memcpy(segment.hash, node->hash, sizeof(SHA1_HASH_TYPE));
        segment.job_id = node->job_id;
        segment.segment_pointer = new_segment;
        segment.segment_size = new_segment_end - new_segment;

        // Go back to the current header and update the number of segments.
        fseek(file->fp, file->current_header_loc, SEEK_SET);
        new_num_segments = num_segments + 1;
        fwrite(&new_num_segments, sizeof(new_num_segments), 1, file->fp);

        // Go to the segment where we will store the data location
        // and write it.
        fseek(file->fp , num_segments * sizeof(FileSegment) , SEEK_CUR);
        fwrite(&segment, sizeof(segment), 1, file->fp);
        
        // Set the FP back to the current file header.
        fseek(file->fp, file->current_header_loc, SEEK_SET);
    }

    record_index = ++file->current_index;

    if( out_index != NULL ){
        *out_index = record_index;
    }

    // Have we exceeded our pool limit?
    if( memory_channel_test_and_set_pool_limit() ) {
        // We need to recover some memory, so
        // purge entries that haven't been recently
        // loaded and request that the tree release
        // some of it's nodes.
        vmstate_cache_purge(file);
    }

    // Ref the node and add it to the state cache.
    object_ref(OBJECT(node));
    vmstate_cache_insert(file, record_index, node);
}

static bool vmstate_file_load_from_index(VMStateFile *file, RSaveTreeNode **new_node, uint64_t index)
{
    // Variables
    FileSegment segment;
    VMFileHeader header;
    uint64_t num_segments;
    bool header_missing, record_missing;
    uint64_t current_header, header_number, record_number, record_loc, next_header;
    VMStateNodeCache *entry;
    RSaveTreeNode *node = NULL;
    bool result_found = false;

    // Look for this node in our cache of previously loaded states.
    QSIMPLEQ_FOREACH(entry, &file->node_cache, next) {
        if( entry->index == index ) {
            entry->loaded = true;
            node = entry->node;
            result_found = true;
            break;
        }
    }

    if( !result_found )
    {
        // Initialize Variabes
        record_loc = 0;
        record_missing = true;
        header_missing = false;
        header_number = index / SEGMENTS_PER_HEADER;
        record_number = index % SEGMENTS_PER_HEADER;

        // We will start at the begenning
        fseek(file->fp, 0, SEEK_SET);

        // Begin to look for header containing the record
        for (current_header = 0; current_header < header_number && !header_missing; ++current_header)
        {
            // Calculate the location for the next header
            uint64_t next_header_field = (current_header) +
                                        (sizeof(header.num_segments)) +
                                        (sizeof(header.segments));
            fseek(file->fp, next_header_field, SEEK_SET);

            // Read the header location and go there.
            fread_checked(&next_header, sizeof(next_header), file->fp);

            if (next_header)
            {
                // We found the header, now we go there
                fseek(file->fp, next_header, SEEK_SET);
            }
            else
            {
                // we did not find the header
                header_missing = true;
            }
        }

        // Unless the header was missing, we should now be on the right header
        if (!header_missing)
        {
            // First we read the number of elements in the header
            fread_checked(&num_segments, sizeof(num_segments), file->fp);

            // Verify that the record number exists
            if (record_number < num_segments)
            {
                // First calculate the distance to the header
                uint64_t record_offset = (record_number * sizeof(FileSegment));

                // We have calculated the jump, now make it.
                fseek(file->fp, record_offset, SEEK_CUR);
                
                // Read the segment data
                fread_checked(&segment.hash, sizeof(segment.hash), file->fp);
                fread_checked(&segment.job_id, sizeof(segment.job_id), file->fp);
                fread_checked(&segment.segment_pointer, sizeof(segment.segment_pointer), file->fp);
                fread_checked(&segment.segment_size, sizeof(segment.segment_size), file->fp);

                // Populate the file offset the to record
                record_loc = segment.segment_pointer;

                // Verify that the record_loc is populated
                // and go to that location
                if (record_loc)
                {
                    record_missing = false;
                    fseek(file->fp, record_loc, SEEK_SET);
                }
            }
        }

        // If we found our record and we successfully made it
        // to the loc, then we can start to load data
        if (!record_missing && record_loc == ftell(file->fp))
        {
            // Create a node to write to the file
            // We don't care about linkage of the node to others as
            // This is being used soley for writing a consistent structure.
            node = rsave_tree_node_new();
            RSaveTreeNodeClass *rstn_class = RSAVE_TREE_NODE_GET_CLASS(node);

            // Farm out the tree node loading
            rstn_class->read_tree_node(node, file->fp, segment.segment_size);

            // Add the hash to the node
            memcpy(node->hash, segment.hash, sizeof(SHA1_HASH_TYPE));

            // Have we exceeded our pool limit?
            if( memory_channel_test_and_set_pool_limit() ) {
                // We need to recover some memory, note that
                // copies of the nodes may still be in the
                // rapid analysis tree.
                vmstate_cache_purge(file);
            }

            // The first reference will always be held by cache to keep the node persistent.
            vmstate_cache_insert(file, index, node);

            // This should have been a success
            result_found = true;
        }

        // Set the FP back to the current file header.
        fseek(file->fp, file->current_header_loc, SEEK_SET);
    }

    if(result_found){
        // Ref it and return it
        object_ref(OBJECT(node));
        *new_node = node;
    }

    // All done
    return result_found;
}

static bool vmstate_file_load_from_hash(VMStateFile *file, RSaveTreeNode **new_node, SHA1_HASH_TYPE hash)
{
    FileSegment segment;
    uint64_t segment_counter, header_pointer, current_segment, record_index;
    VMStateNodeCache *entry;
    bool result_found = false;
    RSaveTreeNode *node = NULL;

    // Look for this node in our cache of previously loaded states.
    QSIMPLEQ_FOREACH(entry, &file->node_cache, next) {
        if(!memcmp(entry->node->hash, hash, sizeof(SHA1_HASH_TYPE))) {
            entry->loaded = true;
            node = entry->node;
            result_found = true;
            break;
        }
    }

    if( !result_found )
    {
        // Start at the first header
        record_index = 0;
        header_pointer = 0;

        do
        {
            // We will start at the beginning of the header
            fseek(file->fp, header_pointer, SEEK_SET);
        
            // Read the number of segments in the header
            fread_checked(&segment_counter, sizeof(segment_counter), file->fp);

            // Check through the header and compare hashes 
            for (current_segment = 0; current_segment < segment_counter && !result_found; ++current_segment)
            {
                // Load the data segment info
                fread_checked(&segment.hash, sizeof(segment.hash), file->fp);
                fread_checked(&segment.job_id, sizeof(segment.job_id), file->fp);
                fread_checked(&segment.segment_pointer, sizeof(segment.segment_pointer), file->fp);
                fread_checked(&segment.segment_size, sizeof(segment.segment_size), file->fp);

                // Check if we found the right hash
                if ( !memcmp(segment.hash, hash, sizeof(SHA1_HASH_TYPE)) )
                {
                    // Create the receiving node for this hash's state
                    node = rsave_tree_node_new();
                    RSaveTreeNodeClass *rstn_class = RSAVE_TREE_NODE_GET_CLASS(node);

                    // We now have a segment pointer that we can seek to.
                    fseek(file->fp, segment.segment_pointer, SEEK_SET);

                    // Farm out the tree node loading
                    rstn_class->read_tree_node(node, file->fp, segment.segment_size);

                    // Add the hash to the node
                    memcpy(node->hash, segment.hash, sizeof(SHA1_HASH_TYPE));

                    // We found what we were seeking.
                    record_index += current_segment;
                    result_found = true;
                }
            }
    
            // Did we exit the loop because we found our result or searched the entire header?
            if (!result_found && current_segment >= SEGMENTS_PER_HEADER)
            {
                // We did not find the hash in this header, load the next header pointer 
                fread_checked(&header_pointer, sizeof(header_pointer), file->fp);
                record_index += SEGMENTS_PER_HEADER;
            }
            else
            {
                // We either found what we were looking for, or we exausted our search
                header_pointer = 0;
            }

        } while(header_pointer > 0 && !result_found);

        // Set the FP back to the current file header.
        fseek(file->fp, file->current_header_loc, SEEK_SET);

        if( result_found ) {
            // Have we exceeded our pool limit?
            if( memory_channel_test_and_set_pool_limit() ) {
                // We need to recover some memory, note that
                // copies of the nodes may still be in the
                // rapid analysis tree.
                vmstate_cache_purge(file);
            }

            // The first reference will always be held by cache to keep the node persistent.
            vmstate_cache_insert(file, record_index, node);
        }
    }

    if( result_found ){
        // Ref it and return it
        object_ref(OBJECT(node));
        *new_node = node;
    }

    // All done
    return result_found;
}

static bool vmstate_file_load_from_job(VMStateFile *file, RSaveTreeNode **new_node, int32_t job_id)
{
    FileSegment segment;
    uint64_t segment_counter, header_pointer, current_segment, record_index;
    VMStateNodeCache *entry;
    bool result_found = false;
    RSaveTreeNode *node = NULL;

    // Look for this node in our cache of previously loaded states.
    QSIMPLEQ_FOREACH(entry, &file->node_cache, next) {
        if(entry->node->job_id == job_id) {
            entry->loaded = true;
            node = entry->node;
            result_found = true;
            break;
        }
    }

    if( !result_found )
    {
        // Start at the first header
        record_index = 0;
        header_pointer = 0;

        do
        {
            // We will start at the beginning of the header
            fseek(file->fp, header_pointer, SEEK_SET);
        
            // Read the number of segments in the header
            fread_checked(&segment_counter, sizeof(segment_counter), file->fp);

            // Check through the header and compare hashes 
            for (current_segment = 0; current_segment < segment_counter && !result_found; ++current_segment)
            {
                // Load the data segment info
                fread_checked(&segment.hash, sizeof(segment.hash), file->fp);
                fread_checked(&segment.job_id, sizeof(segment.job_id), file->fp);
                fread_checked(&segment.segment_pointer, sizeof(segment.segment_pointer), file->fp);
                fread_checked(&segment.segment_size, sizeof(segment.segment_size), file->fp);

                // Check if we found the right hash
                if ( segment.job_id == job_id )
                {
                    // Create the receiving node for this hash's state
                    node = rsave_tree_node_new();
                    RSaveTreeNodeClass *rstn_class = RSAVE_TREE_NODE_GET_CLASS(node);

                    // We now have a segment pointer that we can seek to.
                    fseek(file->fp, segment.segment_pointer, SEEK_SET);

                    // Farm out the tree node loading
                    rstn_class->read_tree_node(node, file->fp, segment.segment_size);

                    // Add the hash to the node
                    memcpy(node->hash, segment.hash, sizeof(SHA1_HASH_TYPE));

                    // We found what we were seeking.
                    record_index += current_segment;
                    result_found = true;
                }
            }
    
            // Did we exit the loop because we found our result or searched the entire header?
            if (!result_found && current_segment >= SEGMENTS_PER_HEADER)
            {
                // We did not find the hash in this header, load the next header pointer 
                fread_checked(&header_pointer, sizeof(header_pointer), file->fp);
                record_index += SEGMENTS_PER_HEADER;
            }
            else
            {
                // We either found what we were looking for, or we exausted our search
                header_pointer = 0;
            }

        } while(header_pointer > 0 && !result_found);

        // Set the FP back to the current file header.
        fseek(file->fp, file->current_header_loc, SEEK_SET);

        if( result_found ) {
            // Have we exceeded our pool limit?
            if( memory_channel_test_and_set_pool_limit() ) {
                // We need to recover some memory, note that
                // copies of the nodes may still be in the
                // rapid analysis tree.
                vmstate_cache_purge(file);
            }

            // The first reference will always be held by cache to keep the node persistent.
            vmstate_cache_insert(file, record_index, node);
        }
    }

    if( result_found ){
        // Ref it and return it
        object_ref(OBJECT(node));
        *new_node = node;
    }

    // All done
    return result_found;
}

static void hash_to_string(SHA1_HASH_TYPE hash, char *str)
{
    uint8_t len = 0, pos = 0;

    while(pos < (sizeof(SHA1_HASH_TYPE)/sizeof(uint32_t)))
    {
        snprintf(&str[len], 9, "%08x", hash[pos]);
        len += 8;
        pos++;
    }
}

static void vmstate_file_query_image_info(VMStateFile *file, ImageInfoList **list)
{
    FileSegment segment;
    uint64_t segment_counter, header_pointer, current_segment;

    SHA1_HASH_TYPE parent_hash;
    ImageInfoList *elem;
    ImageInfo *info;
    int32_t job_id;
    uint64_t job_icount;
    uint64_t job_eindex;
    int64_t timestamp;

    header_pointer = 0;
    do
    {
        // We will start at the beginning of the header
        fseek(file->fp, header_pointer, SEEK_SET);
    
        // Read the number of segments in the header
        fread_checked(&segment_counter, sizeof(segment_counter), file->fp);

        // Check through the header and compare hashes 
        for (current_segment = 0; current_segment < segment_counter; ++current_segment)
        {
            // Load the data segment info
            fread_checked(&segment.hash, sizeof(segment.hash), file->fp);
            fread_checked(&segment.job_id, sizeof(segment.job_id), file->fp);
            fread_checked(&segment.segment_pointer, sizeof(segment.segment_pointer), file->fp);
            fread_checked(&segment.segment_size, sizeof(segment.segment_size), file->fp);

            info = g_new0(ImageInfo,1);
            info->filename = g_new0(char, 256);
            hash_to_string(segment.hash, info->filename);
            if(header_pointer == 0 && current_segment == 0) {
                info->format = g_strdup("Root VMState");
            }else{
                info->format = g_strdup("Rapid Analysis VMState");
            }
            info->has_actual_size = 1;
            info->actual_size = segment.segment_size;
            info->virtual_size = segment.segment_size;

            long pos = ftell(file->fp);
            fseek(file->fp, segment.segment_pointer, SEEK_SET);

            fread_checked(&job_icount, sizeof(job_icount), file->fp);
            fread_checked(&job_eindex, sizeof(job_eindex), file->fp);
            fread_checked(&job_id, sizeof(job_id), file->fp);
            fread_checked(&parent_hash, sizeof(SHA1_HASH_TYPE), file->fp);
            fread_checked(&timestamp, sizeof(timestamp), file->fp);

            info->has_snapshots = 1;
            info->snapshots = g_new0(SnapshotInfoList,1);
            info->snapshots->value = g_new0(SnapshotInfo, 1);
            info->snapshots->value->id = g_new0(char, 256);
            snprintf(info->snapshots->value->id, 255, "%d", segment.job_id);
            info->snapshots->value->name = g_new0(char, 256);
            hash_to_string(parent_hash, info->snapshots->value->name);
            info->snapshots->value->vm_state_size = job_icount;
            info->snapshots->value->date_sec = timestamp / 1000000000l;
            info->snapshots->value->date_nsec = timestamp % 1000000000l;

            info->snapshots->next = NULL;

            fseek(file->fp, pos, SEEK_SET);

            elem = g_new0(ImageInfoList, 1);
            elem->value = info;
            *list = elem;
            list = &elem->next;
        }
 
        // Load the next header pointer 
        fread_checked(&header_pointer, sizeof(header_pointer), file->fp);
    } while(header_pointer > 0);

    // Set the FP back to the current file header.
    fseek(file->fp, file->current_header_loc, SEEK_SET);
}

static void vmstate_file_initfn(Object *obj)
{
    VMStateFile *file = VMSTATE_FILE(obj);

    file->fp = NULL;
    file->current_header_loc = 0;
    file->current_index = 0;
    QSIMPLEQ_INIT(&file->node_cache);
}

static void vmstate_file_finalize(Object *obj)
{
    VMStateFile *file = VMSTATE_FILE(obj);

    fclose(file->fp);
    file->fp = NULL;
    file->current_header_loc = 0;
    file->current_index = 0;

    vmstate_cache_force_purge(file);
}

static void vmstate_file_class_init(ObjectClass *klass, void *class_data)
{
    VMStateFileClass *vmstate_class = VMSTATE_FILE_CLASS(klass);
    vmstate_class->add_header = vmstate_file_add_header;
    vmstate_class->save_data = vmstate_file_save_data;
    vmstate_class->load_from_index = vmstate_file_load_from_index;
    vmstate_class->load_from_hash = vmstate_file_load_from_hash;
    vmstate_class->load_from_job = vmstate_file_load_from_job;
    vmstate_class->find_current_header = vmstate_file_find_current_header;
    vmstate_class->query_image_info = vmstate_file_query_image_info;
}

/**
 * Type Setup Stuff
 */
static const TypeInfo vmstate_file_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_VMSTATE_FILE,
    .instance_size = sizeof(VMStateFile),
    .instance_init = vmstate_file_initfn,
    .instance_finalize = vmstate_file_finalize,
    .class_init = vmstate_file_class_init,
    .class_size = sizeof(VMStateFileClass),
};

static void vmstate_file_register_types(void)
{
    type_register_static(&vmstate_file_info);
}

type_init(vmstate_file_register_types);
