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

#include "indexed-file.h"
#include "qemu/error-report.h"
#include "cromulence/inlines.h"

#include <stdlib.h>
#include <string.h>

/**
 * Supporting Functions
 */
IndexedFile* indexed_file_new(const char *file_path)
{
    // Variables
    FILE *fp;
    IndexedFile *ret_val;
    IndexedFileClass *ret_class;

    // Allocate the new indexed File
    ret_val = INDEXED_FILE(object_new(TYPE_INDEXED_FILE));
    
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

    // We have a indexed File container and an open file. 
    // Now, we want to hook everything together.
    if (ret_val && fp)
    {
        // Store the file pointer
        ret_val->fp = fp;

        // Now, we set the file pointer to the header in progress
        ret_class = INDEXED_FILE_GET_CLASS(ret_val);
        ret_class->find_current_header(ret_val);
    }

    // All done
    return ret_val;
}

/**
 * Class Functions
 */
static void indexed_file_add_header(IndexedFile *file)
{
    // Allocate some variables
    FileIndex header;
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

static void indexed_file_find_current_header(IndexedFile *file)
{
    // Used for sizing.
    FileIndex header;
    uint64_t next_header_field_loc, next_header, file_size;

    // First check to see the size of the file
    fseek(file->fp, 0, SEEK_END);
    file_size = ftell (file->fp); 
    fseek(file->fp, 0, SEEK_SET);

    if (file_size > 0)
    {
        // Initialize the header
        next_header = 0;
     
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
    
        } while(next_header > 0);

        // Advance to the current header
        fseek(file->fp, file->current_header_loc, SEEK_SET);
    }
    else
    {
        // File size zero has no header.
        indexed_file_add_header(file);
    }
}

static void indexed_file_write_data(IndexedFile *file, IFVisitor *visitor, SHA1_HASH_TYPE *out_hash, uint64_t *out_index)
{
    // If we have a null visitor, do none of this.
    if (visitor)
    {
        // We'll assume that there is already at least one header.
        IndexedFileSegment segment;
        uint64_t num_segments = 0;
        uint64_t new_num_segments = 0;
        uint64_t new_segment = 0;
        uint64_t new_segment_end = 0;

        SHA1_HASH_TYPE hash;

        // Clear the memory
        memset(&segment, 0x00, sizeof(segment));

        // Read the current number of segments in this header
        fread_checked(&num_segments, sizeof(num_segments), file->fp);

        // Determine if we need to add a new header
        if (num_segments >= SEGMENTS_PER_HEADER)
        {
            // we're about to add the first segment
            // to the new section
            num_segments = 0;

            // There is already code for adding a header
            indexed_file_add_header(file);
        }

        // Determine where the new segment will go
        fseek(file->fp, 0, SEEK_END);
        new_segment = ftell (file->fp); 

        // Since we are here, go ahead and have the data written      
        visitor->if_write(visitor->opaque, file->fp);

        // Collect the endpoint for segment size calculation
        new_segment_end = ftell(file->fp);

        // Calculate the segment size
        visitor->calculate_hash(visitor->opaque, &hash);
        memcpy(segment.hash, hash, sizeof(SHA1_HASH_TYPE));
        segment.segment_pointer = new_segment;
        segment.segment_size = new_segment_end - new_segment;

        // Go back to the current header and update the number of segments.
        fseek(file->fp, file->current_header_loc, SEEK_SET);
        new_num_segments = num_segments + 1;
        fwrite(&new_num_segments, sizeof(new_num_segments), 1, file->fp);

        // Go to the segment where we will store the data location
        // and write it.
        fseek(file->fp , num_segments * sizeof(IndexedFileSegment) , SEEK_CUR);
        fwrite(&segment, sizeof(segment), 1, file->fp);
        
        // Set the FP back to the current file header.
        fseek(file->fp, file->current_header_loc, SEEK_SET);

        if( out_hash != NULL ){
            memcpy(*out_hash, segment.hash, sizeof(SHA1_HASH_TYPE));
        }

        if( out_index != NULL ){
            *out_index = num_segments;
        }
    }
}

static bool indexed_file_load_from_index(IndexedFile *file, IFVisitor *visitor, uint64_t index)
{
    // Variables
    IndexedFileSegment segment;
    FileIndex header;
    uint64_t num_segments;
    bool header_missing, record_missing, ret_val;
    uint64_t current_header, header_number, record_number, record_loc, next_header;

    // Initialize Variabes
    record_loc = 0;
    ret_val = false;
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
            uint64_t record_offset = (record_number * sizeof(IndexedFileSegment));

            // We have calculated the jump, now make it.
            fseek(file->fp, record_offset, SEEK_CUR);
            
            // Read the segment data
            fread_checked(&segment.hash, sizeof(segment.hash), file->fp);
            fread_checked(&segment.reserved, sizeof(segment.reserved), file->fp);
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
    if (!record_missing && record_loc == ftell(file->fp) && visitor)
    {
        // We have found what the caller was seeking,
        // Now, use the callback to make stuff happen
        visitor->if_read(visitor->opaque, file->fp, segment.segment_size, &segment.hash);

        // This should have been a success
        ret_val = true;
    }

    // Set the FP back to the current file header.
    fseek(file->fp, file->current_header_loc, SEEK_SET);

    // All done
    return ret_val;
}

static bool indexed_file_load_from_hash(IndexedFile *file, IFVisitor *visitor, SHA1_HASH_TYPE hash)
{
    bool result_found;
    IndexedFileSegment segment;
    uint64_t segment_counter, header_pointer, current_segment, hash_compare;

    // Start at the first header
    header_pointer = 0;
    result_found = false;

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
            fread_checked(&segment.reserved, sizeof(segment.reserved), file->fp);
            fread_checked(&segment.segment_pointer, sizeof(segment.segment_pointer), file->fp);
            fread_checked(&segment.segment_size, sizeof(segment.segment_size), file->fp);

            // now compare the hash
            hash_compare = memcmp(segment.hash, hash, sizeof(SHA1_HASH_TYPE));

            // Check if we found the right hash
            if (hash_compare == 0)
            {
                // We now have a segment pointer that we can seek to.
                fseek(file->fp, segment.segment_pointer, SEEK_SET);

                // Ask the visitor to read data.
                visitor->if_read(visitor->opaque, file->fp, segment.segment_size, &segment.hash);

                // We found what we were seeking. 
                result_found = true;
            }
        }
 
        // Did we exit the loop because we found our result or searched the entire header?
        if (!result_found && current_segment >= SEGMENTS_PER_HEADER)
        {
            // We did not find the hash in this header, load the next header pointer 
            fread_checked(&header_pointer, sizeof(header_pointer), file->fp);
        }
        else
        {
            // We either found what we were looking for, or we exausted our search
            header_pointer = 0;
        }

    } while(header_pointer > 0 && !result_found);

    // Set the FP back to the current file header.
    fseek(file->fp, file->current_header_loc, SEEK_SET);

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

static void indexed_file_query_image_info(IndexedFile *file, ImageInfoList **list)
{
    IndexedFileSegment segment;
    uint64_t segment_counter, header_pointer, current_segment;

    ImageInfoList *elem;
    ImageInfo *info;

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
            fread_checked(&segment.reserved, sizeof(segment.reserved), file->fp);
            fread_checked(&segment.segment_pointer, sizeof(segment.segment_pointer), file->fp);
            fread_checked(&segment.segment_size, sizeof(segment.segment_size), file->fp);

            info = g_new0(ImageInfo,1);
            info->filename = g_new0(char, 256);
            hash_to_string(segment.hash, info->filename);

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

static int64_t indexed_file_get_length(IndexedFile *file)
{
    int64_t ret = 0;

    // Find the end of the file.
    fseek(file->fp, 0, SEEK_END);

    // Grab the size of the file.
    ret = ftell(file->fp);

    // Set the FP back to the current file header.
    fseek(file->fp, file->current_header_loc, SEEK_SET);

    // Done.
    return ret;
}

static void indexed_file_initfn(Object *obj)
{
    IndexedFile *file = INDEXED_FILE(obj);

    file->fp = NULL;
    file->current_header_loc = 0;
}

static void indexed_file_finalize(Object *obj)
{
    IndexedFile *file = INDEXED_FILE(obj);

    fclose(file->fp);
    file->fp = NULL;

    file->current_header_loc = 0;
}

static void indexed_file_class_init(ObjectClass *klass, void *class_data)
{
    IndexedFileClass *indf_class = INDEXED_FILE_CLASS(klass);
    indf_class->add_header = indexed_file_add_header;
    indf_class->write_data = indexed_file_write_data;
    indf_class->load_from_index = indexed_file_load_from_index;
    indf_class->load_from_hash = indexed_file_load_from_hash;
    indf_class->find_current_header = indexed_file_find_current_header;
    indf_class->query_image_info = indexed_file_query_image_info;
    indf_class->get_length = indexed_file_get_length; 
}

/**
 * Type Setup Stuff
 */
static const TypeInfo indexed_file_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_INDEXED_FILE,
    .instance_size = sizeof(IndexedFile),
    .instance_init = indexed_file_initfn,
    .instance_finalize = indexed_file_finalize,
    .class_init = indexed_file_class_init,
    .class_size = sizeof(IndexedFileClass),
};

static void indexed_file_register_types(void)
{
    type_register_static(&indexed_file_info);
}

type_init(indexed_file_register_types);
