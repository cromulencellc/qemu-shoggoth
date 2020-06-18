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

#include "qemu/osdep.h"
#include "cpu.h"
#include "qemu/cutils.h"
#include "qemu/bitops.h"
#include "qemu/bitmap.h"
#include "qemu/main-loop.h"
#include "ram.h"
#include "ram_rapid.h"
#include "migration.h"
#include "migration/register.h"
#include "migration/misc.h"
#include "qemu-file.h"
#include "postcopy-ram.h"
#include "migration/page_cache.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qapi/qapi-events-migration.h"
#include "qapi/qmp/qerror.h"
#include "trace.h"
#include "exec/ram_addr.h"
#include "exec/target_page.h"
#include "exec/ramlist.h"
#include "qemu/rcu_queue.h"
#include "migration/colo.h"
#include "migration/block.h"
#include "savevm.h"
#include "ra.h"


/***********************************************************/
/* ram save/restore */

/* RAM_SAVE_FLAG_ZERO used to be named RAM_SAVE_FLAG_COMPRESS, it
 * worked for pages that where filled with the same char.  We switched
 * it to only search for the zero value.  And to avoid confusion with
 * RAM_SSAVE_FLAG_COMPRESS_PAGE just rename it.
 */

#define RAM_SAVE_FLAG_FULL     0x01 /* Obsolete, not used anymore */
#define RAM_SAVE_FLAG_ZERO     0x02
#define RAM_SAVE_FLAG_MEM_SIZE 0x04
#define RAM_SAVE_FLAG_PAGE     0x08
#define RAM_SAVE_FLAG_EOS      0x10
#define RAM_SAVE_FLAG_CONTINUE 0x20
#define RAM_SAVE_FLAG_XBZRLE   0x40
/* 0x80 is reserved in migration.h start with 0x100 next */
#define RAM_SAVE_FLAG_COMPRESS_PAGE 0x100
#define RAM_SAVE_FLAG_DELTA_PAGE    0x200
#define RAM_SAVE_FLAG_DELTA_BANK    0x400

/*
 * An outstanding page request, on the source, having been received
 * and queued
 */
struct RAMSrcPageRequest {
    RAMBlock *rb;
    hwaddr    offset;
    hwaddr    len;

    QSIMPLEQ_ENTRY(RAMSrcPageRequest) next_req;
};

struct RAMRapidLoadCache{
    QEMUFile *in;
    RSaveTreeNode *node;
    uint8_t section_type;
    uint32_t section_id;

    QSIMPLEQ_ENTRY(RAMRapidLoadCache) next;
};
typedef struct RAMRapidLoadCache RAMRapidLoadCache;

/* State of RAM for migration */
struct RAMState {
    /* QEMUFile used for this migration */
    QEMUFile *f;
    /* Last block that we have visited searching for dirty pages */
    RAMBlock *last_seen_block;
    /* Last block from where we have sent data */
    RAMBlock *last_sent_block;
    /* Last dirty target page we have sent */
    ram_addr_t last_page;
    /* last ram version we have seen */
    uint32_t last_version;
    /* We are in the first round */
    bool ram_bulk_stage;
    /* The free page optimization is enabled */
    bool fpo_enabled;
    /* How many times we have dirty too many pages */
    int dirty_rate_high_cnt;
    /* these variables are used for bitmap sync */
    /* last time we did a full bitmap_sync */
    int64_t time_last_bitmap_sync;
    /* bytes transferred at start_time */
    uint64_t bytes_xfer_prev;
    /* number of dirty pages since start_time */
    uint64_t num_dirty_pages_period;
    /* number of iterations at the beginning of period */
    uint64_t iterations_prev;
    /* Iterations since start */
    uint64_t iterations;
    /* number of dirty bits in the bitmap */
    uint64_t migration_dirty_pages;
    /* protects modification of the bitmap */
    QemuMutex bitmap_mutex;
    /* The RAMBlock used in the last src_page_requests */
    RAMBlock *last_req_rb;
    /* Queue of outstanding page requests from the destination */
    QemuMutex src_page_req_mutex;
    // Default hash to use for page references
    SHA1_HASH_TYPE default_hash;
    // Bank load state
    SHA1_HASH_TYPE bank_hash;
    ram_addr_t bank_offset;
    QSIMPLEQ_HEAD(src_page_requests, RAMSrcPageRequest) src_page_requests;
    QSIMPLEQ_HEAD(load_cache, RAMRapidLoadCache) load_cache;
};
typedef struct RAMState RAMState;

static RAMState *ram_state = NULL;

void ram_rapid_precopy_enable_free_page_optimization(void)
{
    ram_state->fpo_enabled = true;
}

/* used by the search for pages to send */
struct PageSearchStatus {
    /* Current block being searched */
    RAMBlock    *block;
    /* Current page to search from */
    unsigned long page;
    /* Current address */
    ram_addr_t addr;
    /* Set once we wrap around */
    bool         complete_round;
};
typedef struct PageSearchStatus PageSearchStatus;

/* Should be holding either ram_list.mutex, or the RCU lock. */
#define RAMBLOCK_FOREACH_NOT_IGNORED(block)            \
    INTERNAL_RAMBLOCK_FOREACH(block)                   \
        if (ramblock_is_ignored(block)) {} else

#define RAMBLOCK_FOREACH_MIGRATABLE(block)             \
    INTERNAL_RAMBLOCK_FOREACH(block)                   \
        if (!qemu_ram_is_migratable(block)) {} else

uint64_t get_ram_rapid_dirty_pages(void)
{
    return ram_state ? ram_state->migration_dirty_pages : 0;
}

/**
 * ram_rapid_postcopy_chunk_hostpages_pass: canocalize bitmap in hostpages
 *
 * Helper for postcopy_chunk_hostpages; it's called twice to
 * canonicalize the two bitmaps, that are similar, but one is
 * inverted.
 *
 * Postcopy requires that all target pages in a hostpage are dirty or
 * clean, not a mix.  This function canonicalizes the bitmaps.
 *
 * @ms: current migration state
 * @unsent_pass: if true we need to canonicalize partially unsent host pages
 *               otherwise we need to canonicalize partially dirty host pages
 * @block: block that contains the page we want to canonicalize
 * @pds: state for postcopy
 */
void ram_rapid_postcopy_chunk_hostpages_pass(MigrationState *ms, bool unsent_pass,
                                          RAMBlock *block, PostcopyDiscardState *pds)
{
    error_report("Postcopy not supported in Rapid Analysis mode\n");
}

/**
 * ram_rapid_postcopy_send_discard_bitmap: transmit the discard bitmap
 *
 * Returns zero on success
 *
 * Transmit the set of pages to be discarded after precopy to the target
 * these are pages that:
 *     a) Have been previously transmitted but are now dirty again
 *     b) Pages that have never been transmitted, this ensures that
 *        any pages on the destination that have been mapped by background
 *        tasks get discarded (transparent huge pages is the specific concern)
 * Hopefully this is pretty sparse
 *
 * @ms: current migration state
 */
int ram_rapid_postcopy_send_discard_bitmap(MigrationState *ms)
{
    error_report("Postcopy not supported in Rapid Analysis mode\n");
    return 0;
}

/**
 * ram_rapid_save_queue_pages: queue the page for transmission
 *
 * A request from postcopy destination for example.
 *
 * Returns zero on success or negative on error
 *
 * @rbname: Name of the RAMBLock of the request. NULL means the
 *          same that last one.
 * @start: starting address from the start of the RAMBlock
 * @len: length (in bytes) to send
 */
int ram_rapid_save_queue_pages(const char *rbname, ram_addr_t start, ram_addr_t len)
{
    error_report("Postcopy not supported in Rapid Analysis mode\n");
    return 0;
}

/**
 * migration_bitmap_find_dirty: find the next dirty page from start
 *
 * Called with rcu_read_lock() to protect migration_bitmap
 *
 * Returns the byte offset within memory region of the start of a dirty page
 *
 * @rs: current RAM state
 * @rb: RAMBlock where to search for dirty pages
 * @start: page where we start the search
 */
static inline
unsigned long migration_bitmap_find_dirty(RAMState *rs, RAMBlock *rb,
                                          unsigned long start)
{
    unsigned long size = rb->used_length >> TARGET_PAGE_BITS;
    unsigned long *bitmap = rb->bmap;
    unsigned long next;

    if (ramblock_is_ignored(rb)) {
        return size;
    }

    /*
     * When the free page optimization is enabled, we need to check the bitmap
     * to send the non-free pages rather than all the pages in the bulk stage.
     */
    if (!rs->fpo_enabled && rs->ram_bulk_stage && start > 0) {
        next = start + 1;
    } else {
        next = find_next_bit(bitmap, size, start);
    }

    return next;
}

static inline bool migration_bitmap_clear_dirty(RAMState *rs,
                                                RAMBlock *rb,
                                                unsigned long page)
{
    bool ret;

    qemu_mutex_lock(&rs->bitmap_mutex);
    ret = test_and_clear_bit(page, rb->bmap);

    if (ret) {
        rs->migration_dirty_pages--;
    }
    qemu_mutex_unlock(&rs->bitmap_mutex);

    return ret;
}

uint64_t ram_rapid_get_total_transferred_pages(void)
{
    return ram_counters.normal + ram_counters.duplicate;
}

/**
 * find_dirty_block: find the next dirty page and update any state
 * associated with the search process.
 *
 * Returns if a page is found
 *
 * @rs: current RAM state
 * @pss: data about the state of the current dirty page scan
 * @again: set to false if the search has scanned the whole of RAM
 */
static bool find_dirty_block(RAMState *rs, PageSearchStatus *pss, bool *again)
{
    pss->page = migration_bitmap_find_dirty(rs, pss->block, pss->page);
    if (pss->complete_round && pss->block == rs->last_seen_block &&
        pss->page >= rs->last_page) {
        /*
         * We've been once around the RAM and haven't found anything.
         * Give up.
         */
        *again = false;
        return false;
    }
    if ((pss->page << TARGET_PAGE_BITS) >= pss->block->used_length) {
        /* Didn't find anything in this RAM Block */
        pss->page = 0;
        pss->block = QLIST_NEXT_RCU(pss->block, next);
        if (!pss->block) {
            /* Hit the end of the list */
            pss->block = QLIST_FIRST_RCU(&ram_list.blocks);
            /* Flag that we've looped */
            pss->complete_round = true;
            rs->ram_bulk_stage = false;
        }
        /* Didn't find anything this time, but try again on the new block */
        *again = true;
        return false;
    } else {
        /* Can go around again, but... */
        *again = true;
        /* We've found something so probably don't need to */
        return true;
    }
}

void ram_rapid_blocks_init(void)
{
    RAMBlock *block = NULL;

    RAMBLOCK_FOREACH(block) {
       // printf("Set %s\n", block->idstr);
        block->max_pages = QEMU_ALIGN_UP(block->max_length, TARGET_PAGE_SIZE) >> TARGET_PAGE_BITS;
        block->rsave_flags = g_malloc0(block->max_pages);
        block->rsave_l2_hashes = g_malloc0(block->max_pages * sizeof(SHA1_HASH_TYPE));
        block->rsave_l1_hashes = g_malloc0((QEMU_ALIGN_UP(block->max_pages, RSAVE_LAYER1_BANK_SIZE) >> RSAVE_LAYER1_BANK_BITS) * sizeof(SHA1_HASH_TYPE));
    }
}

void ram_rapid_blocks_cleanup(void)
{
    RAMBlock *block = NULL;

    RAMBLOCK_FOREACH(block) {
        //printf("Free %s\n", block->idstr);
        g_free(block->rsave_flags);
        g_free(block->rsave_l2_hashes);
        g_free(block->rsave_l1_hashes);
        block->rsave_flags = NULL;
        block->rsave_l2_hashes = NULL;
        block->rsave_l1_hashes = NULL;
    }
}

static void ram_clean_l1_page(RAMBlock *rb, ram_addr_t offset)
{
    const unsigned long page = (offset >> TARGET_PAGE_BITS) >> RSAVE_LAYER1_BANK_BITS;
    rb->rsave_flags[page] &= ~RSAVE_LAYER1_DIRTY;
}

static void ram_clean_l2_page(RAMBlock *rb, ram_addr_t offset)
{
    const unsigned long page = (offset >> TARGET_PAGE_BITS);
    rb->rsave_flags[page] &= ~RSAVE_LAYER2_DIRTY;
}

static int ram_page_needs_refresh(RAMBlock *rb, ram_addr_t offset, SHA1_HASH_TYPE cmp_hash)
{
    const unsigned long page = (offset >> TARGET_PAGE_BITS);
    return (rb->rsave_flags[page] & RSAVE_LAYER2_DIRTY)
        || memcmp(rb->rsave_l2_hashes[page], cmp_hash, sizeof(SHA1_HASH_TYPE));
}

static void ram_set_l2_reference_page_hash(RAMBlock *rb, ram_addr_t offset, SHA1_HASH_TYPE ref_hash)
{
    const unsigned long page = offset >> TARGET_PAGE_BITS;
    rb->rsave_flags[page] &= ~RSAVE_LAYER2_DIRTY;
    memcpy(rb->rsave_l2_hashes[page], ref_hash, sizeof(SHA1_HASH_TYPE));
}

static void ram_set_l1_reference_page_hash(RAMBlock *rb, ram_addr_t offset, SHA1_HASH_TYPE ref_hash)
{
    const unsigned long page = (offset >> TARGET_PAGE_BITS) >> RSAVE_LAYER1_BANK_BITS;
    rb->rsave_flags[page] &= ~RSAVE_LAYER1_DIRTY;
    memcpy(rb->rsave_l1_hashes[page], ref_hash, sizeof(SHA1_HASH_TYPE));
}

static SHA1_HASH_TYPE *ram_get_l2_reference_page_hash(RAMBlock *rb, ram_addr_t offset)
{
    return &rb->rsave_l2_hashes[offset >> TARGET_PAGE_BITS];
}

static SHA1_HASH_TYPE *ram_get_l1_reference_page_hash(RAMBlock *rb, ram_addr_t offset)
{
    return &rb->rsave_l1_hashes[(offset >> TARGET_PAGE_BITS) >> RSAVE_LAYER1_BANK_BITS];
}

//static void ram_get_reference_page_bank_hash(RAMBlock *rb, ram_addr_t offset, ram_addr_t abs_offset, SHA1_HASH_TYPE ref_hash)
//{
//    // TODO: think about this a little more because now we'll have to parse a different vmstate
//    //memcpy(ref_hash, &rb->rsave_hashes[0][(offset >> TARGET_PAGE_BITS) >> RSAVE_LAYER1_BANK_BITS], sizeof(SHA1_HASH_TYPE));
//}

static bool ram_check_section_header(QEMUFile *f, uint8_t *section_type, uint32_t *section_id, char *se_idstr)
{
    char idstr[UCHAR_MAX+1];

    uint8_t this_type = qemu_get_byte(f);
    *section_type = this_type;
    *section_id = qemu_get_be32(f);

    if (this_type == QEMU_VM_SECTION_FULL ||
        this_type == QEMU_VM_SECTION_START) {
        uint32_t instance_id = -1;
        uint32_t version_id = -1;

        /* ID string */
        size_t len = qemu_get_byte(f);

        qemu_get_buffer(f, (uint8_t *)idstr, len);
        instance_id = qemu_get_be32(f);
        (void)instance_id;
        version_id = qemu_get_be32(f);
        (void)version_id;

        if(memcmp(idstr, se_idstr, len) != 0){
            // error, encountered unexpected section
            printf("Error @ line %d\n",__LINE__);
            return false;
        }
    }

    return true;
}

static bool ram_check_section_footer(QEMUFile *f, uint32_t section_id)
{
    uint8_t flags;

    if (migrate_get_current()->send_section_footer) {
        flags = qemu_get_byte(f);
        if( flags != QEMU_VM_SECTION_FOOTER){
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return false;
        }
        uint32_t end_sid = qemu_get_be32(f);
        if( section_id != end_sid ){
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return false;
        }
    }

    return true;
}

static void ram_get_reference_page_bytes(
    RSaveTree *rst,
    RAMState *rs,
    RAMBlock *rb,
    ram_addr_t offset,
    SHA1_HASH_TYPE ref_hash,
    uint8_t *host_buf)
{
    RAMRapidLoadCache *entry;
    RAMBlock *block;
    VMStateIndexEntry *se;
    uint8_t *peek_buf;
    char idstr[UCHAR_MAX+1];
    int flags;
    QEMUFile *f = NULL;
    RSaveTreeNode *node = NULL;
    RSaveTreeClass *rcc = RSAVE_TREE_GET_CLASS(rst);

    if( rcc->search_ram_cache(rst, offset + rb->offset, ref_hash, host_buf) ){
        return;
    }

    // Look for this node in our cache of previously loaded states.
    QSIMPLEQ_FOREACH(entry, &rs->load_cache, next) {
        if(!memcmp(entry->node->hash, ref_hash, sizeof(SHA1_HASH_TYPE))){
            f = entry->in;
            node = entry->node;
            break;
        }
    }

    // Did we find the node for this hash in our cache?
    if( node == NULL) {
        // We didn't find it so load it from scratch.
        VMStateFileClass *vmstate_file_class = VMSTATE_FILE_GET_CLASS(rst->vm_state_file);

        vmstate_file_class->load_from_hash(rst->vm_state_file, &node, ref_hash);

        uint64_t ram_offset = -1;

        QLIST_FOREACH(se, &node->device_list, next) {
            if( !strcmp(se->idstr, "ram") ) {
                ram_offset = se->offset;
                break;
            }
        }

        if( ram_offset == -1 ){
            // error
            printf("Error @ line %d\n",__LINE__);
            return;
        }

        // Prepare the file container with the VM state and load procedure.
        f = qemu_fopen_ops(node->vm_state, &memory_channel_input_ops);

        qemu_peek_buffer(f, &peek_buf, ram_offset, 0);
        qemu_file_skip(f, ram_offset);

        uint32_t section_id;
        uint8_t section_type;
        if(!ram_check_section_header(f, &section_type, &section_id, se->idstr)){
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return;
        }

        if(!(section_type & (QEMU_VM_SECTION_FULL | QEMU_VM_SECTION_START))) {
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return;
        }

        uint64_t ram_size = qemu_get_be64(f);
        flags = ram_size & ~TARGET_PAGE_MASK;
        ram_size &= TARGET_PAGE_MASK;
        if( flags != RAM_SAVE_FLAG_MEM_SIZE ){
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return;
        }

        // check the ram configuration
        RAMBLOCK_FOREACH_MIGRATABLE(block) {
            uint8_t len = qemu_get_byte(f);

            qemu_get_buffer(f, (uint8_t *)idstr, len);
            if(memcmp(idstr, block->idstr, len) != 0){
                // error, encountered unexpected section
                printf("Error @ line %d\n",__LINE__);
                return;
            }

            uint64_t used_length = qemu_get_be64(f);
            if( block->used_length != used_length ){
                // ram mismatch, ram should not be resizable
                printf("Error @ line %d\n",__LINE__);
                return;
            }

            if (migrate_postcopy_ram() && block->page_size != qemu_host_page_size) {
                uint64_t page_size = qemu_get_be64(f);
                if( block->page_size != page_size ){
                    // ram mismatch
                    printf("Error @ line %d\n",__LINE__);
                    return;
                }
            }
        }

        flags = qemu_get_be64(f);
        if( flags != RAM_SAVE_FLAG_EOS){
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return;
        }

        if(!ram_check_section_footer(f, section_id)){
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return;
        }

        if(!ram_check_section_header(f, &section_type, &section_id, NULL)){
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return;
        }

        if(!(section_type & QEMU_VM_SECTION_PART)){
            // ram mismatch
            printf("Error @ line %d\n",__LINE__);
            return;
        }

        entry = g_new0(RAMRapidLoadCache,1);
        entry->in = f;
        entry->node = node;
        entry->section_id = section_id;
        entry->section_type = section_type;
        QSIMPLEQ_INSERT_TAIL(&rs->load_cache, entry, next);
    }

    bool found_page = false;
    do{
        uint8_t len;
        uint8_t ch;
        ram_addr_t addr = qemu_get_be64(f);
        flags = addr & ~TARGET_PAGE_MASK;
        addr &= TARGET_PAGE_MASK;

        if ((flags & (RAM_SAVE_FLAG_ZERO | RAM_SAVE_FLAG_PAGE |
                    RAM_SAVE_FLAG_DELTA_PAGE | RAM_SAVE_FLAG_DELTA_BANK)) &&
            !(flags & RAM_SAVE_FLAG_CONTINUE)) {
            len = qemu_get_byte(f);
            qemu_get_buffer(f, (uint8_t *)idstr, len);
        }

        switch (flags & ~RAM_SAVE_FLAG_CONTINUE) {
            case RAM_SAVE_FLAG_MEM_SIZE:
                len = qemu_get_byte(f);
                qemu_peek_buffer(f, &peek_buf, len + sizeof(uint64_t), 0);
                qemu_file_skip(f, len + sizeof(uint64_t));
                break;

            case RAM_SAVE_FLAG_DELTA_PAGE:
                // A delta should never point to another delta.
                qemu_peek_buffer(f, &peek_buf, sizeof(SHA1_HASH_TYPE), 0);
                qemu_file_skip(f, sizeof(SHA1_HASH_TYPE));
                break;

            case RAM_SAVE_FLAG_DELTA_BANK:
                // A delta should never point to another delta.
                qemu_peek_buffer(f, &peek_buf, sizeof(SHA1_HASH_TYPE), 0);
                qemu_file_skip(f, sizeof(SHA1_HASH_TYPE));
                break;

            case RAM_SAVE_FLAG_ZERO:
                ch = qemu_get_byte(f);
                if( addr == offset ){
                    memset(host_buf, ch, TARGET_PAGE_SIZE);
                    found_page = true;
                }
                break;

            case RAM_SAVE_FLAG_PAGE:
                if( addr == offset ){
                    qemu_get_buffer(f, host_buf, TARGET_PAGE_SIZE);
                    found_page = true;
                }else{
                    qemu_peek_buffer(f, &peek_buf, TARGET_PAGE_SIZE, 0);
                    qemu_file_skip(f, TARGET_PAGE_SIZE);
                }
                break;

            case RAM_SAVE_FLAG_EOS:
                if(!ram_check_section_footer(f, entry->section_id)){
                    // ram mismatch
                    printf("Error @ line %d\n",__LINE__);
                    return;
                }

                if( entry->section_type != QEMU_VM_SECTION_END ){
                    if(!ram_check_section_header(f, &entry->section_type, &entry->section_id, NULL)){
                        // ram mismatch
                        printf("Error @ line %d\n",__LINE__);
                        return;
                    }
                }
                /* normal exit */
                break;
        }
    }while(!found_page);

    if(found_page){
        rcc->update_ram_cache(rst, offset + rb->offset, ref_hash, host_buf);
    }
}
/*
void ram_rapid_reset_ram_block_deltas(SHA1_HASH_TYPE new_hash)
{
    RAMBlock *block;

    rcu_read_lock();
    RAMBLOCK_FOREACH(block)
    {
        int page = 0;
        while(page < block->max_pages){
            // Look for dirty pages, then clean them and reset their hash.
            if(block->rsave_flags[page >> RSAVE_LAYER1_BANK_BITS] & RSAVE_LAYER1_DIRTY) {
                // At least one page in this bank was dirty...
                uint64_t last_page = MIN(page + RSAVE_LAYER1_BANK_SIZE, block->max_pages);
                for(;page < last_page; page++){
                    // Is this page dirty?
                    if(block->rsave_flags[page] & RSAVE_LAYER2_DIRTY) {
                        memcpy(block->rsave_l2_hashes[page], new_hash, sizeof(SHA1_HASH_TYPE));
                        block->rsave_flags[page] &= ~RSAVE_LAYER2_DIRTY;
                    }
                }
                block->rsave_flags[page >> RSAVE_LAYER1_BANK_BITS] &= ~RSAVE_LAYER1_DIRTY;
            } else {
                // This whole bank was clean so just skip it...
                page += RSAVE_LAYER1_BANK_SIZE;
            }
        }
    }
    rcu_read_unlock();
}
*/
void ram_rapid_get_ram_blocks(MemoryList *mem_list)
{
    RAMBlock *block;

    rcu_read_lock();
    RAMBLOCK_FOREACH(block)
    { 
        MemoryDescriptor *desc = g_new(MemoryDescriptor, 1);

        desc->offset = block->offset;
        desc->size = block->used_length;
        desc->value = block->host;

        QLIST_INSERT_HEAD(mem_list, desc, next);
    }
    rcu_read_unlock();
}

void ram_rapid_get_ram_blocks_deltas(MemoryList *mem_list)
{
    RAMBlock *block;

    rcu_read_lock();
    RAMBLOCK_FOREACH(block)
    { 
        // Count the relative page number wrt the current block
        int page = 0;

        // Loop through the memory pages in the block
        while(page < block->max_pages) 
        {
            // Test if the page has a dirty segment
            if(block->rsave_flags[page >> RSAVE_LAYER1_BANK_BITS] & RSAVE_LAYER1_DIRTY) 
            {
                // We have a dirty segment somewhere, lets find it
                uint64_t last_page = MIN(page + RSAVE_LAYER1_BANK_SIZE, block->max_pages);
                for(;page < last_page; page++) 
                {
                    // Test the segment to see if its dirty
                    if(block->rsave_flags[page] & RSAVE_LAYER2_DIRTY) 
                    {
                        // Create a memory descriptor 
                        MemoryDescriptor *desc = g_new(MemoryDescriptor, 1);

                        // Calculate offset into actual ram
                        desc->offset = block->offset + (page * TARGET_PAGE_SIZE);
                        desc->size = TARGET_PAGE_SIZE;
                        desc->value = &block->host[page * TARGET_PAGE_SIZE];

                        QLIST_INSERT_HEAD(mem_list, desc, next);
                    }
                }
            }
            else
            {
                // The page is clean, move past the whole page
                page += RSAVE_LAYER1_BANK_SIZE;
            }
        }
    }
    rcu_read_unlock();
}

void ram_rapid_set_ram_block(CPUState *cpu, uint64_t offset, uint32_t size, uint8_t *data, bool is_physical)
{
    if( is_physical )
    {
        cpu_physical_memory_rw(offset, data, size, 1);

        // Mark the ram as dirty
        rapid_analysis_mark_ram_dirty(offset, offset + size);
    }else{
        cpu_memory_rw_debug(cpu, offset, data, size, 1);

        // Mark the virtual ram as dirty
        rapid_analysis_mark_vram_dirty(cpu, offset, offset + size);
    }

}

/**
 * save_page_header: write page header to wire
 *
 * If this is the 1st block, it also writes the block identification
 *
 * Returns the number of bytes written
 *
 * @f: QEMUFile where to send the data
 * @block: block that contains the page we want to send
 * @offset: offset inside the block for the page
 *          in the lower bits, it contains flags
 */
static size_t save_page_header(RAMState *rs, QEMUFile *f,  RAMBlock *block,
                               ram_addr_t offset)
{
    size_t size, len;

    if (block == rs->last_sent_block) {
        offset |= RAM_SAVE_FLAG_CONTINUE;
    }
    qemu_put_be64(f, offset);
    size = 8;

    if (!(offset & RAM_SAVE_FLAG_CONTINUE)) {
        len = strlen(block->idstr);
        qemu_put_byte(f, len);
        qemu_put_buffer(f, (uint8_t *)block->idstr, len);
        size += 1 + len;
        rs->last_sent_block = block;
    }
    return size;
}

/**
 * save_default_reference_page: send the reference page to the stream
 *
 * Returns the number of pages written.
 *
 * @rs: current RAM state
 * @block: block that contains the page we want to send
 * @offset: offset inside the block for the page
 *//*
static int save_default_reference_page(RAMState *rs, RAMBlock *block, ram_addr_t offset)
{
    int pages = -1;
    ram_counters.transferred +=
        save_page_header(rs, rs->f, block, offset | RAM_SAVE_FLAG_DELTA_PAGE);
    
    // Use the default hash since this is the first reference save.
    qemu_put_buffer(rs->f, (uint8_t *)rs->default_hash, sizeof(SHA1_HASH_TYPE));

    ram_counters.transferred += sizeof(SHA1_HASH_TYPE);
    ram_counters.normal++;
    pages = 1;

    return pages;
}*/

/**
 * save_l2_reference_page: send the reference page to the stream
 *
 * Returns the number of pages written.
 *
 * @rs: current RAM state
 * @block: block that contains the page we want to send
 * @offset: offset inside the block for the page
 */
static int save_reference_page(RAMState *rs, RAMBlock *block, ram_addr_t offset)
{
    SHA1_HASH_TYPE *clean_hash = ram_get_l2_reference_page_hash(block, offset);
    ram_counters.transferred +=
        save_page_header(rs, rs->f, block, offset | RAM_SAVE_FLAG_DELTA_PAGE);

    qemu_put_buffer(rs->f, (uint8_t *)*clean_hash, sizeof(SHA1_HASH_TYPE));

    ram_counters.transferred += sizeof(SHA1_HASH_TYPE);
    ram_counters.normal++;

    return 1;
}

/**
 * save_default_reference_page_bank: send the reference page bank to the stream
 *
 * Returns the number of pages written.
 *
 * @rs: current RAM state
 * @block: block that contains the page we want to send
 * @offset: offset inside the block for the page
 */
static void save_default_reference_page_bank(RAMState *rs, RAMBlock *block, ram_addr_t offset)
{
    ram_counters.transferred +=
        save_page_header(rs, rs->f, block, offset | RAM_SAVE_FLAG_DELTA_BANK);

    // Use the default hash since this is the first reference save.
    qemu_put_buffer(rs->f, (uint8_t *)rs->default_hash, sizeof(SHA1_HASH_TYPE));
    ram_counters.transferred += sizeof(SHA1_HASH_TYPE);
}

/**
 * save_reference_page_bank: send the reference page bank to the stream
 *
 * Returns the number of pages written.
 *
 * @rs: current RAM state
 * @block: block that contains the page we want to send
 * @offset: offset inside the block for the page
 */
static void save_reference_page_bank(RAMState *rs, RAMBlock *block, ram_addr_t offset)
{
    ram_counters.transferred +=
        save_page_header(rs, rs->f, block, offset | RAM_SAVE_FLAG_DELTA_BANK);

    SHA1_HASH_TYPE *clean_hash = ram_get_l1_reference_page_hash(block, offset);
    qemu_put_buffer(rs->f, (uint8_t *)*clean_hash, sizeof(SHA1_HASH_TYPE));
    ram_counters.transferred += sizeof(SHA1_HASH_TYPE);
}

/**
 * compare_page_l1_to_l2_hash: compares the l1 and l2 hash for a specific page
 *
 * Returns the difference between the two hashes
 *
 * @rs: current RAM state
 * @block: block that contains the hash for our page
 * @offset: offset inside the block for the page
 */
static int compare_page_l1_to_l2_hash(RAMState *rs, RAMBlock *block, ram_addr_t offset)
{
    SHA1_HASH_TYPE *l1_hash = ram_get_l1_reference_page_hash(block, offset);
    SHA1_HASH_TYPE *l2_hash = ram_get_l1_reference_page_hash(block, offset);
    return memcmp(*l1_hash, *l2_hash, sizeof(SHA1_HASH_TYPE));
}

/**
 * save_zero_page: send the zero page to the stream
 *
 * Returns the number of pages written.
 *
 * @rs: current RAM state
 * @block: block that contains the page we want to send
 * @offset: offset inside the block for the page
 */
static int save_zero_page(RAMState *rs, RAMBlock *block, ram_addr_t offset, uint8_t *p)
{
    int pages = -1;

    if (buffer_is_zero(p, TARGET_PAGE_SIZE)) {
        ram_counters.duplicate++;
        ram_counters.transferred +=
            save_page_header(rs, rs->f, block, offset | RAM_SAVE_FLAG_ZERO);
        qemu_put_byte(rs->f, 0);
        ram_counters.transferred += 1;
        pages = 1;
    }

    return pages;
}

/*
 * @pages: the number of pages written by the control path,
 *        < 0 - error
 *        > 0 - number of pages written
 *
 * Return true if the pages has been saved, otherwise false is returned.
 */
static bool control_save_page(RAMState *rs, RAMBlock *block, ram_addr_t offset,
                              int *pages)
{
    uint64_t bytes_xmit = 0;
    int ret;

    *pages = -1;
    ret = ram_control_save_page(rs->f, block->offset, offset, TARGET_PAGE_SIZE,
                                &bytes_xmit);
    if (ret == RAM_SAVE_CONTROL_NOT_SUPP) {
        return false;
    }

    if (bytes_xmit) {
        ram_counters.transferred += bytes_xmit;
        *pages = 1;
    }

    if (ret == RAM_SAVE_CONTROL_DELAYED) {
        return true;
    }

    if (bytes_xmit > 0) {
        ram_counters.normal++;
    } else if (bytes_xmit == 0) {
        ram_counters.duplicate++;
    }

    return true;
}

/*
 * directly send the page to the stream
 *
 * Returns the number of pages written.
 *
 * @rs: current RAM state
 * @block: block that contains the page we want to send
 * @offset: offset inside the block for the page
 * @buf: the page to be sent
 * @async: send to page asyncly
 */
static int save_normal_page(RAMState *rs, RAMBlock *block, ram_addr_t offset, uint8_t *buf)
{
    ram_counters.transferred += save_page_header(rs, rs->f, block,
                                                 offset | RAM_SAVE_FLAG_PAGE);
    qemu_put_buffer(rs->f, buf, TARGET_PAGE_SIZE);
    ram_counters.transferred += TARGET_PAGE_SIZE;
    ram_counters.normal++;

    return 1;
}

/**
 * unqueue_page: gets a page of the queue
 *
 * Helper for 'get_queued_page' - gets a page off the queue
 *
 * Returns the block of the page (or NULL if none available)
 *
 * @rs: current RAM state
 * @offset: used to return the offset within the RAMBlock
 */
static RAMBlock *unqueue_page(RAMState *rs, ram_addr_t *offset)
{
    RAMBlock *block = NULL;

    qemu_mutex_lock(&rs->src_page_req_mutex);
    if (!QSIMPLEQ_EMPTY(&rs->src_page_requests)) {
        struct RAMSrcPageRequest *entry =
                                QSIMPLEQ_FIRST(&rs->src_page_requests);
        block = entry->rb;
        *offset = entry->offset;

        if (entry->len > TARGET_PAGE_SIZE) {
            entry->len -= TARGET_PAGE_SIZE;
            entry->offset += TARGET_PAGE_SIZE;
        } else {
            memory_region_unref(block->mr);
            QSIMPLEQ_REMOVE_HEAD(&rs->src_page_requests, next_req);
            g_free(entry);
            migration_consume_urgent_request();
        }
    }
    qemu_mutex_unlock(&rs->src_page_req_mutex);

    return block;
}

/**
 * get_queued_page: unqueue a page from the postocpy requests
 *
 * Skips pages that are already sent (!dirty)
 *
 * Returns if a queued page is found
 *
 * @rs: current RAM state
 * @pss: data about the state of the current dirty page scan
 */
static bool get_queued_page(RAMState *rs, PageSearchStatus *pss)
{
    RAMBlock  *block;
    ram_addr_t offset;
    bool dirty;

    do {
        block = unqueue_page(rs, &offset);
        /*
         * We're sending this page, and since it's postcopy nothing else
         * will dirty it, and we must make sure it doesn't get sent again
         * even if this queue request was received after the background
         * search already sent it.
         */
        if (block) {
            unsigned long page;

            page = offset >> TARGET_PAGE_BITS;
            dirty = test_bit(page, block->bmap);
            if (dirty) {
                trace_get_queued_page(block->idstr, (uint64_t)offset, page);
            }
        }

    } while (block && !dirty);

    if (block) {
        /*
         * As soon as we start servicing pages out of order, then we have
         * to kill the bulk stage, since the bulk stage assumes
         * in (migration_bitmap_find_and_reset_dirty) that every page is
         * dirty, that's no longer true.
         */
        rs->ram_bulk_stage = false;

        /*
         * We want the background search to continue from the queued page
         * since the guest is likely to want other pages near to the page
         * it just requested.
         */
        pss->block = block;
        pss->page = offset >> TARGET_PAGE_BITS;
    }

    return !!block;
}

/**
 * migration_page_queue_free: drop any remaining pages in the ram
 * request queue
 *
 * It should be empty at the end anyway, but in error cases there may
 * be some left.  in case that there is any page left, we drop it.
 *
 */
static void migration_page_queue_free(RAMState *rs)
{
    struct RAMSrcPageRequest *mspr, *next_mspr;
    /* This queue generally should be empty - but in the case of a failed
     * migration might have some droppings in.
     */
    rcu_read_lock();
    QSIMPLEQ_FOREACH_SAFE(mspr, &rs->src_page_requests, next_req, next_mspr) {
        memory_region_unref(mspr->rb->mr);
        QSIMPLEQ_REMOVE_HEAD(&rs->src_page_requests, next_req);
        g_free(mspr);
    }
    rcu_read_unlock();
}

static void ram_state_cleanup(RAMState **rsp)
{
    if (*rsp) {
        migration_page_queue_free(*rsp);
        qemu_mutex_destroy(&(*rsp)->bitmap_mutex);
        qemu_mutex_destroy(&(*rsp)->src_page_req_mutex);
        g_free(*rsp);
        *rsp = NULL;
    }
}

static void ram_state_reset(RAMState *rs)
{
    rs->last_seen_block = NULL;
    rs->last_sent_block = NULL;
    rs->last_page = 0;
    rs->last_version = ram_list.version;
    rs->ram_bulk_stage = true;
    rs->fpo_enabled = false;
}

static int ram_state_init(RAMState **rsp)
{
    *rsp = g_try_new0(RAMState, 1);

    if (!*rsp) {
        error_report("%s: Init ramstate fail", __func__);
        return -1;
    }

    qemu_mutex_init(&(*rsp)->bitmap_mutex);
    qemu_mutex_init(&(*rsp)->src_page_req_mutex);
    QSIMPLEQ_INIT(&(*rsp)->src_page_requests);

    /*
     * Count the total number of pages used by ram blocks not including any
     * gaps due to alignment or unplugs.
     */
    (*rsp)->migration_dirty_pages = ram_bytes_total() >> TARGET_PAGE_BITS;

    ram_state_reset(*rsp);

    return 0;
}

static void ram_list_init_bitmaps(void)
{
    RAMBlock *block;
    unsigned long pages;

    /* Skip setting bitmap if there is no RAM */
    if (ram_bytes_total()) {
        RAMBLOCK_FOREACH_NOT_IGNORED(block) {
            pages = block->max_length >> TARGET_PAGE_BITS;
            block->bmap = bitmap_new(pages);
            bitmap_set(block->bmap, 0, pages);
        }
    }
}

static void ram_init_bitmaps(RAMState *rs)
{
    /* For memory_global_dirty_log_start below.  */
    qemu_mutex_lock_iothread();
    qemu_mutex_lock_ramlist();
    rcu_read_lock();

    ram_list_init_bitmaps();
    memory_global_dirty_log_start();

    rcu_read_unlock();
    qemu_mutex_unlock_ramlist();
    qemu_mutex_unlock_iothread();
}

static int ram_init_all(RAMState **rsp)
{
    ram_init_bitmaps(*rsp);

    return 0;
}

static void ram_state_resume_prepare(RAMState *rs, QEMUFile *out)
{
    RAMBlock *block;
    uint64_t pages = 0;

    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        pages += bitmap_count_one(block->bmap,
                                  block->used_length >> TARGET_PAGE_BITS);
    }

    /* This may not be aligned with current bitmaps. Recalculate. */
    rs->migration_dirty_pages = pages;

    rs->last_seen_block = NULL;
    rs->last_sent_block = NULL;
    rs->last_page = 0;
    rs->last_version = ram_list.version;
    /*
     * Disable the bulk stage, otherwise we'll resend the whole RAM no
     * matter what we have sent.
     */
    rs->ram_bulk_stage = false;

    /* Update RAMState cache of output QEMUFile */
    rs->f = out;

    trace_ram_state_resume_prepare(pages);
}

void ram_rapid_update_dirty_pages(RAMBlock *rb, size_t start, size_t npages)
{
    qemu_mutex_lock(&ram_state->bitmap_mutex);
    ram_state->migration_dirty_pages -=
                  bitmap_count_one_with_offset(rb->bmap, start, npages);
    bitmap_clear(rb->bmap, start, npages);
    qemu_mutex_unlock(&ram_state->bitmap_mutex);
}

/**
 * ram_save_setup: Setup RAM for migration
 *
 * Returns zero to indicate success and negative for error
 *
 * @f: QEMUFile where to send the data
 * @opaque: RAMState pointer
 */
static int ram_save_setup(QEMUFile *f, void *opaque)
{
    RAMState **rsp = opaque;
    RAMBlock *block;

    /* migration has already setup the bitmap, reuse it. */
    if (ram_init_all(rsp) != 0) {
        return -1;
    }

    (*rsp)->f = f;

    rcu_read_lock();

    qemu_put_be64(f, ram_bytes_total() | RAM_SAVE_FLAG_MEM_SIZE);

    RAMBLOCK_FOREACH_MIGRATABLE(block) {
        qemu_put_byte(f, strlen(block->idstr));
        qemu_put_buffer(f, (uint8_t *)block->idstr, strlen(block->idstr));
        qemu_put_be64(f, block->used_length);
        if (migrate_ignore_shared()) {
            qemu_put_be64(f, block->mr->addr);
            qemu_put_byte(f, ramblock_is_ignored(block) ? 1 : 0);
        }
    }

    rcu_read_unlock();

    ram_control_before_iterate(f, RAM_CONTROL_SETUP);
    ram_control_after_iterate(f, RAM_CONTROL_SETUP);

    qemu_put_be64(f, RAM_SAVE_FLAG_EOS);
    qemu_fflush(f);

    return 0;
}

/**
 * ram_default_save_target_page: save one target page (always saves a reference)
 *
 * Returns the number of pages written
 *
 * @rs: current RAM state
 * @ms: current migration state
 * @pss: data about the page we want to send
 *//*
static int ram_default_save_target_page(RAMState *rs, PageSearchStatus *pss)
{
    RAMBlock *block = pss->block;
    ram_addr_t offset = pss->addr;
    uint8_t *p = block->host + offset;
    int res;

    if (control_save_page(rs, block, offset, &res)) {
        return res;
    }

    res = save_zero_page(rs, block, offset, p);
    if (res > 0) {
        return res;
    }

    return save_default_reference_page(rs, block, offset);
}*/

/**
 * ram_root_save_target_page: save one target page (doesn't save references)
 *
 * Returns the number of pages written
 *
 * @rs: current RAM state
 * @ms: current migration state
 * @pss: data about the page we want to send
 */
static int ram_root_save_target_page(RAMState *rs, PageSearchStatus *pss)
{
    RAMBlock *block = pss->block;
    ram_addr_t offset = pss->addr;
    uint8_t *p = block->host + offset;
    int res;

    if (control_save_page(rs, block, offset, &res)) {
        return res;
    }

    res = save_zero_page(rs, block, offset, p);
    if (res > 0) {
        return res;
    }

    return save_normal_page(rs, block, offset, p);
}

/**
 * ram_delta_save_target_page: save one target page
 *
 * Returns the number of pages written
 *
 * @rs: current RAM state
 * @ms: current migration state
 * @pss: data about the page we want to send
 */
static int ram_delta_save_target_page(RAMState *rs, PageSearchStatus *pss)
{
    RAMBlock *block = pss->block;
    ram_addr_t offset = pss->addr;
    uint8_t *p = block->host + offset;
    int res;

    if (control_save_page(rs, block, offset, &res)) {
        return res;
    }

    // Check if the page actually needs to be a reference
    if( block->rsave_flags[pss->page] & RSAVE_LAYER2_DIRTY ){
        // Was the page set dirty? Then save it off.
        res = save_normal_page(rs, block, offset, p);
    }else if( compare_page_l1_to_l2_hash(rs, block, offset) ) {
        // Does the L1 hash match the L2 hash? If they're different, then use the l2 hash.
        res = save_reference_page(rs, block, offset);
    }else{
        // This page isn't dirty and it's hash matches the L1 so skip it.
        ram_counters.normal++;
        res = 1;
    }

    return res;
}

/**
 * ram_save_host_page: save a whole host page
 *
 * Starting at *offset send pages up to the end of the current host
 * page. It's valid for the initial offset to point into the middle of
 * a host page in which case the remainder of the hostpage is sent.
 * Only dirty target pages are sent. Note that the host page size may
 * be a huge page for this block.
 * The saving stops at the boundary of the used_length of the block
 * if the RAMBlock isn't a multiple of the host page size.
 *
 * Returns the number of pages written or negative on error
 *
 * @rs: current RAM state
 * @ms: current migration state
 * @pss: data about the page we want to send
 * @root_save: if we are the first vm save state
 */
static int ram_save_host_page(RAMState *rs, PageSearchStatus *pss)
{
    int tmppages, pages = 0;
    size_t pagesize_bits =
        qemu_ram_pagesize(pss->block) >> TARGET_PAGE_BITS;

    do {
        /* Check the pages is dirty and if it is send it */
        if (!migration_bitmap_clear_dirty(rs, pss->block, pss->page)) {
            pss->page++;
            continue;
        }

        tmppages = ram_root_save_target_page(rs, pss);
        if (tmppages < 0) {
            return tmppages;
        }

        pages += tmppages;

        pss->page++;
    } while ((pss->page & (pagesize_bits - 1)) &&
             offset_in_ramblock(pss->block, pss->addr));

    /* The offset we leave with is the last one we looked at */
    pss->page--;
    return pages;
}

static void ram_save_iterate_begin(QEMUFile *f, RAMState *rs)
{
    if (ram_list.version != rs->last_version) {
        ram_state_reset(rs);
    }

    /* Read version before ram_list.blocks */
    smp_rmb();

    ram_control_before_iterate(f, RAM_CONTROL_ROUND);
}

static int ram_save_iterate_end(QEMUFile *f)
{
    int ret;

    qemu_put_be64(f, RAM_SAVE_FLAG_EOS);
    qemu_fflush(f);
    ram_counters.transferred += 8;

    ret = qemu_file_get_error(f);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/**
 * ram_delta_save_iterate: iterative stage for migration during delta save
 *
 * Returns zero to indicate success and negative for error
 *
 * @f: QEMUFile where to send the data
 * @opaque: RAMState pointer
 */
static int ram_delta_save_iterate(QEMUFile *f, void *opaque)
{
    RAMState **temp = opaque;
    RAMState *rs = *temp;
    PageSearchStatus pss;
    int ret;
    int i;
    int64_t t0;
    int done = 0;

    if (blk_mig_bulk_active()) {
        /* Avoid transferring ram during bulk phase of block migration as
         * the bulk phase will usually take a long time and transferring
         * ram updates during that time is pointless. */
        ram_save_iterate_end(f);
        return 0;
    }

    rcu_read_lock();

    ram_save_iterate_begin(f, rs);

    t0 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    i = 0;
    while ((ret = qemu_file_rate_limit(f)) == 0 ||
            !QSIMPLEQ_EMPTY(&rs->src_page_requests)) {
        bool pages = 0;
        bool again;

        if (qemu_file_get_error(f)) {
            break;
        }

        /* No dirty page as there is zero RAM */
        if (!ram_bytes_total()) {
            done = 1;
            break;
        }

        pss.block = rs->last_seen_block;
        pss.page = rs->last_page;
        pss.complete_round = false;

        if (!pss.block) {
            pss.block = QLIST_FIRST_RCU(&ram_list.blocks);
        }

        do {
            bool found = get_queued_page(rs, &pss);
            again = true;

            if (!found) {
                /* priority queue empty, so just search for something dirty */
                found = find_dirty_block(rs, &pss, &again);
            }

            if (!qemu_ram_is_migratable(pss.block)) {
                error_report("block %s should not be migrated !", pss.block->idstr);
                continue;
            }

            if ( found ){

                // The layer 1 was dirty so one of the layer 2 entries was dirty
                do {
                    /* Check the pages is dirty and if it is send it */
                    if (migration_bitmap_clear_dirty(rs, pss.block, pss.page)) {
                        // Update our page address
                        pss.addr = pss.page << TARGET_PAGE_BITS;

                        // Are there any RAM flags available in this operation mode?
                        if( pss.block->rsave_flags ){
                            // We're fully operational.
                            uint8_t page_flags = pss.block->rsave_flags[pss.page >> RSAVE_LAYER1_BANK_BITS];

                            // Is this page aligned with our layer 1 bank size?
                            if( !(pss.addr & (RSAVE_LAYER1_BANK_MASK - 1)) ) {
                                // Make a reference to the bank of pages
                                save_reference_page_bank(rs, pss.block, pss.addr);
                            }

                            // When the L1 entry is clean we can skip this page.
                            if(page_flags & RSAVE_LAYER1_DIRTY) {
                                int page_result = ram_delta_save_target_page(rs, &pss);
                                if (page_result < 0) {
                                    pages = page_result;
                                    break;
                                }
                                pages += page_result;
                            }else{
                                // This page was already handled with the bank reference
                                ram_counters.normal++;
                                pages += 1;
                            }
                        }else{
                            // Is this page aligned with our layer 1 bank size?
                            if( !(pss.addr & (RSAVE_LAYER1_BANK_MASK - 1)) ) {
                                // Make a reference to the bank of pages
                                save_default_reference_page_bank(rs, pss.block, pss.addr);
//                                printf("Saved ref bank @ %lX\n", pss.addr);
                            }
                            ram_counters.normal++;
                            pages += 1;
/*
                            // We're partially operational so this must be the initial save.
                            int page_result = ram_default_save_target_page(rs, &pss);
                            if (page_result < 0) {
                                pages = page_result;
                                break;
                            }
                            pages += page_result;*/
                        }
                    }

                    pss.page++;
                } while(offset_in_ramblock(pss.block, pss.page << TARGET_PAGE_BITS));

                /* The offset we leave with is the last one we looked at */
                pss.page--;
            }
        } while (!pages && again);

        rs->last_seen_block = pss.block;
        rs->last_page = pss.page;

        /* no more pages to sent */
        if (pages == 0) {
            done = 1;
            break;
        }

        rs->iterations++;

        /* we want to check in the 1st loop, just in case it was the 1st time
           and we had to sync the dirty bitmap.
           qemu_get_clock_ns() is a bit expensive, so we only check each some
           iterations
        */
        if ((i & 63) == 0) {
            uint64_t t1 = (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - t0) / 1000000;
            if (t1 > DIRTY_SYNC_MAX_WAIT) {
                trace_ram_save_iterate_big_wait(t1, i);
                break;
            }
        }
        i++;
    }

    rcu_read_unlock();

//    printf("Exiting ram_delta_save_iterate\n");

    /*
     * Must occur before EOS (or any QEMUFile operation)
     * because of RDMA protocol.
     */
    ram_control_after_iterate(f, RAM_CONTROL_ROUND);

    ret = ram_save_iterate_end(f);
    if(ret < 0){
        return ret;
    }

    return done;
}

/**
 * ram_root_save_iterate: iterative stage for migration during root save
 *
 * Returns zero to indicate success and negative for error
 *
 * @f: QEMUFile where to send the data
 * @opaque: RAMState pointer
 */
static int ram_root_save_iterate(QEMUFile *f, void *opaque)
{
    RAMState **temp = opaque;
    RAMState *rs = *temp;
    PageSearchStatus pss;
    int ret;
    int done = 0;

    if (blk_mig_bulk_active()) {
        /* Avoid transferring ram during bulk phase of block migration as
         * the bulk phase will usually take a long time and transferring
         * ram updates during that time is pointless. */
        ram_save_iterate_end(f);
        return 0;
    }

    rcu_read_lock();

    ram_save_iterate_begin(f, rs);

    while ((ret = qemu_file_rate_limit(f)) == 0 ||
            !QSIMPLEQ_EMPTY(&rs->src_page_requests)) {
        int pages = 0;
        bool again;

        if (qemu_file_get_error(f)) {
            break;
        }

        /* No dirty page as there is zero RAM */
        if (!ram_bytes_total()) {
            done = 1;
            break;
        }

        pss.block = rs->last_seen_block;
        pss.page = rs->last_page;
        pss.complete_round = false;

        if (!pss.block) {
            pss.block = QLIST_FIRST_RCU(&ram_list.blocks);
        }

        do {
            bool found = get_queued_page(rs, &pss);
            again = true;

            if (!found) {
                /* priority queue empty, so just search for something dirty */
                found = find_dirty_block(rs, &pss, &again);
            }

            if (!qemu_ram_is_migratable(pss.block)) {
                error_report("block %s should not be migrated !", pss.block->idstr);
                continue;
            }

            if ( found ){
                pss.addr = pss.page << TARGET_PAGE_BITS;

                // We're doing a root save so bypass checking the dirty flags
                pages = ram_save_host_page(rs, &pss);
            }
        } while (!pages && again);

        rs->last_seen_block = pss.block;
        rs->last_page = pss.page;

        /* no more pages to send */
        if (pages == 0) {
            done = 1;
            break;
        }

        rs->iterations++;
    }

    rcu_read_unlock();

//    printf("Exiting ram_root_save_iterate\n");

    /*
     * Must occur before EOS (or any QEMUFile operation)
     * because of RDMA protocol.
     */
    ram_control_after_iterate(f, RAM_CONTROL_ROUND);

    ret = ram_save_iterate_end(f);
    if(ret < 0){
        return ret;
    }

    return done;
}

static bool ram_has_postcopy(void *opaque)
{
    return false;
}

/**
 * ram_block_from_stream: read a RAMBlock id from the migration stream
 *
 * Must be called from within a rcu critical section.
 *
 * Returns a pointer from within the RCU-protected ram_list.
 *
 * @f: QEMUFile where to read the data from
 * @flags: Page flags (mostly to see if it's a continuation of previous block)
 */
static inline RAMBlock *ram_block_from_stream(QEMUFile *f, int flags)
{
    static RAMBlock *block = NULL;
    char id[UCHAR_MAX+1];
    uint8_t len;

    if (flags & RAM_SAVE_FLAG_CONTINUE) {
        if (!block) {
            error_report("Ack, bad migration stream!");
            return NULL;
        }
        return block;
    }

    len = qemu_get_byte(f);
    qemu_get_buffer(f, (uint8_t *)id, len);
    id[len] = 0;

    block = qemu_ram_block_by_name(id);
    if (!block) {
        error_report("Can't find block %s", id);
        return NULL;
    }

    if (ramblock_is_ignored(block)) {
        error_report("block %s should not be migrated !", id);
        return NULL;
    }

    return block;
}

static inline void *host_from_ram_block_offset(RAMBlock *block,
                                               ram_addr_t offset)
{
    if (!offset_in_ramblock(block, offset)) {
        return NULL;
    }

    return block->host + offset;
}

static void ram_save_pending(QEMUFile *f, void *opaque, uint64_t max_size,
                             uint64_t *res_precopy_only,
                             uint64_t *res_compatible,
                             uint64_t *res_postcopy_only)
{
    RAMState **temp = opaque;
    RAMState *rs = *temp;
    uint64_t remaining_size;

    remaining_size = rs->migration_dirty_pages * TARGET_PAGE_SIZE;

    *res_precopy_only += remaining_size;
}

static int ram_load(QEMUFile *f, void *opaque, int version_id)
{
    RAMState *rs = *((RAMState **)opaque);
    int flags = 0, ret = 0;
    int len = 0;
    SHA1_HASH_TYPE hash;

    if (version_id != 4) {
        ret = -EINVAL;
    }

    RSaveTree *rst = rapid_analysis_get_instance(NULL);
    if (!rst)
    {
        error_report("Must be running under rapid analysis mode to load rsave snapshots.");
        return -EINVAL;
    }

    /* This RCU critical section can be very long running.
     * When RCU reclaims in the code start to become numerous,
     * it will be necessary to reduce the granularity of this
     * critical section.
     */
    rcu_read_lock();

    //printf("Entered load\n");
    while (!ret && !(flags & RAM_SAVE_FLAG_EOS)) {
        ram_addr_t addr, total_ram_bytes;
        void *host = NULL;
        uint8_t ch;
        RAMBlock *block = NULL;

        addr = qemu_get_be64(f);
        flags = addr & ~TARGET_PAGE_MASK;
        //printf("Flags %X\n", flags);
        addr &= TARGET_PAGE_MASK;
        //printf("Address %lX\n", addr);

        if (flags & (RAM_SAVE_FLAG_COMPRESS_PAGE | RAM_SAVE_FLAG_XBZRLE)) {
            error_report("Received an unexpected compressed page");
            ret = -EINVAL;
            break;
        }

        if( flags & RAM_SAVE_FLAG_MEM_SIZE ){
            /* Synchronize RAM block list */
            //printf("RAM_SAVE_FLAG_MEM_SIZE...\n");
            total_ram_bytes = addr;
            while (!ret && total_ram_bytes) {
                char id[UCHAR_MAX+1];
                ram_addr_t length;

                len = qemu_get_byte(f);
                qemu_get_buffer(f, (uint8_t *)id, len);
                id[len] = 0;
                length = qemu_get_be64(f);

                block = qemu_ram_block_by_name(id);
                if (block && !qemu_ram_is_migratable(block)) {
                    error_report("block %s should not be migrated !", id);
                    ret = -EINVAL;
                } else if (block) {
                    if (length != block->used_length) {
                        Error *local_err = NULL;

                        ret = qemu_ram_resize(block, length,
                                              &local_err);
                        if (local_err) {
                            error_report_err(local_err);
                        }
                    }
                    if (migrate_ignore_shared()) {
                        hwaddr addr = qemu_get_be64(f);
                        bool ignored = qemu_get_byte(f);
                        if (ignored != ramblock_is_ignored(block)) {
                            error_report("RAM block %s should %s be migrated",
                                         id, ignored ? "" : "not");
                            ret = -EINVAL;
                        }
                        if (ramblock_is_ignored(block) &&
                            block->mr->addr != addr) {
                            error_report("Mismatched GPAs for block %s "
                                         "%" PRId64 "!= %" PRId64,
                                         id, (uint64_t)addr,
                                         (uint64_t)block->mr->addr);
                            ret = -EINVAL;
                        }
                    }
                    ram_control_load_hook(f, RAM_CONTROL_BLOCK_REG,
                                          block->idstr);
                } else {
                    error_report("Unknown ramblock \"%s\", cannot "
                                 "accept migration", id);
                    ret = -EINVAL;
                }

                total_ram_bytes -= length;
            }

            if (!ret) {
                ret = qemu_file_get_error(f);
            }

            // We're done here so advance...
            continue;
        }

        if (flags & (RAM_SAVE_FLAG_ZERO | RAM_SAVE_FLAG_PAGE |
                    RAM_SAVE_FLAG_DELTA_PAGE | RAM_SAVE_FLAG_DELTA_BANK)) {

            if( rs->bank_offset < addr || rs->bank_offset > 0 ) {
                ram_addr_t bank_end;
                // A delta bank will never span across different RAM blocks.
                block = ram_block_from_stream(f, rs->bank_offset | RAM_SAVE_FLAG_CONTINUE);
                if(flags & RAM_SAVE_FLAG_CONTINUE){
                    bank_end = addr;
                }else{
                    bank_end = block->used_length;
                }

                //printf("Filling gaps between %lX and %lX...\n", rs->bank_offset, bank_end);

                // Populate the missing pages leading up this address using bank information.
                for( ram_addr_t page = rs->bank_offset; page < bank_end; page += TARGET_PAGE_SIZE )
                {
                    host = host_from_ram_block_offset(block, page);
                    if (!host) {
                        error_report("Illegal RAM offset " RAM_ADDR_FMT, page);
                        ret = -EINVAL;
                        break;
                    }

                    // Proceed to populate this page from the delta bank hash
                    if(ram_page_needs_refresh(block, page, rs->bank_hash))
                    {
                        ram_get_reference_page_bytes(rst, rs, block, page, rs->bank_hash, host);
                        ram_set_l2_reference_page_hash(block, page, rs->bank_hash);
                        ram_clean_l2_page(block, page);
                    }
                }
            }

            // Now get the ram block again for the newest address.
            block = ram_block_from_stream(f, flags);

            host = host_from_ram_block_offset(block, addr);
            if (!host) {
                error_report("Illegal RAM offset " RAM_ADDR_FMT, addr);
                ret = -EINVAL;
                break;
            }

            // Advance our bank offset to the next expected page
            //printf("Advance to %lX\n", addr);
            rs->bank_offset = addr;
        }

        // Process the RAM directive
        switch (flags & ~RAM_SAVE_FLAG_CONTINUE) {
        case RAM_SAVE_FLAG_ZERO:
           // printf("RAM_SAVE_FLAG_ZERO...\n");
            ch = qemu_get_byte(f);
            ram_handle_zero_page(host, ch, TARGET_PAGE_SIZE);
            ram_set_l2_reference_page_hash(block, addr, rst->active_hash);
            ram_clean_l2_page(block, addr);
            rs->bank_offset += TARGET_PAGE_SIZE;
            break;

        case RAM_SAVE_FLAG_PAGE:
            //printf("RAM_SAVE_FLAG_PAGE...\n");
            qemu_get_buffer(f, host, TARGET_PAGE_SIZE);
            ram_set_l2_reference_page_hash(block, addr, rst->active_hash);
            ram_clean_l2_page(block, addr);
            rs->bank_offset += TARGET_PAGE_SIZE;
            break;

        case RAM_SAVE_FLAG_DELTA_PAGE:
           // printf("RAM_SAVE_FLAG_DELTA_PAGE...\n");
            qemu_get_buffer(f, (uint8_t*)hash, sizeof(SHA1_HASH_TYPE));
            if(ram_page_needs_refresh(block, addr, hash))
            {
                ram_get_reference_page_bytes(rst, rs, block, addr, hash, host);
                ram_set_l2_reference_page_hash(block, addr, hash);
                ram_clean_l2_page(block, addr);
            }
            rs->bank_offset += TARGET_PAGE_SIZE;
            break;

        case RAM_SAVE_FLAG_DELTA_BANK:
            // Load the attributes for this bank
          //  printf("RAM_SAVE_FLAG_DELTA_BANK...\n");
            qemu_get_buffer(f, (uint8_t*)rs->bank_hash, sizeof(SHA1_HASH_TYPE));
            ram_set_l1_reference_page_hash(block, addr, rs->bank_hash);
            ram_clean_l1_page(block, addr);
            break;

        case RAM_SAVE_FLAG_EOS:
            /* normal exit */
            break;

        default:
            if (flags & RAM_SAVE_FLAG_HOOK) {
                ram_control_load_hook(f, RAM_CONTROL_HOOK, NULL);
            } else {
                error_report("Unknown combination of migration flags: %#x",
                             flags);
                ret = -EINVAL;
            }
        }

        if (!ret) {
            ret = qemu_file_get_error(f);
        }
    }
    //printf("Exited load\n");

    rcu_read_unlock();

    return ret;
}

static void ram_save_cleanup(void *opaque)
{
    RAMBlock *block;

    /* caller have hold iothread lock or is in a bh, so there is
     * no writing race against this migration_bitmap
     */
    memory_global_dirty_log_stop();

    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        g_free(block->bmap);
        block->bmap = NULL;
    }
}

/**
 * ram_load_setup: Setup RAM for migration incoming side
 *
 * Returns zero to indicate success and negative for error
 *
 * @f: QEMUFile where to receive the data
 * @opaque: RAMState pointer
 */
static int ram_load_setup(QEMUFile *f, void *opaque)
{
    RAMState *rs = *((RAMState**)opaque);

    QSIMPLEQ_INIT(&rs->load_cache);
    rs->bank_offset = 0;

    return 0;
}

static int ram_load_cleanup(void *opaque)
{
    RAMRapidLoadCache *entry;
    RAMRapidLoadCache *next_entry;
    RAMState *rs = *((RAMState**)opaque);

    if(!QSIMPLEQ_EMPTY(&rs->load_cache)) {
        QSIMPLEQ_FOREACH_SAFE(entry, &rs->load_cache, next, next_entry) {
            QSIMPLEQ_REMOVE_HEAD(&rs->load_cache, next);
            qemu_fclose(entry->in);
            object_unref(OBJECT(entry->node));
            g_free(entry);
        }
    }

    return 0;
}

static int ram_resume_prepare(MigrationState *s, void *opaque)
{
    RAMState *rs = *(RAMState **)opaque;

    ram_state_resume_prepare(rs, s->to_dst_file);

    return 0;
}

static SaveVMHandlers rootsave_ram_handlers = {
    .save_setup = ram_save_setup,
    .save_live_iterate = ram_root_save_iterate,
    .save_live_complete_postcopy = NULL,
    .save_live_complete_precopy = NULL,
    .has_postcopy = ram_has_postcopy,
    .save_live_pending = ram_save_pending,
    .load_state = ram_load,
    .save_cleanup = ram_save_cleanup,
    .load_setup = ram_load_setup,
    .load_cleanup = ram_load_cleanup,
    .resume_prepare = ram_resume_prepare,
};

static SaveVMHandlers deltasave_ram_handlers = {
    .save_setup = ram_save_setup,
    .save_live_iterate = ram_delta_save_iterate,
    .save_live_complete_postcopy = NULL,
    .save_live_complete_precopy = NULL,
    .has_postcopy = ram_has_postcopy,
    .save_live_pending = ram_save_pending,
    .load_state = ram_load,
    .save_cleanup = ram_save_cleanup,
    .load_setup = ram_load_setup,
    .load_cleanup = ram_load_cleanup,
    .resume_prepare = ram_resume_prepare,
};

void ram_rapid_init(Error **errp)
{
    if (ram_state_init(&ram_state)) {
        error_setg(errp, "Failed to initialize ram migration state for rapid analysis");
        return;
    }

    if(migrate_colo_enabled()){
        error_setg(errp, "COLO is not supported with rapid analysis");
        return;
    }

    if(migrate_postcopy_ram()){
        error_setg(errp, "Postcopy RAM is not supported with rapid analysis");
        return;
    }

    if(migrate_use_multifd()){
        error_setg(errp, "MultiFD is not supported with rapid analysis");
        return;
    }

    register_savevm_live(NULL, "ram", 0, 4, &rootsave_ram_handlers, &ram_state);
}

void ram_rapid_delta_init(QemuOpts *ra_opts, SHA1_HASH_TYPE *root_hash, Error **errp)
{
    (void)ra_opts;
    if (ram_state_init(&ram_state)) {
        error_setg(errp, "Failed to initialize ram migration state for delta rapid analysis");
        return;
    }

    if(migrate_colo_enabled()){
        error_setg(errp, "COLO is not supported with rapid analysis");
        return;
    }

    if(migrate_postcopy_ram()){
        error_setg(errp, "Postcopy RAM is not supported with rapid analysis");
        return;
    }

    if(migrate_use_multifd()){
        error_setg(errp, "MultiFD is not supported with rapid analysis");
        return;
    }

    if( root_hash ){
        memcpy(ram_state->default_hash, *root_hash, sizeof(SHA1_HASH_TYPE));
    }

    register_savevm_live(NULL, "ram", 0, 4, &deltasave_ram_handlers, &ram_state);
}

void ram_rapid_destroy(void)
{
    unregister_savevm(NULL, "ram", &ram_state);
    ram_state_cleanup(&ram_state);
    ram_state = NULL;
}
