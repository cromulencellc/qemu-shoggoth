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

#ifndef QEMU_MIGRATION_RAM_RAPID_H
#define QEMU_MIGRATION_RAM_RAPID_H

#include "racomms/racomms-types.h"
#include "ra-types.h"

void ram_rapid_blocks_init(void);
void ram_rapid_blocks_cleanup(void);
uint64_t get_ram_rapid_dirty_pages(void);
void ram_rapid_set_ram_block(CPUState *cpu, uint64_t offset, uint32_t size, uint8_t *data, bool is_physical);
int ram_rapid_save_queue_pages(const char *rbname, ram_addr_t start, ram_addr_t len);
int ram_rapid_postcopy_send_discard_bitmap(MigrationState *ms);
void ram_rapid_postcopy_chunk_hostpages_pass(MigrationState *ms, bool unsent_pass,
                                          RAMBlock *block, PostcopyDiscardState *pds);
void ram_rapid_get_ram_blocks(MemoryList *mem_list);
void ram_rapid_get_ram_blocks_deltas(MemoryList *mem_list);
void ram_rapid_update_dirty_pages(RAMBlock *rb, size_t start, size_t npages);
uint64_t ram_rapid_get_total_transferred_pages(void);
void ram_rapid_precopy_enable_free_page_optimization(void);

#endif
