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

#ifndef QEMU_MIGRATION_RAM_XBZRLE_H
#define QEMU_MIGRATION_RAM_XBZRLE_H

uint64_t get_ram_dirty_pages(void);
int ram_xbzrle_save_queue_pages(const char *rbname, ram_addr_t start, ram_addr_t len);
int ram_xbzrle_postcopy_send_discard_bitmap(MigrationState *ms);
void ram_xbzrle_postcopy_chunk_hostpages_pass(MigrationState *ms, bool unsent_pass,
                                          RAMBlock *block, PostcopyDiscardState *pds);
void ram_xbzrle_precopy_enable_free_page_optimization(void);
void ram_xbzrle_update_dirty_pages(RAMBlock *rb, size_t start, size_t npages);
uint64_t ram_xbzrle_get_total_transferred_pages(void);

#endif
