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

#ifndef __RA_H__
#define __RA_H__

#include "qemu/option.h"
#include "qemu-options.h"
#include "racomms/racomms-types.h"
#include "rsave-tree.h"
#include "migration/rsave-tree-node.h"
#include "racomms/interface.h"

extern QemuOptsList qemu_rapidanalysis_opts;

QemuOpts *rapid_analysis_parse(const char *optstr);
RSaveTree *rapid_analysis_get_instance(CPUState *cpu);
bool is_rapid_analysis_active(void);
bool rapid_analysis_awaiting_work(CPUState *cpu);
bool rapid_analysis_load_work(CPUState *cpu);
void rapid_analysis_end_work(CPUState *cpu, bool send_report);
void rapid_analysis_increment_analysis(CPUState *cpu, TranslationBlock *tb);
void rapid_analysis_set_configuration(CommsRequestConfigMsg *req, CommsQueue *q);
void rapid_analysis_send_tree(CommsRequestRapidSaveTreeMsg *req, CommsQueue *q);
void rapid_analysis_accel_init(QemuOpts *ra_opts, QemuOpts *accel_opts, Error **errp);
void rapid_analysis_drive_init(QemuOpts *ra_opts, MachineState *machine);
void rapid_analysis_init(QemuOpts *ra_opts, MachineState *machine);
void rapid_analysis_cleanup(MachineState *machine);
void rapid_analysis_partial_init(Error **errp);
void rapid_analysis_partial_delta(SHA1_HASH_TYPE *root_hash, Error **errp);
void rapid_analysis_partial_cleanup(void);
void rapid_analysis_mark_ram_dirty(hwaddr start, hwaddr end);
void rapid_analysis_mark_vram_dirty(CPUState *cpu, hwaddr start, hwaddr end);
void rapid_analysis_mark_ram_clean(hwaddr start, hwaddr end);
void rapid_analysis_set_error(uint32_t error_id_in, uint64_t error_loc_in, const char *error_text_in);
void rapid_analysis_clear_error(void);
bool rapid_analysis_handle_syscall(CPUState *cs, uint64_t number, ...);
bool rapid_analysis_has_error(void);
uint32_t rapid_analysis_get_error_id(void);
uint64_t rapid_analysis_get_error_loc(void);
const char *rapid_analysis_get_error_text(void);

#endif
