/*
 * QEMU snapshots
 *
 * Copyright (c) 2004-2008 Fabrice Bellard
 * Copyright (c) 2009-2015 Red Hat Inc
 *
 * Authors:
 *  Juan Quintela <quintela@redhat.com>
 *
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_MIGRATION_SNAPSHOT_H
#define QEMU_MIGRATION_SNAPSHOT_H

#include "rsave-tree.h"
#include "racomms/interface.h"
#include "racomms/racomms-types.h"

int save_snapshot(const char *name, Error **errp);
int save_snapshot_rsave(const char *filename, Error **errp);
int load_snapshot(const char *name, Error **errp);
int load_snapshot_rsave(const char *filename, SHA1_HASH_TYPE *hash, Error **errp);
void increment_snapshot_rsave(CPUState *cpu, RSaveTree *rst, TranslationBlock *tb);
bool load_work(CPUState *cpu, RSaveTree *rst);
void close_work(RSaveTree *rst, CPUState *cpu, SHA1_HASH_TYPE job_hash, bool send_results);
CommsMessage *build_rsave_report(RSaveTree *rst, SHA1_HASH_TYPE job_hash, JOB_REPORT_TYPE report_mask, CommsQueue *queue);

#endif
