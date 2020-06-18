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

#include "qemu/osdep.h"
#include "trace.h"
#include "qapi/error.h"
#include "qemu/job.h"
#include "block/block.h"
#include "block/block_int.h"
#include "block/blockjob_int.h"
#include "sysemu/block-backend.h"

typedef struct DumpBlockJob {
    BlockJob common;
    BlockDriverState *target;
    SHA1_HASH_TYPE hash;
} DumpBlockJob;

static const BlockJobDriver dump_job_driver;

typedef struct {
    int ret;
} DumpCompleteData;

static void dump_complete(Job *job, void *opaque)
{
    DumpCompleteData *data = opaque;

    job_completed(job);
    data->ret = job->ret;
    g_free(data);
}

static int coroutine_fn dump_run(Job *job, Error **errp)
{
    DumpBlockJob *s = container_of(job, DumpBlockJob, common.job);
    BlockDriverState *bs = blk_bs(s->common.blk);
    DumpCompleteData *data;
    int ret = 0;

    if (bs)
    {
        BlockDriver *drv = bs->drv;
        if (drv && drv->bdrv_dump_state)
        {
            ret = drv->bdrv_dump_state(bs, s->target, s->hash);
        }
    }

    data = g_malloc(sizeof(*data));
    data->ret = ret;
    job_defer_to_main_loop(job, dump_complete, data);
    return 0;
}

static void dump_commit(Job *job)
{
//    printf("dump_commit");  
}

static void dump_abort(Job *job)
{
//    printf("dump_abort");
}

static void dump_clean(Job *job)
{
//    printf("dump_clean");
}

static void dump_attached_aio_context(BlockJob *job, AioContext *aio_context)
{ 
//    printf("dump_attached_aio_context");  
}

static void dump_drain(BlockJob *job)
{
//    printf("dump_drain");
}

static const BlockJobDriver dump_job_driver = {
    .job_driver = {
        .instance_size          = sizeof(DumpBlockJob),
        .job_type               = JOB_TYPE_BACKUP,
        .free                   = block_job_free,
        .user_resume            = block_job_user_resume,
        .drain                  = block_job_drain,
        .run                    = dump_run,
        .commit                 = dump_commit,
        .abort                  = dump_abort,
        .clean                  = dump_clean,
    },
    .attached_aio_context   = dump_attached_aio_context,
    .drain                  = dump_drain,
};


BlockJob *dump_job_create(const char *job_id, BlockDriverState *bs, BlockDriverState *target, SHA1_HASH_TYPE hash, Error **errp)
{
    int64_t len;
    DumpBlockJob *job = NULL;

    if (bs && target)
    { 
        if (bdrv_is_inserted(bs))
        {
            if (!bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_BACKUP_SOURCE, NULL))
            {
                len = bdrv_getlength(bs);
                if (len >= 0) 
                {
                    // For now, we will borrow these values from the
                    // block_job_create call in backup_job_create (backup.c)
                    job = block_job_create(job_id, &dump_job_driver, NULL, bs,
                                           BLK_PERM_CONSISTENT_READ,
                                           BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE |
                                           BLK_PERM_WRITE_UNCHANGED | BLK_PERM_GRAPH_MOD,
                                           0, JOB_DEFAULT, NULL, NULL, errp);
                    if (job)
                    {

                        block_job_add_bdrv(&job->common, "target", target, 0, BLK_PERM_ALL, errp);

                        job->target = target;
                        memcpy(job->hash, hash, sizeof(SHA1_HASH_TYPE));
                        return &job->common;
                    }  
                } 
                else
                {
                    error_prepend(errp, "%s was empty\n", bs->filename);
                }
            }
            else
            {
                error_prepend(errp, "%s does not support backup\n", bs->filename);   
            }
        }
        else 
        {
            error_prepend(errp, "%s is not inserted\n", bs->filename);
        }
    }
    else
    {
        error_prepend(errp, "Source and target drives cannot be null\n"); 
    }
    return NULL;                  
}

void synchronous_dump_job(const char *job_id, BlockDriverState *bs, BlockDriverState *target, SHA1_HASH_TYPE hash, Error **errp)
{
    int64_t len;

    // Do we have all the required args?
    if (bs && target)
    { 
        // Is the source inserted?
        if (bdrv_is_inserted(bs))
        {
            // Can we perform this operation
            if (!bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_BACKUP_SOURCE, NULL))
            {
                // Is the source of length 0
                len = bdrv_getlength(bs);
                if (len >= 0) 
                { 
                    // Douse the source have the dump function
                    BlockDriver *drv = bs->drv;
                    if (drv->bdrv_dump_state)
                    {
                        // Perform the dump
                        drv->bdrv_dump_state(bs, target, hash);
                    }
                    else
                    {
                        error_prepend(errp, "Source cannot dumpl\n");    
                    }
                } 
                else
                {
                    error_prepend(errp, "%s was empty\n", bs->filename);
                }
            }
            else
            {
                error_prepend(errp, "%s does not support backup\n", bs->filename);   
            }
        }
        else 
        {
            error_prepend(errp, "%s is not inserted\n", bs->filename);
        }
    }
    else
    {
        error_prepend(errp, "Source and target drives cannot be null\n"); 
    }                                       
}

