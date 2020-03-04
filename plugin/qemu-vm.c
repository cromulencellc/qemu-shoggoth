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
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"

#include "qemu-vm.h"

void continue_vm(Error **errp)
{
    BlockBackend *blk;
    Error *local_err = NULL;

    /* if there is a dump in background, we should wait until the dump
     * finished */
    if (dump_in_progress()) 
    {
        error_setg(errp, "There is a dump in process, please wait.");
        return;
    }

    if (runstate_needs_reset()) 
    {
        error_setg(errp, "Resetting the Virtual Machine is required");
        return;
    } else if (runstate_check(RUN_STATE_SUSPENDED)) 
    {
        return;
    }

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) 
    {
        blk_iostatus_reset(blk);
    }

    /* Continuing after completed migration. Images have been inactivated to
     * allow the destination to take control. Need to get control back now.
     *
     * If there are no inactive block nodes (e.g. because the VM was just
     * paused rather than completing a migration), bdrv_inactivate_all() simply
     * doesn't do anything. */
    bdrv_invalidate_cache_all(&local_err);
    if (local_err) 
    {
        error_propagate(errp, local_err);
        return;
    }

    if (runstate_check(RUN_STATE_INMIGRATE)) 
    {
        autostart = 1;
    } else 
    {
        vm_start();
    }
}

void stop_vm(Error **errp)
{
    /* if there is a dump in background, we should wait until the dump
     * finished */
    if (dump_in_progress()) 
    {
        error_setg(errp, "There is a dump in process, please wait.");
        return;
    }

    if (runstate_check(RUN_STATE_INMIGRATE)) 
    {
        autostart = 0;
    } else 
    {
        vm_stop(RUN_STATE_PAUSED);
    }
}

void shutdown_vm(Error **errp) 
{
    qemu_system_powerdown_request();
}

void reset_vm(Error **errp) 
{
    // This isn't quite QMP, but we want qmp-like behavior
    qemu_system_reset_request(SHUTDOWN_CAUSE_HOST_QMP);
}

void quit_vm(Error **errp) 
{
    no_shutdown = 0;

    // This isn't quite QMP, but we want qmp-like behavior
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_QMP);
}