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
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include "ui/console.h"
#include "qemu/cutils.h"
#include "qapi/qapi-commands-ui.h"
#include "plugin/plugin-error.h"
#include "block/qapi.h"
#include "hw/boards.h"

#include "qemu-vm.h"

extern RunState current_run_state;

void qemu_vm_continue(void)
{
    BlockBackend *blk;
    Error *local_err = NULL;

    /* if there is a dump in background, we should wait until the dump
     * finished */
    if (dump_in_progress()) 
    {
        return;
    }

    if (runstate_needs_reset()) 
    {
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

void qemu_vm_stop(int reason)
{
    vm_stop(reason);
}

void qemu_vm_shutdown(void)
{
    qemu_system_powerdown_request();
}

void qemu_vm_reset(void)
{
    // This isn't quite QMP, but we want qmp-like behavior
    qemu_system_reset_request(SHUTDOWN_CAUSE_HOST_QMP_QUIT);
}

void qemu_vm_quit(void)
{
    no_shutdown = 0;

    // This isn't quite QMP, but we want qmp-like behavior
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_QMP_QUIT);
}

int qemu_vm_get_state(void)
{
    return current_run_state;
}

void qemu_vm_send_key(const char *keys)
{
    KeyValueList *keylist, *head = NULL, *tmp = NULL;
    const char *separator;
    int keyname_len;

    while (1) {
        separator = qemu_strchrnul(keys, '-');
        keyname_len = separator - keys;

        /* Be compatible with old interface, convert user inputted "<" */
        if (keys[0] == '<' && keyname_len == 1) {
            keys = "less";
            keyname_len = 4;
        }

        keylist = g_malloc0(sizeof(*keylist));
        keylist->value = g_malloc0(sizeof(*keylist->value));

        if (!head) {
            head = keylist;
        }
        if (tmp) {
            tmp->next = keylist;
        }
        tmp = keylist;

        if (strstart(keys, "0x", NULL)) {
            char *endp;
            int value = strtoul(keys, &endp, 0);
            assert(endp <= keys + keyname_len);
            if (endp != keys + keyname_len) {
                qapi_free_KeyValueList(head);
                return;
            }
            keylist->value->type = KEY_VALUE_KIND_NUMBER;
            keylist->value->u.number.data = value;
        } else {
            int idx = index_from_key(keys, keyname_len);
            if (idx == Q_KEY_CODE__MAX) {
                qapi_free_KeyValueList(head);
                return;
            }
            keylist->value->type = KEY_VALUE_KIND_QCODE;
            keylist->value->u.qcode.data = idx;
        }

        if (!*separator) {
            break;
        }
        keys = separator + 1;
    }

    qemu_vm_send_keylist(head, false, -1);
    qapi_free_KeyValueList(head);
}

void qemu_vm_send_keylist(KeyValueList *keys, bool has_hold_time, int64_t hold_time)
{
    Error *local_err = NULL;
    qmp_send_key(keys, has_hold_time, hold_time, &local_err);
}

static const char base_keys[]     = ",./;\'[]\\`1234567890-=abcdefghijklmnopqrstuvwxyz";
static const char shifted_keys[]  = "<>?:\"{}|~!@#$%^&*()_+ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *special_keys[] = {
    "comma",
    "dot",
    "slash",
    "semicolon",
    "apostrophe",
    "bracket_left",
    "bracket_right",
    "backslash",
    "grave_accent",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "minus",
    "equal",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

void qemu_vm_send_keystring(const char *string)
{
    int k, idx;

    while(*string){
        KeyValueList *keylist = NULL;
        KeyValueList **keycur = &keylist;
        const char *chstr = NULL;
        int chlen = 0;

        if(isspace(*string)){
            // Handle whitespace.
            if(*string == ' '){
                chstr = "spc";
            }else
            if(*string == '\t'){
                chstr = "tab";
            }

            if(chstr){
                chlen = strlen(chstr);
            }
        }else{
            // This loop will only accept readable characters.
            for(k=0; k < sizeof(shifted_keys); k++){
                if(*string == shifted_keys[k]){
                    // Found shifted character
                    keylist = g_malloc0(sizeof(*keylist));
                    keylist->value = g_malloc0(sizeof(*keylist->value));
                    idx = index_from_key("shift", strlen("shift"));
                    keylist->value->type = KEY_VALUE_KIND_QCODE;
                    keylist->value->u.qcode.data = idx;
                    // Advance current key
                    keycur = &(keylist->next);

                    chstr = &base_keys[k];
                    chlen = 1;
                    break;
                }else if(*string == base_keys[k]){
                    // Found unshifted character
                    chstr = string;
                    chlen = 1;
                    break;
                }
            }

            if(chlen == 1 && special_keys[k] != NULL){
                chstr = special_keys[k];
                chlen = strlen(special_keys[k]);
            }
        }

        if(chstr){
            (*keycur) = g_malloc0(sizeof(*keylist));
            (*keycur)->value = g_malloc0(sizeof(*keylist->value));
            idx = index_from_key(chstr, chlen);
            (*keycur)->value->type = KEY_VALUE_KIND_QCODE;
            (*keycur)->value->u.qcode.data = idx;

            qemu_vm_send_keylist(keylist, false, -1);
            qapi_free_KeyValueList(keylist);
        }

        string++;
    }
}

bool qemu_vm_save_screenshot(const char *file_name,
    bool has_device,
    const char *device,
    bool has_head,
    int64_t head)
{
    Error *err = NULL;
    qmp_screendump(file_name, has_device, device, has_head, head, &err);
    if(err){
        qemu_plugin_last_error = err;
        return false;
    }

    return true;
}

void qemu_vm_get_snapshots(ImageInfoList **snapshots)
{
    Error *err = NULL;
    ImageInfoList **last = snapshots;
    BlockDriverState *blocks = bdrv_all_find_vmstate_bs();
    *snapshots = NULL;

    // If the file opened, we will now get info
    if (blocks)
    {
        *last = g_new0(ImageInfoList, 1);

        bdrv_query_image_info(blocks, &((*last)->value), &err);
        if (err) {
            return;
        }
    }
}

const char *qemu_vm_get_arch(int cpu_idx)
{
    MachineClass *mc = MACHINE_GET_CLASS(current_machine);
    const CPUArchIdList *cpus = mc->possible_cpu_arch_ids(current_machine);
    if (cpus && cpu_idx < cpus->len){
        const CPUArchId *arch = &cpus->cpus[cpu_idx];
        if(arch){
            return arch->type;
        }
    }

    return NULL;
}
