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
 * The creation of this code was funded by the US Government. Use of this code for any
 * purpose other than those authorized by the funding US Government may be subject to restrictions.
 * 
 * Neither party is granted any right or license other than the existing licenses
 * and covenants expressly stated herein. Cromulence LLC retains all right, title and interest to
 * Reference Code and Technology Specifications and You retain all right, title and interest
 * in Your Modifications and associated specifications as permitted by the existing license.
 * Except as expressly permitted herein, You must not otherwise use any package, class or
 * interface naming conventions that appear to originate from Original Contributor.
 */
#include "qemu/qemu-plugin.hpp"
#include "plugin/display_cb.h"
#include "plugin/plugin-console.h"

#include "QEMUWrapper.h"
#include "QtWrapper.h"

void QEMU_do_shutdown()
{
    display_request_shutdown();
}

void QEMU_process_key_event(int keyNum, bool keyDown)
{
    QemuConsole *con = NULL;
    int keycode = getScanCode(keyNum);

    for(int i = 0; ; ++i)
    {
        con = display_console_lookup_by_index(i);

        if(!con)
        {
            break;
        }

        if (display_console_is_graphic(con))
        {
            display_process_graphic_key_event(con, keycode, keyDown);
        }
    }  
}

void QEMU_command_send(const char *cmdline)
{
    qemu_console_send(cmdline);
}

