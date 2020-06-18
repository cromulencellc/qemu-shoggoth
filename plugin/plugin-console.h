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

#ifndef __PLUGIN_CONSOLE_H__
#define __PLUGIN_CONSOLE_H__


#ifdef __cplusplus
extern "C"{
#endif

// Pull in items from display_cb.h
// This will be in line with other items in this directory.

void qemu_console_set_printf(void *opaque, void(*p)(void *opaque, const char *fmt, ...));
void qemu_console_set_pretty_printf(void *opaque, void(*p)(void *opaque, const char *fmt, ...));
void qemu_console_send(const char *cmdline);

#ifdef __cplusplus
}
#endif

#endif