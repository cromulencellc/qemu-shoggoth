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

#ifndef __QEMU_PLUGIN_HPP__
#define __QEMU_PLUGIN_HPP__

#include <cstdint>
#include <cstdlib>

#ifdef __cplusplus
extern "C" {
#endif

#include "qemu/osdep.h"
#include "qemu/compiler.h"
#include "qemu/typedefs.h"
#include "qemu/option.h"
#include "qemu/option_int.h"
#include "cpp/qom/object.hpp"
#include "racomms/interface.h"
#include "racomms/racomms-types.h"

void qemu_plugin_register_type(void *opaque, TypeInfo *plugin_type);
void qemu_plugin_register_options(void *opaque, QemuOptsList *opts);
void qemu_plugin_register_commands(void *opaque, QemuOptsList *commands);
void qemu_plugin_register_loader(void *opaque, const char *pattern, TypeInfo *plugin_subtype);

bool plugin_setup(void *plugin, const char *path);

#ifdef __cplusplus
}
#endif

#endif