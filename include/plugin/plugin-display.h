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

#ifndef __PLUGIN_DISPLAY_H__
#define __PLUGIN_DISPLAY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/object.h"
#include "qemu/typedefs.h"
#include "ui/types.h"

// ****************************************************** //
// **********       Plugin Class Setup        ********** //
// **************************************************** //

#define TYPE_DISPLAY_PLUGIN_OBJECT "DisplayPluginObject"
#define DISPLAY_PLUGIN_OBJECT(obj)                                    \
    OBJECT_CHECK(DisplayPluginObject, (obj), TYPE_DISPLAY_PLUGIN_OBJECT)
#define DISPLAY_PLUGIN_OBJECT_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(DisplayPluginClass, klass, TYPE_DISPLAY_PLUGIN_OBJECT)
#define DISPLAY_PLUGIN_OBJECT_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(DisplayPluginClass, obj, TYPE_DISPLAY_PLUGIN_OBJECT)

typedef struct DisplayPluginImplementation DisplayPluginImplementation;
typedef struct DisplayPluginObject DisplayPluginObject;
typedef struct DisplayPluginClass DisplayPluginClass;

struct DisplayPluginImplementation
{
    void (*pre_early_init)(void *plugin);
    void (*post_early_init)(void *plugin);
    void (*pre_init)(void *plugin);
    void (*post_init)(void *plugin);
    void (*pre_display_callback_register)(void *plugin);
    void (*post_display_callback_register)(void *plugin);
    void (*pre_display_change_listener_register)(void *plugin);
    void (*post_display_change_listener_register)(void *plugin);
    void (*pre_mouse_change_notifier_register)(void *plugin);
    void (*post_mouse_change_notifier_register)(void *plugin);
    void (*do_console_operations)(void *plugin, QemuConsole *console);
    void (*on_exit)(void *plugin);
    void (*plugin_display_gfx_update)(void *plugin, DisplayChangeListener *dcl, int x, int y, int w, int h);
    void (*plugin_display_gfx_switch)(void *plugin, DisplayChangeListener *dcl, struct DisplaySurface *new_surface);
    bool (*plugin_display_gfx_check_format)(void *plugin, DisplayChangeListener *dcl, pixman_format_code_t format);
    QemuConsole *(*plugin_display_refresh)(void *plugin, DisplayChangeListener *dcl);
    void (*plugin_display_mouse_set)(void *plugin, DisplayChangeListener *dcl, int x, int y, int on);
    void (*plugin_display_cursor_define)(void *plugin, DisplayChangeListener *dcl, QEMUCursor *cursor);
    /**
     * For now we are missing some callbacks (Example 3D console callbacks). They can be added as needed.
     */
};

struct DisplayPluginObject {
    Object obj;
    const char *args;
    QemuDisplay display_callbacks;
    Notifier mouse_mode_notifier;
    DisplayChangeListener change_listeners;
    DisplayPluginImplementation implementation;
    DisplayChangeListenerOps display_2d_graphic_ops;
};

struct DisplayPluginClass {
    ObjectClass parent;
    const char *(*get_args)(void *opaque);
    bool (*do_display_registration)(void *opaque);
};

// ******************************************************** //
// **********       Plugin Class Helpers         ********* //
// ****************************************************** //

DisplayPluginObject *get_display_plugin(const char *name, const char *args);
void qemu_display_plugin_register_type(void *opaque, TypeInfo *plugin_type);

#ifdef __cplusplus
}
#endif

#endif