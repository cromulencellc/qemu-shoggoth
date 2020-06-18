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

#ifndef DISPLAY_CB_H
#define DISPLAY_CB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ui/types.h"
#include "qemu/notify.h"

/**
 * 
 * @param ui
 */
void display_register(QemuDisplay *ui);

/**
 * 
 * @param dcl
 */
void display_register_DisplayChangeListener(DisplayChangeListener *dcl);

/**
 * 
 * @param notify
 */
void display_add_mouse_mode_change_notifier(Notifier *notify);


/**
 * 
 * @param s
 * @return
 */
void *display_surface_get_image(DisplaySurface *s);

/**
 * 
 * @param s
 * @return
 */
int display_surface_get_width(DisplaySurface *s);

/**
 * 
 * @param s
 * @return
 */
int display_surface_get_height(DisplaySurface *s);

/**
 * 
 * @param s
 * @return 
 */
PixelFormat display_get_pixelformat(DisplaySurface *s);

/**
 * 
 * @param s
 * @return
 */
pixman_format_code_t display_get_display_format(DisplaySurface *s);

/**
 * 
 * @param index
 * @return 
 */
QemuConsole *display_console_lookup_by_index(unsigned int index);

/**
 * 
 * @param con
 * @return
 */
void *display_get_display_plugin(void);

/**
 * 
 * @param con
 */
void display_graphic_hw_update(QemuConsole *con);

/**
 * 
 * 
 * @param con
 * @param id
 */
void display_console_set_window_id(QemuConsole *con, int window_id);

/**
 * 
 */
void display_request_shutdown(void);

/**
 * 
 * @param con
 * @return
 */
bool display_console_is_graphic(QemuConsole *con);

/**
 * 
 * 
 * @param con
 * @param keycode
 * @param key_down
 */
void display_process_graphic_key_event(QemuConsole *con, int keycode, bool key_down);

/**
 * 
 * 
 * @param maplen
 * @return
 */
const guint16 *display_get_xorg_input_map(int *maplen);


#ifdef __cplusplus
}
#endif

#endif