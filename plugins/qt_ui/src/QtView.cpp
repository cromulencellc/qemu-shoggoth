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

#include "QtView.h"
#include "plugin/display_cb.h"


#include <iostream>


#define IGNORE_POINTER(x) ((void)((void *) x))
#define IGNORE_VALUE(x) ((void)(x))

#define HEX_PIPE(x) std::hex << x << std::dec

#define MESSAGE_BUFFER_LENGTH (500)

static DisplayChangeListenerOps qt_2d_ops;

static const guint16 *qt_get_keyboard_mapping(int *maplen)
{
    if (maplen)
    {
        *maplen = 0;

        switch (getOS())
        {
            case LINUX:
            {
                return display_get_xorg_input_map(maplen);
            }
            break;
            default:
            {
                char messageBuffer[MESSAGE_BUFFER_LENGTH];
                
                ::memset(messageBuffer, 0, MESSAGE_BUFFER_LENGTH);
                ::snprintf(messageBuffer, 
                           MESSAGE_BUFFER_LENGTH, 
                           "Unsupported operating system: %s\nQEMU will now exit",
                           getOSName());
                std::cout << messageBuffer << std::endl;
                showError(messageBuffer, true);
            }
        }
    }
    return NULL;
}

static void qt_dpy_post_init(void *plugin)
{
    int map_len = 0;
    QtView *qtv = QT_VIEW(plugin);
    const guint16 *map = qt_get_keyboard_mapping(&map_len);
    setKeyMapData(qtv->uiPtr, map, map_len);
}

static void qt_dpy_do_console_operations(void *plugin, QemuConsole *console)
{
    IGNORE_POINTER(plugin);
    IGNORE_POINTER(console);
}

static void qt_dpy_on_exit(void *plugin)
{
    IGNORE_POINTER(plugin);
}

static void qt_dpy_gfx_update(void *plugin, DisplayChangeListener *dcl, int x, int y, int w, int h)
{
    //IGNORE_POINTER(plugin);
    IGNORE_POINTER(dcl);
    IGNORE_VALUE(x);
    IGNORE_VALUE(y);
    IGNORE_VALUE(w);
    IGNORE_VALUE(h);

    QtView *qtv = QT_VIEW(plugin);
    updateView(qtv->uiPtr, x, y, w, h);
}

static void qt_dpy_gfx_switch(void *plugin, DisplayChangeListener *dcl, struct DisplaySurface *new_surface)
{    
    IGNORE_POINTER(dcl);
    QtView *qtv = QT_VIEW(plugin);

    qtv->ds = new_surface;
    void *pix = display_surface_get_image(qtv->ds);
    int width = display_surface_get_width(qtv->ds);
    int height = display_surface_get_height(qtv->ds);
    //PixelFormat pf = display_get_pixelformat(qtv->ds);
    pixman_format_code_t format = display_get_display_format(qtv->ds);

    if (format != PIXMAN_x8r8g8b8)
    {
        // This may not be the final placement for this code
        // We want to convert the data into 32 bit RGB format. 
        // Create a transform with the correct type: pixman_image_create_bits 
        // Composit with the data passed in: pixman_image_composite 
        // See qtk.c:gd_switch() for example
        std::cout << "Format update may be required" << std::endl;
    }

    setView(qtv->uiPtr, pix, height, width);
}

static bool qt_dpy_gfx_check_format(void *plugin, DisplayChangeListener *dcl, pixman_format_code_t format)
{
    IGNORE_POINTER(plugin);
    IGNORE_POINTER(dcl);
    return format == PIXMAN_x8r8g8b8;
}

static QemuConsole *qt_dpy_refresh(void *plugin, DisplayChangeListener *dcl)
{
    IGNORE_POINTER(plugin);
    IGNORE_POINTER(dcl);
    return NULL;
}

static void qt_dpy_mouse_set(void *plugin, DisplayChangeListener *dcl, int x, int y, int on)
{
    IGNORE_POINTER(plugin);
    IGNORE_POINTER(dcl);
    IGNORE_VALUE(x);
    IGNORE_VALUE(y);
    IGNORE_VALUE(on);
    // std::cout << "qt_dpy_mouse_set" << std::endl;
}

static void qt_dpy_cursor_define(void *plugin, DisplayChangeListener *dcl, QEMUCursor *cursor)
{
    IGNORE_POINTER(plugin);
    IGNORE_POINTER(dcl);
    IGNORE_POINTER(cursor);    
    // std::cout << "qt_dpy_cursor_define" << std::endl;
}

static void qt_mouse_mode_change(Notifier *notify, void *data)
{
    IGNORE_POINTER(notify);
    IGNORE_POINTER(data);  
    // std::cout << "qt_mouse_mode_change" << std::endl;
}

static void qt_view_initfn(Object *obj)
{
    QtView *qtv = QT_VIEW(obj);
    qtv->uiPtr = getUI();

    DisplayPluginObject *display = DISPLAY_PLUGIN_OBJECT(obj);
    display->mouse_mode_notifier.notify = qt_mouse_mode_change;
    display->implementation.do_console_operations = qt_dpy_do_console_operations;

    // Fill out the implementation
    display->implementation.post_init = qt_dpy_post_init;
    display->implementation.plugin_display_refresh = qt_dpy_refresh;
    display->implementation.plugin_display_mouse_set = qt_dpy_mouse_set;
    display->implementation.plugin_display_gfx_update = qt_dpy_gfx_update;
    display->implementation.plugin_display_gfx_switch = qt_dpy_gfx_switch;
    display->implementation.plugin_display_gfx_check_format = qt_dpy_gfx_check_format;
    display->implementation.plugin_display_cursor_define = qt_dpy_cursor_define;
    display->implementation.on_exit = qt_dpy_on_exit;
}

static void qt_view_finalize(Object *obj)
{
    QtView *qtv = QT_VIEW(obj);
    
    deleteUI();
    qtv->uiPtr = NULL;
}

static void qt_view_class_init(ObjectClass *klass,
                               void *class_data G_GNUC_UNUSED)
{
    (void)(klass);
}

bool plugin_setup(void *plugin, const char *path)
{
    (void)(path);
    (void)(plugin);

    qt_view_info.parent = TYPE_DISPLAY_PLUGIN_OBJECT;
    qt_view_info.name = TYPE_QT_VIEW;
    qt_view_info.instance_size = sizeof(QtView);
    qt_view_info.instance_init = qt_view_initfn;
    qt_view_info.instance_finalize = qt_view_finalize;
    qt_view_info.class_init = qt_view_class_init;
    qt_view_info.class_size = sizeof(QtViewClass);
    
    type_register_static(&qt_view_info);

    return true;
}
