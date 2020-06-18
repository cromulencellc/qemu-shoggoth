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

#ifndef UI_TYPES_H
#define UI_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ui/qemu-pixman.h"
#include "qemu/typedefs.h"
#include "qapi/qapi-types-ui.h"
#include "qemu/notify.h"

typedef struct QemuDisplay QemuDisplay;

struct QemuDisplay {
    DisplayType type;
    void (*early_init)(DisplayOptions *opts);
    void (*init)(DisplayState *ds, DisplayOptions *opts);
};

typedef struct DisplaySurface {
    pixman_format_code_t format;
    pixman_image_t *image;
    uint8_t flags;
#ifdef CONFIG_OPENGL
    GLenum glformat;
    GLenum gltype;
    GLuint texture;
#endif
} DisplaySurface;

/* cursor data format is 32bit RGBA */
typedef struct QEMUCursor {
    int                 width, height;
    int                 hot_x, hot_y;
    int                 refcount;
    uint32_t            data[];
} QEMUCursor;

typedef void *QEMUGLContext;
typedef struct QEMUGLParams QEMUGLParams;

struct QEMUGLParams {
    int major_ver;
    int minor_ver;
};

typedef struct QemuDmaBuf {
    int       fd;
    uint32_t  width;
    uint32_t  height;
    uint32_t  stride;
    uint32_t  fourcc;
    uint32_t  texture;
    bool      y0_top;
} QemuDmaBuf;

typedef struct DisplayChangeListenerOps {
    const char *dpy_name;

    void (*dpy_refresh)(DisplayChangeListener *dcl);

    void (*dpy_gfx_update)(DisplayChangeListener *dcl,
                           int x, int y, int w, int h);
    void (*dpy_gfx_switch)(DisplayChangeListener *dcl,
                           struct DisplaySurface *new_surface);
    bool (*dpy_gfx_check_format)(DisplayChangeListener *dcl,
                                 pixman_format_code_t format);

    void (*dpy_text_cursor)(DisplayChangeListener *dcl,
                            int x, int y);
    void (*dpy_text_resize)(DisplayChangeListener *dcl,
                            int w, int h);
    void (*dpy_text_update)(DisplayChangeListener *dcl,
                            int x, int y, int w, int h);

    void (*dpy_mouse_set)(DisplayChangeListener *dcl,
                          int x, int y, int on);
    void (*dpy_cursor_define)(DisplayChangeListener *dcl,
                              QEMUCursor *cursor);

    QEMUGLContext (*dpy_gl_ctx_create)(DisplayChangeListener *dcl,
                                       QEMUGLParams *params);
    void (*dpy_gl_ctx_destroy)(DisplayChangeListener *dcl,
                               QEMUGLContext ctx);
    int (*dpy_gl_ctx_make_current)(DisplayChangeListener *dcl,
                                   QEMUGLContext ctx);
    QEMUGLContext (*dpy_gl_ctx_get_current)(DisplayChangeListener *dcl);

    void (*dpy_gl_scanout_disable)(DisplayChangeListener *dcl);
    void (*dpy_gl_scanout_texture)(DisplayChangeListener *dcl,
                                   uint32_t backing_id,
                                   bool backing_y_0_top,
                                   uint32_t backing_width,
                                   uint32_t backing_height,
                                   uint32_t x, uint32_t y,
                                   uint32_t w, uint32_t h);
    void (*dpy_gl_scanout_dmabuf)(DisplayChangeListener *dcl,
                                  QemuDmaBuf *dmabuf);
    void (*dpy_gl_cursor_dmabuf)(DisplayChangeListener *dcl,
                                 QemuDmaBuf *dmabuf, bool have_hot,
                                 uint32_t hot_x, uint32_t hot_y);
    void (*dpy_gl_cursor_position)(DisplayChangeListener *dcl,
                                   uint32_t pos_x, uint32_t pos_y);
    void (*dpy_gl_release_dmabuf)(DisplayChangeListener *dcl,
                                  QemuDmaBuf *dmabuf);
    void (*dpy_gl_update)(DisplayChangeListener *dcl,
                          uint32_t x, uint32_t y, uint32_t w, uint32_t h);

} DisplayChangeListenerOps;

struct DisplayChangeListener {
    uint64_t update_interval;
    const DisplayChangeListenerOps *ops;
    DisplayState *ds;
    QemuConsole *con;

    QLIST_ENTRY(DisplayChangeListener) next;
};

#ifdef __cplusplus
}
#endif

#endif
