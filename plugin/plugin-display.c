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

#include "plugin/plugin-display.h"
#include "qom/object_interfaces.h"
#include "plugin/display_cb.h"

#include <stdio.h>

/**
 * These are public helper functions
 */
DisplayPluginObject *get_display_plugin(const char *name, const char *args)
{
    DisplayPluginObject *ret_val = NULL;
    GSList *list = object_class_get_list(TYPE_DISPLAY_PLUGIN_OBJECT, false);
    while (list && !ret_val) 
    { 
        DisplayPluginClass *dpc = OBJECT_CLASS_CHECK(DisplayPluginClass, list->data, TYPE_DISPLAY_PLUGIN_OBJECT);
        if (strcmp(name, object_class_get_name(OBJECT_CLASS(dpc))) == 0)
        {
            ret_val = DISPLAY_PLUGIN_OBJECT(object_new(name));
        }

        GSList *next = list->next;
        g_slist_free_1(list);
        list = next;
    }
    return ret_val;
}

/**
 * These are private helper functions
 */
static void *get_display_manager(void)
{
    return display_get_display_plugin(); 
}

/**
 * These are callback functions
 */

static void display_plugin_init(DisplayState *ds, DisplayOptions *opts)
{
    void *manager = get_display_manager();
    if (manager)
    {
        DisplayPluginObject *dpo = DISPLAY_PLUGIN_OBJECT(manager);

        if (dpo->implementation.pre_init)
        {
            dpo->implementation.pre_init(dpo);
        }

        if (dpo->change_listeners.ops)
        {
            if (dpo->implementation.pre_display_change_listener_register)
            {
                dpo->implementation.pre_display_change_listener_register(dpo);
            }

            display_register_DisplayChangeListener(&dpo->change_listeners);

            if (dpo->implementation.pre_display_change_listener_register)
            {
                dpo->implementation.pre_display_change_listener_register(dpo);
            }
        }

        if (dpo->implementation.do_console_operations)
        {
            for (int i = 0; ; ++i)
            {
                QemuConsole *console = display_console_lookup_by_index(i);
                if (console)
                {
                    dpo->implementation.do_console_operations(dpo, console);
                }
                else
                {
                    break;
                }             
            }
        }

        if (dpo->implementation.post_init)
        {
            dpo->implementation.post_init(dpo);
        }
    }
}

static void display_on_exit(void)
{
    void *manager = get_display_manager();
    if (manager)
    { 
        DisplayPluginObject *dpy = DISPLAY_PLUGIN_OBJECT(manager); 
        if (dpy->implementation.on_exit)
        {
            dpy->implementation.on_exit(dpy);
        }     
    }    
}

static void plugin_display_gfx_update(DisplayChangeListener *dcl, int x, int y, int w, int h)
{
    void *manager = get_display_manager();
    if (manager)
    { 
        DisplayPluginObject *dpy = DISPLAY_PLUGIN_OBJECT(manager); 
        if (dpy->implementation.plugin_display_gfx_update)
        {
            dpy->implementation.plugin_display_gfx_update(dpy, dcl, x, y, w, h);
        }
    }
}

static void plugin_display_gfx_switch(DisplayChangeListener *dcl, struct DisplaySurface *new_surface)
{
    void *manager = get_display_manager();
    if (manager)
    { 
        DisplayPluginObject *dpy = DISPLAY_PLUGIN_OBJECT(manager); 
        if (dpy->implementation.plugin_display_gfx_switch)
        {
            dpy->implementation.plugin_display_gfx_switch(dpy, dcl, new_surface);
        }
    }    
}

static bool plugin_display_gfx_check_format(DisplayChangeListener *dcl, pixman_format_code_t format)
{
    bool ret_val = false;
    void *manager = get_display_manager();
    if (manager)
    { 
        DisplayPluginObject *dpy = DISPLAY_PLUGIN_OBJECT(manager);
        if (dpy->implementation.plugin_display_gfx_check_format)
        {
            ret_val = dpy->implementation.plugin_display_gfx_check_format(dpy, dcl, format);
        } 
    }
    return ret_val;
}

static void plugin_display_refresh(DisplayChangeListener *dcl)
{
    QemuConsole *con = NULL;
    void *manager = get_display_manager();
    if (manager)
    { 
        DisplayPluginObject *dpy = DISPLAY_PLUGIN_OBJECT(manager); 
        if (dpy->implementation.plugin_display_refresh)
        {
            con = dpy->implementation.plugin_display_refresh(dpy, dcl);
        }
    }

    // NULL is ok here
    display_graphic_hw_update(con);
}

static void plugin_display_mouse_set(DisplayChangeListener *dcl, int x, int y, int on)
{
    void *manager = get_display_manager();
    if (manager)
    { 
        DisplayPluginObject *dpy = DISPLAY_PLUGIN_OBJECT(manager); 
        if (dpy->implementation.plugin_display_mouse_set)
        {
            dpy->implementation.plugin_display_mouse_set(dpy, dcl, x, y, on);
        }
    }
}

static void plugin_display_cursor_define(DisplayChangeListener *dcl, QEMUCursor *cursor)
{
    void *manager = get_display_manager();
    if (manager)
    { 
        DisplayPluginObject *dpy = DISPLAY_PLUGIN_OBJECT(manager); 
        if (dpy->implementation.plugin_display_cursor_define)
        {
            dpy->implementation.plugin_display_cursor_define(dpy, dcl, cursor);
        }
    }
}

static void display_plugin_early_init(DisplayOptions *opts)
{
    void *manager = get_display_manager();
    if (manager)
    {
        DisplayPluginObject *dpo = DISPLAY_PLUGIN_OBJECT(manager);

        if (dpo->implementation.pre_early_init)
        {
            dpo->implementation.pre_early_init(dpo);
        }

        // For now, I'm leaving this on. We may want to set different 
        // callbacks based on which features are set in the implementation
        // this is the set for a 2D graphical console.
        dpo->display_2d_graphic_ops.dpy_gfx_update = plugin_display_gfx_update;
        dpo->display_2d_graphic_ops.dpy_gfx_switch = plugin_display_gfx_switch;
        dpo->display_2d_graphic_ops.dpy_gfx_check_format = plugin_display_gfx_check_format;
        dpo->display_2d_graphic_ops.dpy_refresh = plugin_display_refresh;
        dpo->display_2d_graphic_ops.dpy_mouse_set = plugin_display_mouse_set;
        dpo->display_2d_graphic_ops.dpy_cursor_define = plugin_display_cursor_define;
        dpo->change_listeners.ops = &dpo->display_2d_graphic_ops;

        if (dpo->mouse_mode_notifier.notify)
        {
            if (dpo->implementation.pre_mouse_change_notifier_register)
            {
                dpo->implementation.pre_mouse_change_notifier_register(dpo);
            }

            display_add_mouse_mode_change_notifier(&dpo->mouse_mode_notifier);
            
            if (dpo->implementation.post_mouse_change_notifier_register)
            {
                dpo->implementation.post_mouse_change_notifier_register(dpo);
            }
        } 

        atexit(display_on_exit);

        if (dpo->implementation.post_early_init)
        {
            dpo->implementation.post_early_init(dpo);
        }
    }   
}

/**
 * These are the member functions of the plugin-display
 * class.
 */
static const char *display_plugin_object_get_args(void *opaque)
{
    DisplayPluginObject *display = DISPLAY_PLUGIN_OBJECT(opaque);
    return display->args;
}

static bool display_do_display_registration(void *opaque)
{
    bool ret_val = false;
    DisplayPluginObject *dpo = DISPLAY_PLUGIN_OBJECT(opaque);

    if (dpo->display_callbacks.early_init || dpo->display_callbacks.init)
    {
        if (dpo->implementation.pre_display_callback_register)
        {
            dpo->implementation.pre_display_callback_register(dpo);
        }
        
        display_register(&dpo->display_callbacks);

        if (dpo->implementation.post_display_callback_register)
        {
            dpo->implementation.post_display_callback_register(dpo);
        }

        ret_val = true;

    }
    return ret_val;  
}

/**
 * This is QEMU class management code
 */

static void display_plugin_object_initfn(Object *obj)
{
    DisplayPluginObject *display = DISPLAY_PLUGIN_OBJECT(obj);
    display->args = NULL;
    display->display_callbacks.type = DISPLAY_TYPE_PLUGIN;
    display->display_callbacks.early_init = display_plugin_early_init; 
    display->display_callbacks.init = display_plugin_init; 
}

static void display_plugin_object_finalize(Object *obj)
{

}

static void display_plugin_object_class_init(ObjectClass *klass,
                                             void *class_data G_GNUC_UNUSED)
{
    DisplayPluginClass *dpc = DISPLAY_PLUGIN_OBJECT_CLASS(klass);
    dpc->get_args = display_plugin_object_get_args;
    dpc->do_display_registration = display_do_display_registration;
}

static const TypeInfo display_plugin_object_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_DISPLAY_PLUGIN_OBJECT,
    .abstract = true,
    .instance_size = sizeof(DisplayPluginObject),
    .instance_init = display_plugin_object_initfn,
    .instance_finalize = display_plugin_object_finalize,
    .class_init = display_plugin_object_class_init,
    .class_size = sizeof(DisplayPluginClass),
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void display_plugin_object_register_types(void)
{
    type_register_static(&display_plugin_object_info);
}

type_init(display_plugin_object_register_types);