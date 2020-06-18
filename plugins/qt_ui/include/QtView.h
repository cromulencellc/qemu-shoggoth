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

#ifndef QTVIEW_H
#define QTVIEW_H

#include "qemu/qemu-plugin.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include "plugin/plugin-display.h"

#ifdef __cplusplus
}
#endif

#include "QtWrapper.h"

/**
 * Define macros for casting and object management.
 */
#define TYPE_QT_VIEW "qtview"
#define QT_VIEW(obj)                                    \
    OBJECT_CHECK(QtView, (obj), TYPE_QT_VIEW)
#define QT_VIEW_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(QtViewClass, klass, TYPE_QT_VIEW)
#define QT_VIEW_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(QtViewClass, obj, TYPE_QT_VIEW)

/**
 * Define macro for opts.
 */
#define QT_VIEW_OPTS  ("qt-view")

/**
 * Object type structs.
 */
typedef struct QtView QtView;
typedef struct QtViewClass QtViewClass;

/**
 * @param obj The parent object
 */
struct QtView 
{
    DisplayPluginObject obj;
    UIStruct  *uiPtr;
    DisplaySurface *ds;
    pixman_image_t *transform;
};

/**
 * @param parent The parent class
 */
struct QtViewClass
{
    DisplayPluginClass parent;
};

/**
 * Type information.
 */
static TypeInfo qt_view_info;

#endif