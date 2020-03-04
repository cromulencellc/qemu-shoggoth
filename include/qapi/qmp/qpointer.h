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

#ifndef QPOINTER_H
#define QPOINTER_H

#include "qapi/qmp/qobject.h"

typedef void (*QPOINTER_FREE_FUNCTION)(void *);

struct QPointer {
    struct QObjectBase_ base;
    void *value;
    QPOINTER_FREE_FUNCTION free_ptr;
};

QPointer *qpointer_from_pointer(void *value, QPOINTER_FREE_FUNCTION free_function);
void* qpointer_get_pointer(const QPointer *qp);
bool qpointer_is_equal(const QObject *x, const QObject *y);
bool pointer_is_equal(const QObject *x, const void *y);
void qpointer_destroy_obj(QObject *obj);

#endif
