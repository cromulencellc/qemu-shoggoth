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

#include "qemu/osdep.h"
#include "qapi/qmp/qpointer.h"


/**
 * qpointer_from_pointer(): Create a new QPointer from a pointer
 *
 * Return strong reference.
 */
QPointer *qpointer_from_pointer(void *value, QPOINTER_FREE_FUNCTION free_function)
{
    QPointer *qp;

    qp = g_malloc(sizeof(*qp));
    qobject_init(QOBJECT(qp), QTYPE_QPOINTER);
    qp->value = value;
    qp->free_ptr = free_function;

    return qp;
}

/**
 * qpointer_get_pointer(): Get the stored bool
 */
void* qpointer_get_pointer(const QPointer *qp)
{
    return qp->value;
}

/**
 * qpointer_is_equal(): Test whether the two QBools are equal
 */
bool qpointer_is_equal(const QObject *x, const QObject *y)
{
    return qobject_to(QPointer, x)->value == qobject_to(QPointer, y)->value;
}

/**
 * pointer_is_equal(): Tests if the provided pointer is
 * equal to a given QPointer
 */
bool pointer_is_equal(const QObject *x, const void *y)
{
    void *x_rawPtr = qpointer_get_pointer(qobject_to(QPointer, x));
    return x_rawPtr == y;
}

/**
 * qpointer_destroy_obj(): Free all memory allocated by a
 * QPointer object
 */
void qpointer_destroy_obj(QObject *obj)
{
    assert(obj != NULL);
    QPointer *qp = qobject_to(QPointer, obj); 

    // Use the supplied free function to free it.
    if (qp->free_ptr)
    {
        qp->free_ptr(qp->value);
    }

    qp->value = NULL;
    g_free(qp);
}
