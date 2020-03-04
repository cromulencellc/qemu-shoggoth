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

#ifndef QEMU_BENCHMARK_H
#define QEMU_BENCHMARK_H

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "qom/object.h"
#include <sys/time.h>

#define TYPE_BENCHMARKER "benchmarker"
#define BENCHMARKER(obj)                                    \
    OBJECT_CHECK(Benchmarker, (obj), TYPE_BENCHMARKER)
#define BENCHMARKER_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(BenchmarkerClass, klass, TYPE_BENCHMARKER)
#define BENCHMARKER_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(BenchmarkerClass, obj, TYPE_BENCHMARKER)

typedef struct Benchmarker Benchmarker;
typedef struct BenchmarkerClass BenchmarkerClass;

struct Benchmarker {
    Object obj;
    struct timeval start_time;
};

struct BenchmarkerClass {
    ObjectClass parent;
    void (*start_benchmark)(Benchmarker *);
    double (*get_millis_elapsed)(Benchmarker *);
    double (*get_seconds_elapsed)(Benchmarker *);    
};

/**
 * Creates a new benchmarker
 */
Benchmarker* new_benchmarker(void);

/**
 * Get the class portion of the benchmarker
 */
BenchmarkerClass* get_benchmarker_class(Benchmarker*);

#endif