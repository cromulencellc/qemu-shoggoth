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

#include <stdlib.h>
#include <string.h>

#include "qemu/benchmark.h"

static void begin_benchmark(Benchmarker *this)
{
    gettimeofday(&this->start_time, NULL);
}

static double get_elapsed_millis(Benchmarker *this)
{
    struct timeval finish;
    double ret_val;

    gettimeofday(&finish, NULL);

    ret_val = (finish.tv_sec - this->start_time.tv_sec) * 1000;
    ret_val += (finish.tv_usec - this->start_time.tv_usec) / 1000;

    return ret_val;
}

static double get_elapsed_seconds(Benchmarker *this)
{
    struct timeval finish;
    double ret_val;

    gettimeofday(&finish, NULL);

    ret_val = (finish.tv_sec - this->start_time.tv_sec);
    ret_val += (finish.tv_usec - this->start_time.tv_usec) / 100000;

    return ret_val;
}

static void benchmarker_finalize(Object *obj)
{
    Benchmarker *bm = BENCHMARKER(obj);
    memset(&(bm->start_time), 0x00, sizeof(struct timeval));
}

static void benchmarker_class_init(ObjectClass *klass,
                                  void *class_data G_GNUC_UNUSED)
{
    BenchmarkerClass *bm_klass = BENCHMARKER_CLASS(klass);
    bm_klass->start_benchmark = begin_benchmark;
    bm_klass->get_millis_elapsed = get_elapsed_millis;
    bm_klass->get_seconds_elapsed = get_elapsed_seconds;
}

static const TypeInfo benchmarker_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_BENCHMARKER,
    .instance_size = sizeof(Benchmarker),
    .instance_finalize = benchmarker_finalize,
    .class_init = benchmarker_class_init,
    .class_size = sizeof(BenchmarkerClass),
};

static void benchmarker_register_types(void)
{
    type_register_static(&benchmarker_info);
}

type_init(benchmarker_register_types);

Benchmarker* new_benchmarker(void)
{
    Benchmarker *bm;

    bm = BENCHMARKER(object_new(TYPE_BENCHMARKER));
    return bm;
}

BenchmarkerClass* get_benchmarker_class(Benchmarker *bm)
{
    BenchmarkerClass *bm_class;

    bm_class = BENCHMARKER_GET_CLASS(bm);
    return bm_class;
}