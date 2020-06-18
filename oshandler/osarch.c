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
 *  Adam Critchley <shoggoth@cromulence.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 * 
 * The creation of this code was funded by the US Government.
 */

#include "oshandler/osarch.h"
#include "qom/cpu.h"


static void osarch_initfn(Object* obj)
{
	OSArch* osarch = OSARCH(obj);

	osarch->process_header = qstring_new();
}

static void osarch_finalize(Object* obj)
{
}

static void osarch_class_init(ObjectClass *klass, void* class_data)
{
	OSArchClass* osarch_class = OSARCH_CLASS(klass);

    osarch_class->detect = NULL;
    osarch_class->set_breakpoint = NULL;
    osarch_class->remove_breakpoint = NULL;
    osarch_class->remove_all_breakpoints = NULL;
    osarch_class->is_same_process = NULL;
    osarch_class->get_process_string = NULL;
    osarch_class->breakpoint_check = NULL;
    osarch_class->get_active_pagetable = NULL;
    osarch_class->process_enter = NULL;
    osarch_class->process_exit = NULL;
}

OSArch *osarch_init(CPUState *cpu)
{
    OSArch *arch = NULL;

    GSList *list = object_class_get_list(TYPE_OSARCH, false);
    while (!arch && list) {
        OSArchClass *ac = OBJECT_CLASS_CHECK(OSArchClass, list->data,
                                        TYPE_OSARCH);
        if(ac->detect){
            arch = ac->detect(cpu);
        }
        GSList *next = list->next;
        g_slist_free_1(list);
        list = next;
    }

    if(list) {
        g_slist_free(list);
    }

    if(arch){
        arch->cpu = cpu;
    }

	return arch;
}

static const TypeInfo osarch_info = {
	.parent = TYPE_OBJECT,
	.name = TYPE_OSARCH,
    .abstract = true,
	.instance_size = sizeof(OSArch),
	.instance_init = osarch_initfn,
	.instance_finalize = osarch_finalize,
	.class_size = sizeof(OSArchClass),
	.class_init = osarch_class_init
};

static void osarch_register_types(void)
{
	type_register_static(&osarch_info);
}

type_init(osarch_register_types);