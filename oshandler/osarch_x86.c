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
 *  Matt Heine
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 * 
 * The creation of this code was funded by the US Government.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/cpu.h"
#include "qom/object_interfaces.h"
#include "sysemu/sysemu.h"
#include "sysemu/hw_accel.h"
#include "exec/cpu-common.h"
#include "exec/memory.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qpointer.h"
#include "qapi/qapi-types-oshandler.h"
#include "exec/gdbstub.h"
#include "oshandler/osarch_x86.h"
#include <capstone.h>

struct idt_entry
{
    unsigned short base_lo;
    unsigned short sel;        /* Our kernel segment goes here! */
    unsigned char always0;     /* This will ALWAYS be set to 0! */
    unsigned char flags;       /* Set using the above table! */
    unsigned short base_hi;
} __attribute__((packed));

struct idt64_entry {
   uint16_t offset_1; // offset bits 0..15
   uint16_t selector; // a code segment selector in GDT or LDT
   uint8_t ist;       // bits 0..2 holds Interrupt Stack Table offset, rest of bits zero.
   uint8_t type_attr; // type and attributes
   uint16_t offset_2; // offset bits 16..31
   uint32_t offset_3; // offset bits 32..63
   uint32_t zero;     // reserved
} __attribute__((packed));

typedef struct OSArchX86ProcessState{
   uint64_t cr3;
} OSArchX86ProcessState;

#define INVALID_CR3      ((uint64_t)-1)
#define TARGET_PAGE_BITS 12

#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_BITS)
#define TARGET_PAGE_MASK ~(TARGET_PAGE_SIZE - 1)

static bool in_64bit(CPUState* cpu)
{
    X86CPU* arch = X86_CPU(cpu);
    if(arch->env.efer & (1 << 8))
    {
        return true;
    }
    return false;
}

uint64_t parse_idt_entry_base(CPUState* cpu, uint64_t idt_addr, uint16_t entry)
{
    uint8_t idt_dat[16] = {0};

    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->memory_rw_debug) {
        cc->memory_rw_debug(cpu, idt_addr + (entry * sizeof(idt_dat)), idt_dat, sizeof(idt_dat), 0);
    }else{
        cpu_memory_rw_debug(cpu, idt_addr + (entry * sizeof(idt_dat)), idt_dat, sizeof(idt_dat), 0);
    }

    if(in_64bit(cpu))
    {
        uint64_t upper = 0;
        uint32_t lower = 0;

        upper = ((struct idt64_entry*)idt_dat)->offset_3;
        upper <<= 32;
        lower = ((struct idt64_entry*)idt_dat)->offset_2 << 16 | 
                ((struct idt64_entry*)idt_dat)->offset_1;

        *(((uint8_t*)(&upper))) = (uint32_t)lower;

        return upper | lower;
    }
    else
        return ((struct idt_entry*)idt_dat)->base_hi << 16 | ((struct idt_entry*)idt_dat)->base_lo;
}

static target_ulong os_switch_cr3(OSArchX86* arch_x86, CPUState* cpu, target_ulong new_cr3)
{
    X86CPU* x86cpu = X86_CPU(cpu);
    target_ulong orig_cr3 = x86cpu->env.cr[3];
    cpu_x86_update_cr3(&x86cpu->env, new_cr3);
    return orig_cr3;
}

static int osarch_x86_set_breakpoint(OSArch* arch, uint64_t addr, uint64_t length, int flags, ProcessInfo *pi)
{
	cpu_synchronize_state(arch->cpu);

    OSArchX86* arch_x86 = OSARCHX86(arch);
    target_ulong old_cr3 = INVALID_CR3;
    int err = 0;

    if( pi ) {
        old_cr3 = os_switch_cr3(arch_x86, arch->cpu, pi->cr3);
    }

    if (kvm_enabled()) {
        err = kvm_insert_breakpoint(arch->cpu, addr, length, flags);
    }else{
        switch (flags) {
            case GDB_BREAKPOINT_SW:
            case GDB_BREAKPOINT_HW:
                err = cpu_breakpoint_insert(arch->cpu, addr, BP_GDB, NULL);
                break;
            default:
                err = -ENOSYS;
        }
    }

    if( pi ) {
        os_switch_cr3(arch_x86, arch->cpu, old_cr3);
    }

    return err;
}

static int osarch_x86_remove_breakpoint(OSArch* arch, uint64_t addr, uint64_t length, int flags, ProcessInfo *pi)
{
	cpu_synchronize_state(arch->cpu);

    OSArchX86* arch_x86 = OSARCHX86(arch);
    target_ulong old_cr3 = INVALID_CR3;
    int err = 0;

    if( pi ) {
        old_cr3 = os_switch_cr3(arch_x86, arch->cpu, pi->cr3);
    }

    if (kvm_enabled()) {
        err = kvm_remove_breakpoint(arch->cpu, addr, length, flags);
    }else{
        switch (flags) {
            case GDB_BREAKPOINT_SW:
            case GDB_BREAKPOINT_HW:
                err = cpu_breakpoint_remove(arch->cpu, addr, BP_GDB);
                break;
            default:
                err = -ENOSYS;
        }
    }

    if( pi ) {
        os_switch_cr3(arch_x86, arch->cpu, old_cr3);
    }
    if (err) {
        fprintf(stderr, "Error removing breakpoint %d, %lx %d \n", err, addr, flags);
    }
    return err;
}

static void osarch_x86_remove_all_breakpoints(OSArch* arch)
{
    if (kvm_enabled()) {
        kvm_remove_all_breakpoints(arch->cpu);
        return;
    }

    cpu_breakpoint_remove_all(arch->cpu, BP_GDB);
#ifndef CONFIG_USER_ONLY
    cpu_watchpoint_remove_all(arch->cpu, BP_GDB);
#endif
}

static void osarch_x86_get_process_string(OSArch* arch, ProcessInfo *pi, QString **pqstr)
{
    char cr3num[32];
	QString *qstr = *pqstr;
	qstring_append_int(qstr, pi->pid);
    snprintf(cr3num, sizeof(cr3num), "%" PRIx64, pi->cr3);
    qstring_append(qstr, "\t");
    qstring_append(qstr, cr3num);
}

static uint64_t osarch_x86_get_active_pagetable(OSArch* arch, CPUState* cpu)
{
    // This will return the base page directory after masking off
    // flags and other miscellaneous bits from the CR3.
	cpu_synchronize_state(cpu);

    CPUX86State *env = &X86_CPU(cpu)->env;
    uint64_t pagedir = env->cr[3];

    if (cpu_paging_enabled(cpu)) {
        if (env->cr[4] & CR4_PAE_MASK) {
            if (env->hflags & HF_LMA_MASK) {
                pagedir = (env->cr[3] & ~0xfffULL);
            } else
            {
                pagedir = (env->cr[3] & ~0x1f);
            }
        } else {
            pagedir = (env->cr[3] & ~0xfff);
        }
    }

    return pagedir;
}

static bool osarch_x86_is_same_process(OSArch* arch, ProcessInfo *lhs, ProcessInfo *rhs)
{
    // Check that the current cr3 is the cr3 of the process.
    // For linux, swapper will have the same cr3 so we'll get some instruction
    // state for that as well as our activated process.
    if( lhs->cr3 == rhs->cr3 ){
        return true;
    }

    return false;
}

static bool osarch_x86_breakpoint_check(OSArch *arch, CPUState* cpu, OSBreakpoint *bp)
{
    (void) arch;
    cpu_synchronize_state(cpu);
    return (bp->addr == X86_CPU(cpu)->env.eip);
}

static OSArch *osarch_x86_detect(CPUState *cpu)
{
    if(object_dynamic_cast(OBJECT(cpu), TYPE_X86_CPU)) {
        OSArchX86 *arch = OSARCHX86(object_new(TYPE_OSARCHX86));
        arch->x86cpu = X86_CPU(cpu);
        return OSARCH(arch);
    }

    return NULL;
}

static void* osarch_x86_process_enter(OSArch* arch, ProcessInfo *pi)
{
	cpu_synchronize_state(arch->cpu);
    OSArchX86* arch_x86 = OSARCHX86(arch);
    OSArchX86ProcessState *ps = g_new0(OSArchX86ProcessState, 1);
    target_ulong old_cr3 = INVALID_CR3;

    if( !ps ) {
        return NULL;
    }

    if( pi ) {
        old_cr3 = os_switch_cr3(arch_x86, arch->cpu, pi->cr3);
    }

    ps->cr3 = old_cr3;

    return ps;
}

static void osarch_x86_process_exit(OSArch* arch, void *state)
{
	cpu_synchronize_state(arch->cpu);
    OSArchX86* arch_x86 = OSARCHX86(arch);
    OSArchX86ProcessState *ps = (OSArchX86ProcessState *)state;

    if( ps ) {
        os_switch_cr3(arch_x86, arch->cpu, ps->cr3);
    }

    g_free(ps);
}

static void osarch_x86_initfn(Object* obj)
{
	OSArch* arch = OSARCH(obj);
    OSArchX86* arch_x86 = OSARCHX86(arch);

    arch_x86->x86cpu = NULL;
    qstring_append(arch->process_header, "PID\tCR3");
}

static void osarch_x86_finalize(Object* obj)
{
}

static void osarch_x86_class_init(ObjectClass *klass, void* class_data)
{
    OSArchClass* arch_cc = OSARCH_CLASS(klass);

    arch_cc->detect                  = osarch_x86_detect;
    arch_cc->set_breakpoint          = osarch_x86_set_breakpoint;
    arch_cc->remove_breakpoint       = osarch_x86_remove_breakpoint;
    arch_cc->remove_all_breakpoints  = osarch_x86_remove_all_breakpoints;
    arch_cc->is_same_process         = osarch_x86_is_same_process;
    arch_cc->get_process_string      = osarch_x86_get_process_string;
    arch_cc->breakpoint_check        = osarch_x86_breakpoint_check;
    arch_cc->get_active_pagetable    = osarch_x86_get_active_pagetable;
    arch_cc->process_enter           = osarch_x86_process_enter;
    arch_cc->process_exit            = osarch_x86_process_exit;
}

static const TypeInfo osarch_x86_info = {
    .parent = TYPE_OSARCH,
    .name = TYPE_OSARCHX86,
    .instance_size = sizeof(OSArchX86),
    .instance_init = osarch_x86_initfn,
    .instance_finalize = osarch_x86_finalize,
    .class_size = sizeof(OSArchX86Class),
    .class_init = osarch_x86_class_init,
};

static void osarch_x86_register_types(void)
{
    type_register_static(&osarch_x86_info);
}

type_init(osarch_x86_register_types);
