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

#include <triton/api.hpp>
#include <triton/bitsVector.hpp>
#include <triton/exceptions.hpp>
#include <triton/immediate.hpp>
#include <triton/instruction.hpp>
#include <triton/memoryAccess.hpp>
#include <triton/operandWrapper.hpp>
#include <triton/register.hpp>
#include <triton/x8664Cpu.hpp>
#include <triton/x86Cpu.hpp>
#include <triton/x86Specifications.hpp>

#include <capstone.h>

#include "qemu/qemu-plugin.hpp"
#include "plugin/qemu-registers.h"
#include "target/i386/register-types.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "plugin/plugin-object.h"

#ifdef __cplusplus
}
#endif

// These macros define object operations
#define TYPE_TRITONTEST_CPP "triton-test"
#define TRITONTEST(obj)                                    \
    OBJECT_CHECK(TritonTest, (obj), TYPE_TRITONTEST_CPP)
#define TRITONTEST_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(TritonTestClass, klass, TYPE_TRITONTEST_CPP)
#define TRITONTEST_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(TritonTestClass, obj, TYPE_TRITONTEST_CPP)

// Object type data
typedef struct TritonTest TritonTest;
typedef struct TritonTestClass TritonTestClass;

struct TritonTest
{
    PluginObject obj;
};

struct TritonTestClass
{
    PluginObjectClass parent;
};

// Object setup: constructor
static void triton_test_initfn(Object *obj)
{
    printf("triton_test_initfn\n");
    TritonTest *tt = TRITONTEST(obj);
    (void)tt;
}

// Object setup: destructor
static void triton_test_finalize(Object *obj)
{
    printf("triton_test_finalize\n");
    TritonTest *tt = TRITONTEST(obj);
    (void)tt;
}

// Object setup: class constructor 
static void triton_test_class_init(ObjectClass *klass,
                                 void *class_data G_GNUC_UNUSED)
{
    printf("triton_test_class_init\n");
    TritonTestClass *tt_klass = TRITONTEST_CLASS(klass);
    (void)tt_klass;
}

static triton::API ctx;

// Object setup: Object info
static TypeInfo triton_test_info;

static void triton_test_set_register(int creg, triton::arch::Register &tr)
{
    RegisterDescriptor *reg = NULL;
    qemu_get_cpu_register_descriptor(0, creg, &reg);
    if( reg )
    {
        switch(reg->reg_size)
        {
        case 8:
            ctx.setConcreteRegisterValue(tr, *((uint64_t*)reg->reg_value));
            break;
        case 4:
            ctx.setConcreteRegisterValue(tr, *((uint32_t*)reg->reg_value));
            break;
        case 2:
            ctx.setConcreteRegisterValue(tr, *((uint16_t*)reg->reg_value));
            break;
        case 1:
            ctx.setConcreteRegisterValue(tr, reg->reg_value[0]);
            break;
        default:
            std::cout << "Unsupported register size!\n" << std::endl;
            break;
        }
    }
}

/**
 * These are the call back functions that QEMU will use to 
 * talk to the plugins. It is not required to implement all
 * of them; QEMU should be smart in calling only the set 
 * callbacks. For more information on these functions and
 * how the behave, see qemu/qemu-plugin.h. There is 
 * documentation on each function that is currently implemented.
 */
static void triton_test_on_ra_start(void *opaque, CommsWorkItem* work) 
{
    printf("triton_test_on_ra_start\n");
    TritonTest *tt = TRITONTEST(opaque);
    TritonTestClass *tt_klass = TRITONTEST_GET_CLASS(tt);
    (void)tt;
    (void)tt_klass;

    triton_test_set_register(REG_I386_RAX, ctx.registers.x86_rax);
	//ctx.setConcreteRegisterValue(ctx.registers.x86_rax, 0x7ffff7fdd000);
    triton_test_set_register(REG_I386_RCX, ctx.registers.x86_rcx);
	//ctx.setConcreteRegisterValue(ctx.registers.x86_rcx, 0x7ffff7b156d0);
    triton_test_set_register(REG_I386_RDX, ctx.registers.x86_rdx);
	//ctx.setConcreteRegisterValue(ctx.registers.x86_rdx, 0x7ffff7dd5770);
    triton_test_set_register(REG_I386_RBX, ctx.registers.x86_rbx);
	//ctx.setConcreteRegisterValue(ctx.registers.x86_rbx, 0);
    triton_test_set_register(REG_I386_RSP, ctx.registers.x86_rsp);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_rsp, 0x7fffffffe680);
    triton_test_set_register(REG_I386_RBP, ctx.registers.x86_rbp);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_rbp, 0x7fffffffe6a0);
    triton_test_set_register(REG_I386_RSI, ctx.registers.x86_rsi);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_rsi, 0xA);
    triton_test_set_register(REG_I386_RDI, ctx.registers.x86_rdi);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_rdi, 0);
    triton_test_set_register(REG_I386_R8, ctx.registers.x86_r8);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_r8, 0x7ffff7dd5760);
    triton_test_set_register(REG_I386_R9, ctx.registers.x86_r9);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_r9, 0x7ffff7fed700);
    triton_test_set_register(REG_I386_R10, ctx.registers.x86_r10);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_r10, 0x35c);
    triton_test_set_register(REG_I386_R11, ctx.registers.x86_r11);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_r11, 0x246);
    triton_test_set_register(REG_I386_R12, ctx.registers.x86_r12);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_r12, 0x555555554650);
    triton_test_set_register(REG_I386_R13, ctx.registers.x86_r13);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_r13, 0x7fffffffe780);
    triton_test_set_register(REG_I386_R14, ctx.registers.x86_r14);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_r14, 0);
    triton_test_set_register(REG_I386_R15, ctx.registers.x86_r15);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_r15, 0);
    triton_test_set_register(REG_I386_CR0, ctx.registers.x86_cr0);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_cr0, 0x80050033);
    triton_test_set_register(REG_I386_CR1, ctx.registers.x86_cr1);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_cr1, 0);
    triton_test_set_register(REG_I386_CR2, ctx.registers.x86_cr2);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_cr2, 0x7ffff7fdd000);
    triton_test_set_register(REG_I386_CR3, ctx.registers.x86_cr3);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_cr3, 0xd20c000);
    triton_test_set_register(REG_I386_CR4, ctx.registers.x86_cr4);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_cr4, 0x6f0);
    triton_test_set_register(REG_I386_FPREG0, ctx.registers.x86_xmm0);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_xmm0, 0x10);
    triton_test_set_register(REG_I386_FPREG1, ctx.registers.x86_xmm1);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_xmm1, 0x10);
    triton_test_set_register(REG_I386_FPREG2, ctx.registers.x86_xmm2);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_xmm2, 0x10);
    triton_test_set_register(REG_I386_FPREG3, ctx.registers.x86_xmm3);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_xmm3, 0x10);
    triton_test_set_register(REG_I386_FPREG4, ctx.registers.x86_xmm4);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_xmm4, 0x10);
    triton_test_set_register(REG_I386_FPREG5, ctx.registers.x86_xmm5);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_xmm5, 0x10);
    triton_test_set_register(REG_I386_FPREG6, ctx.registers.x86_xmm6);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_xmm6, 0x10);
    triton_test_set_register(REG_I386_FPREG7, ctx.registers.x86_xmm7);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_xmm7, 0x10);
    triton_test_set_register(REG_I386_RIP, ctx.registers.x86_rip);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_rip, 0x55555555480c);
    triton_test_set_register(REG_I386_EFLAGS, ctx.registers.x86_eflags);
//	ctx.setConcreteRegisterValue(ctx.registers.x86_eflags, 0x246);

}

static void triton_test_on_execute_instruction(void *opaque, uint64_t vaddr, void *code_addr)
{
    csh       handle;
    cs_insn*  insn;

    printf("triton_test_on_execute_instruction: %lX at code %lX\n", vaddr, (unsigned long)code_addr);

    /* Open capstone */
    if (cs_open(CS_ARCH_X86,CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("triton_test_on_execute_instruction: Cannot open capstone.");
    }

    /* Init capstone's options */
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    triton::arch::Instruction tinsn;

    /* Let's disass and build our operands */
    size_t count = cs_disasm(handle, static_cast<uint8_t*>(code_addr), 15, vaddr, 0, &insn);
	if (count > 0) {
        printf("0x%lX:\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic, insn[0].op_str);
		tinsn = triton::arch::Instruction(static_cast<uint8_t*>(code_addr), insn[0].size);
        ctx.processing(tinsn);
		cs_free(insn, count);
	} else {
		printf("triton_test_on_execute_instruction: Failed to disassemble given code!\n");
    }

	cs_close(&handle);
}

// These functions are required to setup the plugins
bool plugin_setup(void *plugin, const char *path)
{
    triton_test_info.parent = TYPE_PLUGIN_OBJECT;
    triton_test_info.name = TYPE_TRITONTEST_CPP;
    triton_test_info.instance_size = sizeof(TritonTest);
    triton_test_info.instance_init = triton_test_initfn;
    triton_test_info.instance_finalize = triton_test_finalize;
    triton_test_info.class_init = triton_test_class_init;
    triton_test_info.class_size = sizeof(TritonTestClass);

    qemu_plugin_register_type(plugin, &triton_test_info);

    return true;
}

bool plugin_init(void *opaque, const char *path, QemuOpts *opts)
{
    printf("plugin_init\n");
	ctx.setArchitecture(triton::arch::ARCH_X86_64);

    TritonTest *tt = TRITONTEST(opaque);
    (void)tt;
    return true;
}

void plugin_register_callbacks(void *opaque, PluginCallbacks *callbacks)
{
    printf("plugin_register_callbacks\n");

    callbacks->on_ra_start = triton_test_on_ra_start;
    callbacks->on_execute_instruction = triton_test_on_execute_instruction;
}
