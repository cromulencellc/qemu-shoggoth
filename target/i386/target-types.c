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

#include "qemu/osdep.h"
#include "qom/cpu.h"
#include "target-types.h"
#include "register-types.h"
#include "cpu.h"
#include "exec/gdbstub.h"
#include "sysemu/hw_accel.h"
#include "oshandler/oshandler.h"

#define UNUSED_NAME  "Reserved"

typedef struct RegInfo RegInfo;
struct RegInfo 
{
    const char *name;
    int reg_id;
    int real_id;
    int size;
    int offset;
};

// This is strongly tied to the X86 CPU structure. As it changes, this will have to change too.
static RegInfo extended_name_map[]     = { {"RAX", REG_I386_RAX, REG_I386_RAX, sizeof(uint64_t), 0},
                                           {"RCX", REG_I386_RCX, REG_I386_RCX, sizeof(uint64_t), 0},
                                           {"RDX", REG_I386_RDX, REG_I386_RDX, sizeof(uint64_t), 0},
                                           {"RBX", REG_I386_RBX, REG_I386_RBX, sizeof(uint64_t), 0},
                                           {"RSP", REG_I386_RSP, REG_I386_RSP, sizeof(uint64_t), 0},
                                           {"RBP", REG_I386_RBP, REG_I386_RBP, sizeof(uint64_t), 0},
                                           {"RSI", REG_I386_RSI, REG_I386_RSI, sizeof(uint64_t), 0},
                                           {"RDI", REG_I386_RDI, REG_I386_RDI, sizeof(uint64_t), 0},
                                           {"R8", REG_I386_R8, REG_I386_R8, sizeof(uint64_t), 0},
                                           {"R9", REG_I386_R9, REG_I386_R9, sizeof(uint64_t), 0},
                                           {"R10", REG_I386_R10, REG_I386_R10, sizeof(uint64_t), 0},
                                           {"R11", REG_I386_R11, REG_I386_R11, sizeof(uint64_t), 0},
                                           {"R12", REG_I386_R12, REG_I386_R12, sizeof(uint64_t), 0},
                                           {"R13", REG_I386_R13, REG_I386_R13, sizeof(uint64_t), 0},
                                           {"R14", REG_I386_R14, REG_I386_R14, sizeof(uint64_t), 0},
                                           {"R15", REG_I386_R15,REG_I386_R15, sizeof(uint64_t), 0},
                                           {"ES", REG_I386_ES, REG_I386_ES, sizeof(uint64_t), 0},
                                           {"CS", REG_I386_CS, REG_I386_CS, sizeof(uint64_t), 0},
                                           {"SS", REG_I386_SS, REG_I386_SS, sizeof(uint64_t), 0},
                                           {"DS", REG_I386_DS, REG_I386_DS, sizeof(uint64_t), 0},
                                           {"FS", REG_I386_FS, REG_I386_FS, sizeof(uint64_t), 0},
                                           {"GS", REG_I386_GS, REG_I386_GS, sizeof(uint64_t), 0},
                                           {"CR0", REG_I386_CR0, REG_I386_CR0, sizeof(uint64_t), 0},
                                           {"CR1", REG_I386_CR1, REG_I386_CR1, sizeof(uint64_t), 0},
                                           {"CR2", REG_I386_CR2, REG_I386_CR2, sizeof(uint64_t), 0},
                                           {"CR3", REG_I386_CR3, REG_I386_CR3, sizeof(uint64_t), 0},
                                           {"CR4", REG_I386_CR4, REG_I386_CR4, sizeof(uint64_t), 0},
                                           {"FPREG0", REG_I386_FPREG0, REG_I386_FPREG0, sizeof(FPReg), 0},
                                           {"FPREG1", REG_I386_FPREG1, REG_I386_FPREG1, sizeof(FPReg), 0},
                                           {"FPREG2", REG_I386_FPREG2, REG_I386_FPREG2, sizeof(FPReg), 0},
                                           {"FPREG3", REG_I386_FPREG3, REG_I386_FPREG3, sizeof(FPReg), 0},
                                           {"FPREG4", REG_I386_FPREG4, REG_I386_FPREG4, sizeof(FPReg), 0},
                                           {"FPREG5", REG_I386_FPREG5, REG_I386_FPREG5, sizeof(FPReg), 0},
                                           {"FPREG6", REG_I386_FPREG6, REG_I386_FPREG6, sizeof(FPReg), 0},
                                           {"FPREG7", REG_I386_FPREG7, REG_I386_FPREG7, sizeof(FPReg), 0},
                                           {"RIP", REG_I386_RIP, REG_I386_RIP, sizeof(uint64_t), 0},
                                           {"EFLAGS", REG_I386_EFLAGS, REG_I386_EFLAGS, sizeof(uint64_t), 0},
                                           {"GDTR", REG_I386_GDTR, REG_I386_GDTR, sizeof(uint64_t), 0},
                                           {"IDTR", REG_I386_IDTR, REG_I386_IDTR, sizeof(uint64_t), 0},
                                           {"LDTR", REG_I386_LDTR, REG_I386_LDTR,sizeof(uint64_t), 0},
                                           {"TR", REG_I386_TR, REG_I386_TR, sizeof(uint64_t), 0},
                                           {"EFER", REG_I386_EFER, REG_I386_EFER, sizeof(uint64_t), 0},
                                           {"FPSTAT", REG_I386_FPSTAT, REG_I386_FPSTAT, sizeof(float_status), 0},
                                           {"MXCSR", REG_I386_MXCSR, REG_I386_MXCSR, sizeof(uint32_t), 0},
                                           {"EAX", REG_I386_EAX, REG_I386_RAX, sizeof(uint32_t), 0},
                                           {"AX", REG_I386_AX, REG_I386_RAX, sizeof(uint16_t), 0},
                                           {"AH", REG_I386_AH, REG_I386_RAX, sizeof(uint8_t), 1},
                                           {"AL", REG_I386_AL, REG_I386_RAX, sizeof(uint8_t), 0},
                                           {"ECX", REG_I386_ECX, REG_I386_RCX, sizeof(uint32_t), 0},
                                           {"CX", REG_I386_CX, REG_I386_RCX, sizeof(uint16_t), 0},
                                           {"CH", REG_I386_CH, REG_I386_RCX, sizeof(uint8_t), 1},
                                           {"CL", REG_I386_CL, REG_I386_RCX, sizeof(uint8_t), 0},
                                           {"EDX", REG_I386_EDX, REG_I386_RDX, sizeof(uint32_t), 0},
                                           {"DX", REG_I386_DX, REG_I386_RDX, sizeof(uint16_t), 0},
                                           {"DH", REG_I386_DH, REG_I386_RDX, sizeof(uint8_t), 1},
                                           {"DL", REG_I386_DL, REG_I386_RDX, sizeof(uint8_t), 0},
                                           {"EBX", REG_I386_EBX, REG_I386_RBX, sizeof(uint32_t), 0},
                                           {"BX", REG_I386_BX, REG_I386_RBX, sizeof(uint16_t), 0},
                                           {"BH", REG_I386_BH, REG_I386_RBX, sizeof(uint8_t), 1},
                                           {"BL", REG_I386_BL, REG_I386_RBX, sizeof(uint8_t), 0},
                                           {"ESP", REG_I386_ESP, REG_I386_RSP, sizeof(uint32_t), 0},
                                           {"SP", REG_I386_SP, REG_I386_RSP, sizeof(uint16_t), 0},
                                           {"EBP", REG_I386_EBP, REG_I386_RBP, sizeof(uint32_t), 0},
                                           {"BP", REG_I386_BP, REG_I386_RBP, sizeof(uint16_t), 0},
                                           {"ESI", REG_I386_ESI, REG_I386_RSI, sizeof(uint32_t), 0},
                                           {"SI", REG_I386_SI, REG_I386_RSI, sizeof(uint16_t), 0},
                                           {"EDI", REG_I386_EDI, REG_I386_RDI, sizeof(uint32_t), 0},
                                           {"DI", REG_I386_DI, REG_I386_RDI, sizeof(uint16_t), 0}};

    
static RegInfo *get_register_info(int reg_id)
{
    int i;
    RegInfo *ret_val = NULL;

    for (i = 0; i < sizeof(extended_name_map)/sizeof(RegInfo) && !ret_val; ++i)
    {
        if (extended_name_map[i].reg_id == reg_id)
        {
            ret_val = &extended_name_map[i];
        }
    }
    return ret_val;
}

int get_target_first_register_id(void)
{
    return extended_name_map[0].reg_id;
}

int get_target_next_register_id(int reg_id)
{
    for (int i = 0; i < sizeof(extended_name_map)/sizeof(RegInfo); ++i)
    {
        if(extended_name_map[i].reg_id == reg_id)
        {
            if((i+1) < (sizeof(extended_name_map)/sizeof(RegInfo)))
            {
                return extended_name_map[i+1].reg_id;
            }
        }
    }

    return -1;
}

const char *get_target_register_name(int reg_id)
{
    for (int i = 0; i < sizeof(extended_name_map)/sizeof(RegInfo); ++i)
    {
        if(extended_name_map[i].reg_id == reg_id)
        {
            return extended_name_map[i].name;
        }
    }

    return NULL;
}

int get_target_register_id(const char *reg_name)
{
    for (int i = 0; i < sizeof(extended_name_map)/sizeof(RegInfo); ++i)
    {
        if (strcmp(reg_name, extended_name_map[i].name) == 0)
        {
            return extended_name_map[i].reg_id;
        }
    }

    return -1;
}

int remove_target_breakpoint(CPUState *cpu, uint64_t bp_addr, uint64_t length, int bp_flags)
{
    int err = 0;

    if (kvm_enabled())
    {
        err = kvm_remove_breakpoint(cpu, bp_addr, length, bp_flags);
        if(err) {
            return -1;
        }
    }else{
        switch (bp_flags) {
            case GDB_BREAKPOINT_SW:
            case GDB_BREAKPOINT_HW:
                err = cpu_breakpoint_remove(cpu, bp_addr, BP_GDB);
                if (err) {
                    return -1;
                }
                break;
            default:
                return -ENOSYS;
        }
    }

    return 1;
}

int set_target_breakpoint(CPUState *cpu, uint64_t bp_addr, uint64_t length, int bp_flags)
{
    int err = 0;

    if (kvm_enabled())
    {
        err = kvm_insert_breakpoint(cpu, bp_addr, length, bp_flags);
        if(err) {
            return -1;
        }
    }else{
        switch (bp_flags) {
            case GDB_BREAKPOINT_SW:
            case GDB_BREAKPOINT_HW:
                err = cpu_breakpoint_insert(cpu, bp_addr, BP_GDB, NULL);
                if (err) {
                    return -1;
                }
                break;
            default:
                return -ENOSYS;
        }
    }

    return 1;
}

uint8_t get_target_cpu_register(CPUState *cpu, int reg_id, uint8_t **data)
{
    uint8_t ret_val = 0;
    CPUClass *cpu_class = CPU_GET_CLASS(cpu);

    if (cpu_class->get_register_data && data)
    {  
        // Get info about the requested register
        RegInfo *child_info = get_register_info(reg_id);
        if (child_info)
        {
            
            // Read the real register
            cpu_class->get_register_data(cpu, child_info->real_id, data);
                
            // We may need to adjust the pointer a bit
            *data += child_info->offset;

            // Return the size of the register
            ret_val = child_info->size;
        }
    }
    return ret_val;
}

void set_target_cpu_register(CPUState *cpu, int reg_id, uint8_t size, const uint8_t *data)
{
    CPUClass *cpu_class = CPU_GET_CLASS(cpu);

    if (cpu_class->get_register_data && data)
    {
        // Get info for the register we are writing
        RegInfo *child_info = get_register_info(reg_id);
        if (child_info)
        {
            // Variables
            uint8_t *buffer;
            
            // Get information about the real register
            RegInfo *parent_info = get_register_info(child_info->real_id);
            
            // Read the register 
            cpu_class->get_register_data(cpu, parent_info->reg_id, &buffer);
            
            // Write the data into register memory
            memcpy(buffer + child_info->offset, data, MIN(child_info->size, size));
        }
    }
}
