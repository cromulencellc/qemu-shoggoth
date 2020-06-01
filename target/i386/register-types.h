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

#ifndef __REGISTER_TYPES_H__
#define __REGISTER_TYPES_H__

// The following registers are tied heavily to
// the CPU enums and in the CPUState struct.
// As the structs change this will need to change.
enum {
    REG_I386_RAX = 0,
    REG_I386_RCX = 1,
    REG_I386_RDX = 2,
    REG_I386_RBX = 3,
    REG_I386_RSP = 4,
    REG_I386_RBP = 5,
    REG_I386_RSI = 6,
    REG_I386_RDI = 7,
    REG_I386_R8 = 8,
    REG_I386_R9 = 9,
    REG_I386_R10 = 10,
    REG_I386_R11 = 11,
    REG_I386_R12 = 12,
    REG_I386_R13 = 13,
    REG_I386_R14 = 14,
    REG_I386_R15 = 15,
      
    REG_I386_ES = 32, 
    REG_I386_CS = 33, 
    REG_I386_SS = 34, 
    REG_I386_DS = 35,
    REG_I386_FS = 36, 
    REG_I386_GS = 37,

    REG_I386_CR0 = 38,
    REG_I386_CR1 = 39,
    REG_I386_CR2 = 40,
    REG_I386_CR3 = 41,
    REG_I386_CR4 = 42,

    REG_I386_FPREG0 = 43,
    REG_I386_FPREG1 = 44,
    REG_I386_FPREG2 = 45,
    REG_I386_FPREG3 = 46,
    REG_I386_FPREG4 = 47,
    REG_I386_FPREG5 = 48, 
    REG_I386_FPREG6 = 49,
    REG_I386_FPREG7 = 50,

    REG_I386_RIP = 51,
    REG_I386_EFLAGS = 52,
    REG_I386_GDTR = 53,
    REG_I386_IDTR = 54,
    REG_I386_LDTR = 55,
    REG_I386_TR = 56,
    REG_I386_EFER = 57,
    REG_I386_FPSTAT = 58,
    REG_I386_MXCSR =  59,
    REG_I386_MAX_CONTRL_REG = 60,
    

    REG_I386_EAX = 70,
    REG_I386_AX = 71,
    REG_I386_AH = 72,
    REG_I386_AL = 73,
    REG_I386_ECX = 74,
    REG_I386_CX = 75,
    REG_I386_CH = 76,
    REG_I386_CL = 77,
    REG_I386_EDX = 78,
    REG_I386_DX = 79,
    REG_I386_DH = 80,
    REG_I386_DL = 81,
    REG_I386_EBX = 82,
    REG_I386_BX = 83,
    REG_I386_BH = 84,
    REG_I386_BL = 85,
    REG_I386_ESP = 86,
    REG_I386_SP = 87,
    REG_I386_EBP = 88,
    REG_I386_BP = 89,
    REG_I386_ESI = 90,
    REG_I386_SI = 91,
    REG_I386_EDI = 92,
    REG_I386_DI = 93,
};

#endif
