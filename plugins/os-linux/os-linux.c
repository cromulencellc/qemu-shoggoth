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

#include "qemu/qemu-plugin.h"
#include "oshandler/oshandler.h"
#include "plugin/qemu-memory.h"
#include "plugin/qemu-registers.h"
#include "register-types.h"
#include "target/i386/cpu.h"
#include "oshandler/osarch_x86.h"
#include "sysemu/hw_accel.h"

#include <capstone.h>
#include <capstone/x86.h>
#include <limits.h>

#define EOUTPUT(...) fprintf (stderr, __VA_ARGS__)

// These macros define object operations
#define TYPE_LINUX "linux"
#define LINUX(obj)                                    \
    OBJECT_CHECK(Linux, (obj), TYPE_LINUX)
#define LINUX_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(LinuxClass, klass, TYPE_LINUX)
#define LINUX_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(Linux, obj, TYPE_LINUX)

// This is for opts
#define LINUX_COMM_NAME_SIZE (16)

#define PDPT_ENTRY_MASK (3 << 30)
#define PDPT_ENTRY_INVMASK (~PDPT_ENTRY_MASK)
#define KVM_ENTRY_MASK (1 << 12)
#define KVM_ENTRY_INVMASK (~KVM_ENTRY_MASK)

typedef struct Linux
{
   OSHandler obj;

   uint64_t div0_entry;
   uint64_t divE_entry;
   uint64_t do_divide_error;
   uint64_t do_page_fault;
   uint64_t __do_page_fault;
   uint64_t do_error_trap;
   uint64_t do_trap;
   uint64_t do_syscall_64;
   uint64_t do_umount;
   uint64_t sys_call_table;

   uint64_t vmalloc_fault;

   uint64_t phys_base_ptr;
   uint64_t vmalloc_base_ptr;
   uint64_t page_offset_base_ptr;

   uint64_t phys_base;
   uint64_t vmalloc_base;
   uint64_t page_offset_base;

   uint64_t current_task;

   uint64_t kern_gs_base;

   uint64_t task_mm_offset;
   uint64_t task_pid_offset;
   uint64_t task_comm_offset;
   uint64_t task_fs_offset;
   uint64_t task_pids_offset;

   QList* process_list;

   csh x86_disas_handle;
   uint64_t current_process;

   CPUState *cpu;
} Linux;

typedef struct LinuxClass
{
    OSHandlerClass parent;
} LinuxClass;

static void setup_disassemble(Linux* ctxt)
{
   X86CPU* archx86 = X86_CPU(ctxt->cpu);
   cs_mode disas_mode = CS_MODE_32;

   if(archx86->env.cr[4] & (1 << 5))
   {
      // Is this necessary?
      // fprintf(stderr, "Setting long mode to disassemble\n");
      disas_mode = CS_MODE_64;
   }

   ctxt->x86_disas_handle = 0;

   // need to get processor mode
   cs_err err = cs_open(CS_ARCH_X86, disas_mode, &ctxt->x86_disas_handle);
   if (err) {
      printf("Failed on cs_open() with error returned: %u\n", err);
      return;
   }

   cs_option(ctxt->x86_disas_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

static void cleanup_disassemble(Linux* ctxt)
{
   cs_close(&ctxt->x86_disas_handle);
   ctxt->x86_disas_handle = 0;
}

static uint32_t disassemble_mem(Linux* ctxt, cs_insn** disas_instr, uint64_t addr)
{
   uint8_t *buffer = NULL;

   qemu_get_virtual_memory(ctxt->cpu->cpu_index, addr, 16, &buffer);
   if(!buffer){
      return 0;
   }

   uint32_t disas_count = cs_disasm(ctxt->x86_disas_handle, buffer, 16, addr, /*num_instr*/ 1, disas_instr);
   g_free(buffer);
   return disas_count;
}

static bool parse_do_trap(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   cs_insn* instr = NULL;

   cur_addr = ctxt->do_trap;
   for(uint32_t i = 0; i < 50; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);
      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         if(cur_instr->id == X86_INS_MOV
            && op1->type == X86_OP_REG
            && op2->type == X86_OP_MEM
            && op2->mem.segment == X86_REG_GS )
         {
            ctxt->current_task = ctxt->kern_gs_base + op2->mem.disp;
            cs_free(instr, num_instr);
            return true;
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return false;
}

static bool parse_div0_idte(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint64_t idt_addr = 0;
   uint32_t num_instr = 0;
   uint32_t inst_count = 0;

   cs_insn* instr = NULL;

   X86CPU *x86_cpu = X86_CPU(ctxt->cpu);
   CPUX86State *env = &x86_cpu->env;

   ctxt->kern_gs_base = env->segs[R_GS].base;

   if(ctxt->kern_gs_base == 0 && env->kernelgsbase > 0)
   {
      ctxt->kern_gs_base = env->kernelgsbase;
   }

   idt_addr = env->idt.base;
   ctxt->div0_entry = parse_idt_entry_base(ctxt->cpu, idt_addr, 0);

   cur_addr = ctxt->div0_entry;
   for(uint32_t i = 0; i < 20; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* cur_detail = &(cur_instr->detail->x86);

         if(cur_instr->id == X86_INS_CALL)
         {
            if(inst_count == 1)
            {
               if(cur_detail->operands[0].type == X86_OP_IMM) {
                  ctxt->do_divide_error = cur_detail->operands[0].imm;
                  cs_free(instr, num_instr);
                  return true;
               }
            }
            else
            {
               inst_count++;
            }
         }
         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return false;
}

static bool parse_divE_idte(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   uint32_t inst_count = 0;

   cs_insn* instr = NULL;

   X86CPU *x86_cpu = X86_CPU(ctxt->cpu);
   CPUX86State *env = &x86_cpu->env;

   ctxt->kern_gs_base = env->segs[R_GS].base;

   if(ctxt->kern_gs_base == 0 && env->kernelgsbase > 0)
   {
      ctxt->kern_gs_base = env->kernelgsbase;
   }

   ctxt->divE_entry = parse_idt_entry_base(ctxt->cpu, env->idt.base, 0x0E);

   cur_addr = ctxt->divE_entry;
   for(uint32_t i = 0; i < 20; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* cur_detail = &(cur_instr->detail->x86);

         if(cur_instr->id == X86_INS_CALL)
         {
            if(inst_count == 1)
            {
               if(cur_detail->operands[0].type == X86_OP_IMM) {
                  ctxt->do_page_fault = cur_detail->operands[0].imm;
                  return true;
               }
            }
            else
            {
               inst_count++;
            }
         }
         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return false;
}

static bool parse_do_page_fault(Linux* ctxt)
{
   uint64_t current_call = 0;
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   cs_insn* instr = NULL;

   cur_addr = ctxt->do_page_fault;
   for(uint32_t i = 0; i < 120; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }
         // {
         //    printf("cur_instr is %s (%d)\n", cur_instr->mnemonic, cur_instr->id);
         //    for(uint32_t n = 0; n < detail->op_count; n++ )
         //    {
         //       cs_x86_op *op = &(detail->operands[n]);
         //       printf("  op->type (size) = %d (%d): ", op->type, op->size);
         //       if( op->type == X86_OP_REG)
         //       {
         //          printf("    OP REG  %d\n", detail->operands[n].reg);
         //       }else
         //       if( op->type == X86_OP_IMM )
         //       {
         //          printf("    OP IMM  %#"PRIx64"\n", detail->operands[n].imm);
         //       }else
         //       if( op->type == X86_OP_MEM )
         //       {
         //          printf("    OP MEM BASE %du\n", detail->operands[n].mem.base);
         //          printf("    OP MEM DISP %ld\n", detail->operands[n].mem.disp);
         //       }
         //    }
         //    printf("\n");
         // }

         // follow the first branch in each function
         // and look for an access to gs:current_task
         if(cur_instr->id == X86_INS_JMP || cur_instr->id == X86_INS_CALL)
         {
            if(op1->type == X86_OP_IMM){
               current_call = op1->imm;
               cur_addr = current_call;
               break;
            }
         }else
         // find register holding current task
         if(cur_instr->id == X86_INS_MOV
            && op1->type == X86_OP_REG
            && op2->type == X86_OP_MEM
            && op2->mem.segment == X86_REG_GS
            && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
         {
            // this is __do_page_fault
            ctxt->__do_page_fault = current_call;
            cs_free(instr, num_instr);
            return true;
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return false;
}

static bool parse_inner_do_page_fault(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   cs_insn* instr = NULL;
   x86_reg target_reg = X86_REG_INVALID;
   x86_reg rsi_arg = X86_REG_INVALID;
   x86_reg rdi_arg = X86_REG_INVALID;

   cur_addr = ctxt->__do_page_fault;

   for(uint32_t i = 0; i < 200; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         // follow the local register and look for pass to register args
         if(target_reg != X86_REG_INVALID)
         {
            // look for pass to rdi
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op1->reg == X86_REG_RDI
               && op2->type == X86_OP_REG)
            {
               rdi_arg = op2->reg;
            }else
            // look for pass to rsi
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op1->reg == X86_REG_RSI
               && op2->type == X86_OP_REG)
            {
               rsi_arg = op2->reg;
            }else
            if(cur_instr->id == X86_INS_CALL
               && op1->type == X86_OP_IMM)
            {
               // is this the right call?
               if(rsi_arg == X86_REG_INVALID
                  && rdi_arg == target_reg)
               {
                  ctxt->vmalloc_fault = op1->imm;
                  cs_free(instr, num_instr);
                  return true;
               }else{
                  rsi_arg = X86_REG_INVALID;
                  rdi_arg = X86_REG_INVALID;
               }
            }
         }else{
            // look for the first assignment of register
            // argument RDI to local register
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_REG
               && op2->reg == X86_REG_RDI)
            {
               // move the register
               target_reg = op1->reg;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return false;
}

static bool parse_vmalloc_fault(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   cs_insn* instr = NULL;

   cur_addr = ctxt->vmalloc_fault;
   for(uint32_t i = 0; i < 10; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         if(cur_instr->id == X86_INS_MOV
            && op1->type == X86_OP_REG
            && op2->type == X86_OP_MEM
            && op2->mem.base == X86_REG_RIP)
         {
            ctxt->vmalloc_base_ptr = cur_addr + cur_instr->size + op2->mem.disp;
            ctxt->page_offset_base_ptr = ctxt->vmalloc_base_ptr + sizeof(uint64_t);
            qemu_load_u64(ctxt->cpu->cpu_index, ctxt->vmalloc_base_ptr, &ctxt->vmalloc_base);
            qemu_load_u64(ctxt->cpu->cpu_index, ctxt->page_offset_base_ptr, &ctxt->page_offset_base);
            cs_free(instr, num_instr);
            return true;
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return false;
}

// static bool parse_sys_mprotect(Linux* ctxt)
// {
//    uint64_t cur_addr = 0;
//    uint32_t num_instr = 0;
//    cs_insn* instr = NULL;
//    x86_reg entry_reg = X86_REG_INVALID;
//    x86_reg nr_segments_reg = X86_REG_INVALID;
//    x86_reg segments_reg = X86_REG_INVALID;
//    x86_reg flags_reg = X86_REG_INVALID;
//    // x86_reg target_reg = X86_REG_INVALID;
//    int stage = 0;
//    x86_reg rdi_arg = X86_REG_INVALID;
//    x86_reg rsi_arg = X86_REG_INVALID;
//    x86_reg rdx_arg = X86_REG_INVALID;
//    x86_reg rcx_arg = X86_REG_INVALID;
//    x86_reg r8_arg = X86_REG_INVALID;

//    qemu_load_u64(ctxt->cpu->cpu_index, ctxt->sys_call_table+8*246, &cur_addr);

//    // sys_kexec_load -> machine_kexec_prepare

// // var 1
// // sys_kexec_load+11   49 89 FE                                mov     r14, rdi
// // sys_kexec_load+14   53                                      push    rbx
// // sys_kexec_load+15   BF 16 00 00 00                          mov     edi, 16h
// // sys_kexec_load+1A   49 89 F4                                mov     r12, rsi
// // sys_kexec_load+1D   49 89 D7                                mov     r15, rdx
// // sys_kexec_load+20   48 89 CB                                mov     rbx, rcx

// // sys_kexec_load+123  48 8D 7D C8                             lea     rdi, [rbp-38h]
// // sys_kexec_load+127  4C 89 F6                                mov     rsi, r14
// // sys_kexec_load+12A  49 89 D8                                mov     r8, rbx
// // sys_kexec_load+12D  4C 89 F9                                mov     rcx, r15
// // sys_kexec_load+130  4C 89 E2                                mov     rdx, r12
// // sys_kexec_load+133  49 C7 C5 10 81 16 82                    mov     r13, offset kexec_image
// // sys_kexec_load+13A  E8 51 FD FF FF                          call    kimage_alloc_init

// // var 2
// // .text:FFFFFFFF811213DB 48 8B 5F 38                             mov     rbx, [rdi+38h]
// // .text:FFFFFFFF811213DF 4C 8B 67 60                             mov     r12, [rdi+60h]
// // .text:FFFFFFFF811213E3 48 8B 6F 68                             mov     rbp, [rdi+68h]
// // .text:FFFFFFFF811213E7 4C 8B 6F 70                             mov     r13, [rdi+70h]

// //       FFFFF81121475 48 89 D9                                   mov     rcx, rbx
// // .text:FFFFFFFF81121478 4C 89 E2                                mov     rdx, r12
// // .text:FFFFFFFF8112147B 48 89 EE                                mov     rsi, rbp
// // .text:FFFFFFFF8112147E 4C 89 EF                                mov     rdi, r13
// // .text:FFFFFFFF81121481 E8 4A FB FF FF                          call    do_kexec_load

//    for(uint32_t i = 0; i < 50; i++)
//    {
//       num_instr = disassemble_mem(ctxt, &instr, cur_addr);

//       for(uint32_t j = 0; j < num_instr; j++)
//       {
//          cs_insn* cur_instr = &instr[j];
//          cs_x86* detail = &(cur_instr->detail->x86);
//          cs_x86_op *op1 = NULL;
//          cs_x86_op *op2 = NULL;
//          switch(detail->op_count)
//          {
//             case 2:
//                op2 = &(detail->operands[1]);
//             case 1:
//                op1 = &(detail->operands[0]);
//                break;
//          }

//          {
//             printf("cur_instr is %s (%d)\n", cur_instr->mnemonic, cur_instr->id);
//             for(uint32_t n = 0; n < detail->op_count; n++ )
//             {
//                cs_x86_op *op = &(detail->operands[n]);
//                printf("  op->type (size) = %d (%d): ", op->type, op->size);
//                if( op->type == X86_OP_REG)
//                {
//                   printf("    OP REG  %d\n", detail->operands[n].reg);
//                }else
//                if( op->type == X86_OP_IMM )
//                {
//                   printf("    OP IMM  %#"PRIx64"\n", detail->operands[n].imm);
//                }else
//                if( op->type == X86_OP_MEM )
//                {
//                   printf("    OP MEM BASE %du\n", detail->operands[n].mem.base);
//                   printf("    OP MEM DISP %ld\n", detail->operands[n].mem.disp);
//                }
//             }
//             printf("\n");
//          }
         
//          // use input args to find kmexec_machine_prepare
//          if(stage < 4){
//             // get input arguments
//             if(cur_instr->id == X86_INS_MOV
//                && op1->type == X86_OP_REG
//                && op1->size == 8
//                && ((stage == 3 && op2->type == X86_OP_MEM && op2->mem.segment == X86_REG_RDI)
//                || (op2->type == X86_OP_REG && op2->reg == X86_REG_RDI)))
//             {
//                entry_reg = op1->reg;
//                stage++;
//             }else if(cur_instr->id == X86_INS_MOV
//                && op1->type == X86_OP_REG
//                && op1->size == 8
//                && ((stage == 2 && op2->type == X86_OP_MEM && op2->mem.segment == X86_REG_RDI)
//                || (op2->type == X86_OP_REG && op2->reg == X86_REG_RSI)))
//             {
//                nr_segments_reg = op1->reg;
//                stage++;
//             }else if(cur_instr->id == X86_INS_MOV
//                && op1->type == X86_OP_REG
//                && op1->size == 8
//                && ((stage == 1 && op2->type == X86_OP_MEM && op2->mem.segment == X86_REG_RDI)
//                || (op2->type == X86_OP_REG && op2->reg == X86_REG_RDX)))
//             {
//                segments_reg = op1->reg;
//                stage++;
//             }else if(cur_instr->id == X86_INS_MOV
//                && op1->type == X86_OP_REG
//                && op1->size == 8
//                && ((stage == 0 && op2->type == X86_OP_MEM && op2->mem.segment == X86_REG_RDI)
//                || (op2->type == X86_OP_REG && op2->reg == X86_REG_RCX)))
//             {
//                flags_reg = op1->reg;
//                stage++;
//             }
//          }else if(stage == 4)
//          {
//             // look for pass to arguments
//             if(cur_instr->id == X86_INS_MOV
//                && op1->type == X86_OP_REG
//                && op2->type == X86_OP_REG)
//             {
//                if(op1->reg == X86_REG_RDI){
//                   rdi_arg = op2->reg;
//                }else if(op1->reg == X86_REG_RSI){
//                   rsi_arg = op2->reg;
//                }else if(op1->reg == X86_REG_RDX){
//                   rdx_arg = op2->reg;
//                }else if(op1->reg == X86_REG_RCX){
//                   rcx_arg = op2->reg;
//                }else if(op1->reg == X86_REG_R8){
//                   r8_arg = op2->reg;
//                }
//             }else
//             if(cur_instr->id == X86_INS_CALL
//                && op1->type == X86_OP_IMM)
//             {
//                if( rdi_arg == entry_reg
//                   && rsi_arg == nr_segments_reg
//                   && rdx_arg == segments_reg
//                   && rcx_arg == flags_reg)
//                {
//                   if(r8_arg == X86_REG_INVALID)
//                   {
//                      // this do_kexec_load so follow it...
//                      cur_addr = op1->imm;
//                      break;
//                   }else{
//                      // this is kimage_alloc_init so the return image is in rdi
                     
//                   }
                  
//                }

//                rdi_arg = X86_REG_INVALID;
//                rsi_arg = X86_REG_INVALID;
//                rdx_arg = X86_REG_INVALID;
//                rcx_arg = X86_REG_INVALID;
//                r8_arg = X86_REG_INVALID;
//             }
//          }
//       }
//    }

//    return false;
// }

static bool parse_sys_mprotect(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   cs_insn* instr = NULL;
   x86_reg rsi_arg = X86_REG_INVALID;
   x86_reg target_reg = X86_REG_INVALID;
   int stage = 0;
   bool pop_vma_sig = false;
   bool found_lea_image = false;
   uint64_t current_call = 0;
   int instr_count = 0;

   // this one is doozy... sorry...
   // (0) sys_mprotect find with gs:current_task
   // (1) do_mprotect_pkey uses lea from stack struct
   // (2) mprotect_fixup uses mov rbp, rdx -> mov rsi, rbp
   // (3) follow first function looking for cmovb cs:phys_base or mov cs:phys_base
   // (4) if (3) failed then proceed to look in change_protection itself

   qemu_load_u64(ctxt->cpu->cpu_index, ctxt->sys_call_table+8*10, &cur_addr);
   current_call = cur_addr;

   for(uint32_t i = 0; i < 1500; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         // if(stage == 3){
         //    printf("cur_instr is %s (%d)\n", cur_instr->mnemonic, cur_instr->id);
         //    for(uint32_t n = 0; n < detail->op_count; n++ )
         //    {
         //       cs_x86_op *op = &(detail->operands[n]);
         //       printf("  op->type (size) = %d (%d): ", op->type, op->size);
         //       if( op->type == X86_OP_REG)
         //       {
         //          printf("    OP REG  %d\n", detail->operands[n].reg);
         //       }else
         //       if( op->type == X86_OP_IMM )
         //       {
         //          printf("    OP IMM  %#"PRIx64"\n", detail->operands[n].imm);
         //       }else
         //       if( op->type == X86_OP_MEM )
         //       {
         //          printf("    OP MEM BASE %du\n", detail->operands[n].mem.base);
         //          printf("    OP MEM DISP %ld\n", detail->operands[n].mem.disp);
         //       }
         //    }
         //    printf("\n");
         // }

         if(stage == 0)
         {
            // find register holding current task
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.segment == X86_REG_GS
               && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
            {
               // this is do_mprotect_pkey or sys_mprotect
               cur_addr = current_call;
               current_call = 0;
               stage = 1;
               break;
            }else
            // follow the first call in every function
            if(cur_instr->id == X86_INS_CALL
               && op1->type == X86_OP_IMM)
            {
               cur_addr = op1->imm;
               current_call = cur_addr;
               break;
            }
         }else if(stage == 1)
         {
            // look for local structure pass to rsi, which is the image
            if(cur_instr->id == X86_INS_LEA
               && op1->type == X86_OP_REG
               && op1->reg == X86_REG_RSI
               && op2->type == X86_OP_MEM
               && (op2->mem.base == X86_REG_RBP || op2->mem.base == X86_REG_RSP))
            {
               found_lea_image = true;
            }else
            if(cur_instr->id == X86_INS_CALL
               && op1->type == X86_OP_IMM)
            {
               // is this the right call?
               if(found_lea_image)
               {
                  stage = 2;
                  cur_addr = op1->imm;
                  break;
               }
            }
         }else if(stage == 2)
         {
            // follow the local register and look for pass to register args
            if(target_reg != X86_REG_INVALID)
            {
               // look for pass to rsi
               if(cur_instr->id == X86_INS_MOV
                  && op1->type == X86_OP_REG
                  && op1->reg == X86_REG_RSI
                  && op2->type == X86_OP_REG)
               {
                  rsi_arg = op2->reg;
               }else if((cur_instr->id == X86_INS_SUB
                  || cur_instr->id == X86_INS_SHR
                  || cur_instr->id == X86_INS_ADD
                  || cur_instr->id == X86_INS_SHL)
                  && op1->type == X86_OP_REG
                  && op1->reg == target_reg)
               {
                  // something modified our target reg so get rid of it
                  target_reg = X86_REG_INVALID;
               }
            }else{
               // look for the first assignment of register
               // argument RDX to local register
               if(cur_instr->id == X86_INS_MOV
                  && op1->type == X86_OP_REG
                  && op2->type == X86_OP_REG
                  && op2->reg == X86_REG_RDX)
               {
                  // move the register
                  target_reg = op1->reg;
               }
            }

            // special case, invalidate next call after xor ecx, ecx
            if(cur_instr->id == X86_INS_XOR
               && op1->type == X86_OP_REG
               && op1->reg == X86_REG_ECX
               && op2->type == X86_OP_REG
               && op2->reg == X86_REG_ECX)
            {
               pop_vma_sig = true;
            }

            if(target_reg != X86_REG_INVALID
               && cur_instr->id == X86_INS_CALL
               && op1->type == X86_OP_IMM)
            {
               // is this the right call?
               if(rsi_arg == target_reg
                  && !pop_vma_sig)
               {
                  stage = 3;
                  cur_addr = op1->imm;
                  current_call = cur_addr;
                  break;
               }else{
                  rsi_arg = X86_REG_INVALID;
                  pop_vma_sig = false;
               }
            }
         }else if(stage == 3){
            // take first call to either change_protection_range or
            // hugetlb_change_protection
            if((cur_instr->id == X86_INS_CALL || cur_instr->id == X86_INS_JMP)
               && op1->type == X86_OP_IMM)
            {
               cur_addr = op1->imm;
               stage = 4;
               break;
            }
            // if we don't find functions immediately then everything was inlined
            instr_count++;
            if( instr_count >= 25 ){
               // continue searching for phys_base in this function...
               stage = 4;
            }
         }else if(stage == 4){
            // look in this function for the cs relative mov
            if((cur_instr->id == X86_INS_CMOVB || cur_instr->id == X86_INS_MOV)
               && op1->type == X86_OP_REG
               && op1->size == 8
               && op2->type == X86_OP_MEM
               && op2->mem.base == X86_REG_RIP)
            {
               ctxt->phys_base_ptr = cur_addr + cur_instr->size + op2->mem.disp;
               qemu_load_u64(ctxt->cpu->cpu_index, ctxt->phys_base_ptr, &ctxt->phys_base);
               cs_free(instr, num_instr);
               return true;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   // uint64_t inner_addr = 0;
   // cs_insn* inner_instr = NULL;
   // uint32_t num_inner = 0;
   // // lookup failed in base function of change_protection...
   // // so proceed to look in inner functions for phys_base.
   // if( current_call )
   // {
   //    printf("Lookup failed, try again in change_protection %lX\n", current_call);
   //    for(uint32_t i = 0; i < 30; i++)
   //    {
   //       num_instr = disassemble_mem(ctxt, &instr, cur_addr);

   //       for(uint32_t j = 0; j < num_instr; j++)
   //       {
   //          cs_insn* cur_instr = &instr[j];
   //          // {
   //          //    cs_x86* detail = &(cur_instr->detail->x86);
   //          //    printf("cur_instr is %s (%d)\n", cur_instr->mnemonic, cur_instr->id);
   //          //    for(uint32_t n = 0; n < detail->op_count; n++ )
   //          //    {
   //          //       cs_x86_op *op = &(detail->operands[n]);
   //          //       printf("  op->type (size) = %d (%d): ", op->type, op->size);
   //          //       if( op->type == X86_OP_REG)
   //          //       {
   //          //          printf("    OP REG  %d\n", detail->operands[n].reg);
   //          //       }else
   //          //       if( op->type == X86_OP_IMM )
   //          //       {
   //          //          printf("    OP IMM  %#"PRIx64"\n", detail->operands[n].imm);
   //          //       }else
   //          //       if( op->type == X86_OP_MEM )
   //          //       {
   //          //          printf("    OP MEM BASE %du\n", detail->operands[n].mem.base);
   //          //          printf("    OP MEM DISP %ld\n", detail->operands[n].mem.disp);
   //          //       }
   //          //    }
   //          //    printf("\n");
   //          // }

   //          if(cur_instr->id == X86_INS_CALL
   //             && cur_instr->detail->x86.operands[0].type == X86_OP_IMM)
   //          {
   //             inner_addr = cur_instr->detail->x86.operands[0].imm;

   //             for(uint32_t k = 0; k < 2000; k++)
   //             {
   //                num_inner = disassemble_mem(ctxt, &inner_instr, inner_addr);

   //                for(uint32_t l = 0; l < num_inner; l++)
   //                {
   //                   cs_insn* cur_inner_instr = &inner_instr[l];
   //                   cs_x86* detail = &(cur_inner_instr->detail->x86);
   //                   cs_x86_op *op1 = NULL;
   //                   cs_x86_op *op2 = NULL;
   //                   switch(detail->op_count)
   //                   {
   //                      case 2:
   //                         op2 = &(detail->operands[1]);
   //                      case 1:
   //                         op1 = &(detail->operands[0]);
   //                         break;
   //                   }

   //                   if(cur_inner_instr->id == X86_INS_CMOVB
   //                      && op1->type == X86_OP_REG
   //                      && op2->type == X86_OP_MEM
   //                      && op2->mem.base == X86_REG_RIP)
   //                   {
   //                      printf("found phys_base!!!!!!!!!!!!!!!!!!\n");
   //                      ctxt->phys_base_ptr = inner_addr + cur_inner_instr->size + op2->mem.disp;
   //                      qemu_load_u64(ctxt->cpu->cpu_index, ctxt->phys_base_ptr, &ctxt->phys_base);
   //                      cs_free(inner_instr, num_inner);
   //                      cs_free(instr, num_instr);
   //                      return true;
   //                   }

   //                   inner_addr += cur_inner_instr->size;
   //                }

   //                cs_free(inner_instr, num_inner);
   //             }
   //          }

   //          cur_addr += cur_instr->size;
   //       }

   //       cs_free(instr, num_instr);
   //    }
   // }

   // // lookup failed in base function of change_protection...
   // // so proceed to look in inner functions for phys_base.
   // if( current_call )
   // {
   //    printf("Lookup failed, going into inner functions for %lX\n", current_call);
   //    for(uint32_t i = 0; i < 30; i++)
   //    {
   //       num_instr = disassemble_mem(ctxt, &instr, cur_addr);

   //       for(uint32_t j = 0; j < num_instr; j++)
   //       {
   //          cs_insn* cur_instr = &instr[j];
   //          // {
   //          //    cs_x86* detail = &(cur_instr->detail->x86);
   //          //    printf("cur_instr is %s (%d)\n", cur_instr->mnemonic, cur_instr->id);
   //          //    for(uint32_t n = 0; n < detail->op_count; n++ )
   //          //    {
   //          //       cs_x86_op *op = &(detail->operands[n]);
   //          //       printf("  op->type (size) = %d (%d): ", op->type, op->size);
   //          //       if( op->type == X86_OP_REG)
   //          //       {
   //          //          printf("    OP REG  %d\n", detail->operands[n].reg);
   //          //       }else
   //          //       if( op->type == X86_OP_IMM )
   //          //       {
   //          //          printf("    OP IMM  %#"PRIx64"\n", detail->operands[n].imm);
   //          //       }else
   //          //       if( op->type == X86_OP_MEM )
   //          //       {
   //          //          printf("    OP MEM BASE %du\n", detail->operands[n].mem.base);
   //          //          printf("    OP MEM DISP %ld\n", detail->operands[n].mem.disp);
   //          //       }
   //          //    }
   //          //    printf("\n");
   //          // }

   //          if(cur_instr->id == X86_INS_CALL
   //             && cur_instr->detail->x86.operands[0].type == X86_OP_IMM)
   //          {
   //             inner_addr = cur_instr->detail->x86.operands[0].imm;

   //             for(uint32_t k = 0; k < 2000; k++)
   //             {
   //                num_inner = disassemble_mem(ctxt, &inner_instr, inner_addr);

   //                for(uint32_t l = 0; l < num_inner; l++)
   //                {
   //                   cs_insn* cur_inner_instr = &inner_instr[l];
   //                   cs_x86* detail = &(cur_inner_instr->detail->x86);
   //                   cs_x86_op *op1 = NULL;
   //                   cs_x86_op *op2 = NULL;
   //                   switch(detail->op_count)
   //                   {
   //                      case 2:
   //                         op2 = &(detail->operands[1]);
   //                      case 1:
   //                         op1 = &(detail->operands[0]);
   //                         break;
   //                   }

   //                   if(cur_inner_instr->id == X86_INS_CMOVB
   //                      && op1->type == X86_OP_REG
   //                      && op2->type == X86_OP_MEM
   //                      && op2->mem.base == X86_REG_RIP)
   //                   {
   //                      printf("found phys_base!!!!!!!!!!!!!!!!!!\n");
   //                      ctxt->phys_base_ptr = inner_addr + cur_inner_instr->size + op2->mem.disp;
   //                      qemu_load_u64(ctxt->cpu->cpu_index, ctxt->phys_base_ptr, &ctxt->phys_base);
   //                      cs_free(inner_instr, num_inner);
   //                      cs_free(instr, num_instr);
   //                      return true;
   //                   }

   //                   inner_addr += cur_inner_instr->size;
   //                }

   //                cs_free(inner_instr, num_inner);
   //             }
   //          }

   //          cur_addr += cur_instr->size;
   //       }

   //       cs_free(instr, num_instr);
   //    }
   // }

   return false;
}

static bool parse_do_divide_error(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   cs_insn* instr = NULL;

   cur_addr = ctxt->do_divide_error;
   for(uint32_t i = 0; i < 10; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* cur_detail = &(cur_instr->detail->x86);

         if((cur_instr->id == X86_INS_CALL || cur_instr->id == X86_INS_JMP)
            && cur_detail->operands[0].type == X86_OP_IMM)
         {
            ctxt->do_error_trap = cur_detail->operands[0].imm;
            cs_free(instr, num_instr);
            return true;
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return false;
}

static uint64_t find_syscall_table(Linux* ctxt, uint64_t routine)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   uint64_t sys_call_table = 0;
   cs_insn* instr = NULL;

   cur_addr = routine;

   for(uint32_t i = 0; i < 50; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      // for(uint32_t j = 0; j < num_instr; j++)
      // {
      //    cs_insn* cur_instr = &instr[j];
      //    cs_detail *detail = cur_instr->detail;
      //    printf("cur_instr is %s (%d)\n", cur_instr->mnemonic, cur_instr->id);
      //    for(uint32_t n = 0; n < detail->x86.op_count; n++ )
      //    {
      //       cs_x86_op *op = &(detail->x86.operands[n]);
      //       printf("  op->type = %d: ", op->type);
      //       if( op->type == X86_OP_REG)
      //       {
      //          printf("    OP REG  %d\n", detail->x86.operands[n].reg);
      //       }else
      //       if( op->type == X86_OP_IMM )
      //       {
      //          printf("    OP IMM  %#"PRIx64"\n", detail->x86.operands[n].imm);
      //       }else
      //       if( op->type == X86_OP_MEM )
      //       {
      //          printf("    OP MEM SEGMENT %du\n", detail->x86.operands[n].mem.segment);
      //          printf("    OP MEM SCALE %d\n", detail->x86.operands[n].mem.scale);
      //          printf("    OP MEM BASE %du\n", detail->x86.operands[n].mem.base);
      //          printf("    OP MEM DISP %lX\n", detail->x86.operands[n].mem.disp);
      //       }
      //    }
      // }

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         if(cur_instr->id == X86_INS_MOV
            && op1->type == X86_OP_REG
            && op2->type == X86_OP_MEM
            && op2->mem.scale == 8)
         {
            sys_call_table = op2->mem.disp;
            cs_free(instr, num_instr);
            return sys_call_table;
         }
         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return 0;
}

static bool parse_do_syscall(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   cs_insn* instr = NULL;

   X86CPU *x86_cpu = X86_CPU(ctxt->cpu);
   CPUX86State *env = &x86_cpu->env;

   ctxt->do_syscall_64 = env->lstar;

   // look for the syscall table call directly first...
   cur_addr = ctxt->do_syscall_64;
   for(uint32_t i = 0; i < 50; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);
      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         switch(detail->op_count)
         {
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         if(cur_instr->id == X86_INS_CALL
            && op1->type == X86_OP_MEM
            && op1->mem.scale == 8)
         {
            ctxt->sys_call_table = op1->mem.disp;
            cs_free(instr, num_instr);
            return true;
         }
         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   // didn't find it directly in the syscall routine, so look for a syscall function
   cur_addr = ctxt->do_syscall_64;
   for(uint32_t i = 0; i < 150; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* cur_detail = &(cur_instr->detail->x86);

         if(cur_instr->id == X86_INS_CALL
            && cur_detail->operands[0].type == X86_OP_IMM)
         {
            uint64_t ret_val = find_syscall_table(ctxt, cur_detail->operands[0].imm);
            if( ret_val > 0 ){
               ctxt->sys_call_table = ret_val;
               ctxt->do_syscall_64 = cur_detail->operands[0].imm;
               cs_free(instr, num_instr);
               return true;
            }
         }
         cur_addr += cur_instr->size;
      }
      cs_free(instr, num_instr);
   }

   return false;
}

static bool parse_do_error_trap(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   uint32_t inst_count = 0;

   cs_insn* instr = NULL;

   cur_addr = ctxt->do_error_trap;
   for(uint32_t i = 0; i < 50; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);
      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86* cur_detail = &(cur_instr->detail->x86);

         if(cur_instr->id == X86_INS_CALL)
         {
            if(inst_count == 1)
            {
               if(cur_detail->operands[0].type == X86_OP_IMM)
               {
                  ctxt->do_trap = cur_detail->operands[0].imm;
                  cs_free(instr, num_instr);
                  return true;
               }
            }
            else
            {
               inst_count++;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return false;
}

/* // Handles an ubuntu type kernel
static bool parse_do_error_trap2(Linux* ctxt, CPUState* cs)
{
   uint64_t cur_addr = 0;

   uint32_t num_instr = 0;
   uint32_t inst_count = 0;

   bool found = false;

   cs_insn* instr = NULL;

   cur_addr = ctxt->do_error_trap;
   for(uint32_t i = 0; i < 50; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);
      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

         // EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "call", sizeof(cur_instr->mnemonic)) == 0)
         {
            if(inst_count == 0)
            {
               for(uint32_t k = 0; k < cur_instr->detail->x86.op_count; k++)
               {
                  // EOUTPUT("operands[%d] = ", k);
                  switch(cur_instr->detail->x86.operands[k].type)
                  {
                     case X86_OP_REG:
                        // EOUTPUT("  OP REG  %d\n", cur_instr->detail->x86.operands[k].reg);
                        break;
                     case X86_OP_IMM:
                        // EOUTPUT("  OP IMM  %#"PRIx64"\n", cur_instr->detail->x86.operands[k].imm);
                        ctxt->do_error_trap = cur_instr->detail->x86.operands[k].imm;

                        found = true;
                        break;
                     case X86_OP_MEM:
                        // EOUTPUT("  OP MEM SEGMENT: %#"PRIx64" BASE %#"PRIx64" INDEX %#"PRIx64" SCALE %#"PRIx64
                        //    " DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[k].mem.segment,
                        //    cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
                        //    cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);
                        break;
                     case X86_OP_FP:
                        // EOUTPUT("  OP FP \n");
                        break;
                     case X86_OP_INVALID:
                        break;
                     default:
                        break;
                  }
               }
               break;
            }
            else
            {
               inst_count++;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);

      if(found)
         break;
   }

   // EOUTPUT("do_trap = %#"PRIx64"\n", ctxt->do_trap);

   if(!found)
   {
       // EOUTPUT("Could not find do_trap\n");
      goto fail;
   }
   return parse_do_error_trap(ctxt, cs);

fail:
   return found;
}
*/

static bool uint_in_list(uint64List* list, uint64_t val)
{
   for(; list; list=list->next)
   {
      if (val == list->value)
      {
         return true;
      }     
   }
   return false;
}

#define TASK_LIST_MM_OFS            (ctxt->task_mm_offset)
#define TASK_LIST_ACTIVE_MM_OFS         (TASK_LIST_MM_OFS+8)
#define TASK_LIST_PID_OFS           (ctxt->task_pid_offset)
#define TASK_LIST_TGID_OFS          (TASK_LIST_PID_OFS+4)
#define TASK_LIST_STACK_CANARY_OFS     (TASK_LIST_PID_OFS+0x8)
#define TASK_LIST_REAL_PARENT_OFS      (TASK_LIST_PID_OFS+0x10)
#define TASK_LIST_PARENT_OFS        (TASK_LIST_PID_OFS+0x18)
#define TASK_LIST_CHILD_LIST_HEAD_OFS  (TASK_LIST_PID_OFS+0x20)
#define TASK_LIST_SIBLING_LIST_HEAD_OFS (TASK_LIST_PID_OFS+0x30)
#define TASK_LIST_PIDS_OFS          (TASK_LIST_CHILD_LIST_HEAD_OFS+0x48)
#define TASK_LIST_COMM_OFS             (ctxt->task_comm_offset)
#define TASK_LIST_FS_STRUCT_OFS     (ctxt->task_fs_offset)
#define TASK_LIST_FILES_STRUCT_OFS     (TASK_LIST_FS_STRUCT_OFS+8)

#define MM_STRUCT_VM_AREA_OFS       0x0000
#define MM_STRUCT_MMAP_BASE_OFS     0x0020
#define MM_STRUCT_MMAP_LEGACY_BASE_OFS  0x0028
#define MM_STRUCT_TASK_SIZE            0x0030
#define MM_STRUCT_HIGHEST_VM_END_OFS   0x0038

#define VM_AREA_VM_START_OFS        0x0000
#define VM_AREA_VM_END_OFS             0x0008
#define VM_AREA_VM_NEXT_OFS            0x0010
#define VM_AREA_VM_PREV_OFS            0x0018
// vma_set_page_prot
#define VM_AREA_VM_PAGE_PROT_OFS    0x0048
#define VM_AREA_VM_FLAGS_OFS        0x0050
#define VM_AREA_VM_FILE_OFS         0x0090
#define MM_STRUCT_PGD_OFS           0x0040

static void parse_task_child_ptrs(Linux* ctxt, Process* task, CPUState* cpu, uint64List* tail)
{
   // We should keep track of the child that we are considering
   uint64_t current_child = 0;
   
   // We have pointers to the list data for children in 
   // a task struct. Remember that this points, not to the
   // start of the next task struct, but to the child list node
   // in the next task struct.
   uint64_t next_child = task->u.lnx.child_list_next;
    uint64_t previous_child = task->u.lnx.child_list_prev;

    // Try step through the list of child structs
   // This will do nothing in the case of only one child
   // This will also not add the last child.
   for (current_child = next_child;
        current_child && current_child != previous_child;
       qemu_load_u64(ctxt->cpu->cpu_index, current_child, &current_child))
   {
         // Transform the kernel LL pointer to a task pointer by jumping to the
      // top of the task struct
      uint64_t current_task_pointer = current_child - TASK_LIST_SIBLING_LIST_HEAD_OFS;
         
      // If, for some reason, we've added this task before, 
      // then we are in a bad state. We will make sure this isn't the case
      if (uint_in_list(task->u.lnx.children, current_task_pointer))
      {
         // If we are here, we are unlikely to recover
         break;
      }
      uint64List* newEntry = g_new0(uint64List, 1);
      newEntry->next = NULL;
      newEntry->value = current_task_pointer;
      if (task->u.lnx.children == NULL)
      {
         task->u.lnx.children = newEntry;
      }
      else
      {
         tail->next = newEntry;
      }
      tail = newEntry;
   }

    {
      // We have skipped putting the last child in
      // If there is only one child, we have put no children in
      // So, we will add the previous now. This will cover both cases
        uint64_t last_task_ptr = previous_child - TASK_LIST_SIBLING_LIST_HEAD_OFS;
        
      // Its wise to ensure that we aren't double adding this pointer
      if (previous_child && !uint_in_list(task->u.lnx.children, last_task_ptr))
       {
         uint64List* newEntry = g_new0(uint64List, 1);
         newEntry->next = NULL;
         newEntry->value = last_task_ptr;
         if (task->u.lnx.children == NULL)
         {
            task->u.lnx.children = newEntry;
         }
         else
         {
            tail->next = newEntry;
         }
         tail = newEntry;
      }
   }
}

// static void parse_task_sibling_ptrs(Process* task, CPUState* cpu, uint64List* siblings)
// {
//    if(task->u.lnx.sibling_list_next == task->u.lnx.sibling_list_prev)
//       return;
// }

static void parse_vm_area_struct(Linux* ctxt, Process *task, TaskMemoryInfo* mem_info, CPUState* cpu)
{
   uint64_t ptr = mem_info->base_ptr;

   VmAreaInfo* vm_info = NULL;
   VmAreaInfoList** tail = &(mem_info->vm_areas);

   while(true)
   {
      uint64_t next = 0;
      uint64_t prev = 0;

      vm_info = g_new0(VmAreaInfo, 1);

      // if(!strcmp(task->name,"systemd")){//core.27815")){
      //    unsigned long a, b, c, d, e, f, g;

      //    if(!qemu_load_u64(ctxt->cpu->cpu_index, ptr + 0, &a) ||
      //       !qemu_load_u64(ctxt->cpu->cpu_index, ptr + 8, &b) ||
      //       !qemu_load_u64(ctxt->cpu->cpu_index, ptr + 0x10, &c) ||
      //       !qemu_load_u64(ctxt->cpu->cpu_index, ptr + 0x18, &d) ||
      //       !qemu_load_u64(ctxt->cpu->cpu_index, ptr + 0x20, &e) ||
      //       !qemu_load_u64(ctxt->cpu->cpu_index, ptr + 0x28, &f) ||
      //       !qemu_load_u64(ctxt->cpu->cpu_index, ptr + 0x30, &g)){
      //       return;
      //    }
      //    printf("0x00 = %#"PRIx64"\n", a);
      //    printf("0x08 = %#"PRIx64"\n", b);
      //    printf("0x10 = %#"PRIx64"\n", c);
      //    printf("0x18 = %#"PRIx64"\n", d);
      //    printf("0x20 = %#"PRIx64"\n", e);
      //    printf("0x28 = %#"PRIx64"\n", f);
      //    printf("0x30 = %#"PRIx64"\n", g);
      // }

      if(!qemu_load_u64(ctxt->cpu->cpu_index, ptr + VM_AREA_VM_NEXT_OFS, &next) ||
         !qemu_load_u64(ctxt->cpu->cpu_index, ptr + VM_AREA_VM_PREV_OFS, &prev) ||
         !qemu_load_u64(ctxt->cpu->cpu_index, ptr + VM_AREA_VM_START_OFS, &vm_info->vm_start) ||
         !qemu_load_u64(ctxt->cpu->cpu_index, ptr + VM_AREA_VM_END_OFS,&vm_info->vm_end) ||
         !qemu_load_u64(ctxt->cpu->cpu_index, ptr + VM_AREA_VM_PAGE_PROT_OFS, &vm_info->page_prot) ||
         !qemu_load_u64(ctxt->cpu->cpu_index, ptr + VM_AREA_VM_FLAGS_OFS, &vm_info->flags) ||
         !qemu_load_u64(ctxt->cpu->cpu_index, ptr + VM_AREA_VM_FILE_OFS, &vm_info->file_ptr)){
         // Fail to read vm info. Bail.
         g_free(vm_info);
         break;
      }

      if (vm_info->vm_start & 0xFFF)
      {
         // Bad vm_start info. Bail.
         g_free(vm_info);
         break;
      }

      VmAreaInfoList* entry = g_new0(VmAreaInfoList, 1);
      entry->value = vm_info;
      entry->next = NULL;
      *tail = entry;
      tail = &(entry->next);

      if (next == ptr)
         break;
      ptr = next;

      if(0 == ptr)
         break;
   }
}

static bool parse_mm_struct(Linux* ctxt, Process* task, CPUState* cpu)
{
   uint64_t vm_area_head_ptr = 0;
   uint64_t pgd_ptr = 0;

   uint64_t mm_ptr = task->u.lnx.active_mm_ptr;

   TaskMemoryInfo* info = NULL;

   if(!task->u.lnx.active_mm_ptr){
      if(!task->u.lnx.mm_ptr){
         return false;
      }else{
         mm_ptr = task->u.lnx.mm_ptr;
      }
   }

   // EOUTPUT("mm_ptr = %#"PRIx64"\n", mm_ptr);

   if(!qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + MM_STRUCT_VM_AREA_OFS, &vm_area_head_ptr)){
      return false;
   }

   info = g_new0(TaskMemoryInfo, 1);

   task->u.lnx.task_mem = info;

   info->base_ptr = vm_area_head_ptr;

   info->vm_areas = NULL;

   if(!qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + MM_STRUCT_MMAP_BASE_OFS, &info->mmap_base) ||
      !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + MM_STRUCT_MMAP_LEGACY_BASE_OFS, &info->mmap_legacy_base) ||
      !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + MM_STRUCT_TASK_SIZE, &info->task_size) ||
      !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + MM_STRUCT_HIGHEST_VM_END_OFS, &info->highest_vm_end)){
      return false;
   }
   //    printf("mmap_base = %#"PRIx64"\n", info->mmap_base);
   //    printf("mmap_legacy_base = %#"PRIx64"\n", info->mmap_legacy_base);
   //    printf("task_size = %#"PRIx64"\n", info->task_size);
   //    printf("highest_vm_end = %#"PRIx64"\n", info->highest_vm_end);

   // if(!strcmp(task->name,"systemd")){//core.27815")){
   //    unsigned long a, b, c, d, e, f, g;

   //    if(!qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + 0, &a) ||
   //       !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + 8, &b) ||
   //       !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + 0x10, &c) ||
   //       !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + 0x18, &d) ||
   //       !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + 0x20, &e) ||
   //       !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + 0x28, &f) ||
   //       !qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + 0x30, &g)){
   //       return false;
   //    }
   //    printf("0x00 = %#"PRIx64"\n", a);
   //    printf("0x08 = %#"PRIx64"\n", b);
   //    printf("0x10 = %#"PRIx64"\n", c);
   //    printf("0x18 = %#"PRIx64"\n", d);
   //    printf("0x20 = %#"PRIx64"\n", e);
   //    printf("0x28 = %#"PRIx64"\n", f);
   //    printf("0x30 = %#"PRIx64"\n", g);
   // }

   parse_vm_area_struct(ctxt, task, info, cpu);

   if(!qemu_load_u64(ctxt->cpu->cpu_index, mm_ptr + MM_STRUCT_PGD_OFS, &pgd_ptr)){
      return false;
   }

    // Verify that we read valid information
   if(0 == pgd_ptr)
   {
      task->info->cr3 = 0;
      return false;
   }

   // convert to physical addr for actual cr3

   /* From pgd_alloc
.text:FFFFFFFF810668F9 B8 00 00 00 80           mov     eax, 80000000h
.text:FFFFFFFF810668FE 48 01 D8                 add     rax, rbx
.text:FFFFFFFF81066901 72 54                    jb      short loc_FFFFFFFF81066957
.text:FFFFFFFF81066903 48 C7 C7 00 00 00+       mov     rdi, 0FFFFFFFF80000000h
.text:FFFFFFFF8106690A 48 2B 3D BF 04 BD+       sub     rdi, cs:page_offset_base  page_offset_base dq 0FFFF880000000000h
.text:FFFFFFFF81066911
.text:FFFFFFFF81066911                   loc_FFFFFFFF81066911:
.text:FFFFFFFF81066911 48 01 C7                 add     rdi, rax
.text:FFFFFFFF81066914 48 C1 EF 0C              shr     rdi, 0Ch
.text:FFFFFFFF81066918 48 C1 E7 06              shl     rdi, 6
.text:FFFFFFFF8106691C 48 03 3D 9D 04 BD+       add     rdi, cs:vmemmap_base  vmemmap_base    dq 0FFFFEA0000000000h  
.text:FFFFFFFF81066923 48 83 C7 20              add     rdi, 20h
.text:FFFFFFFF81066927 E8 E4 8B 2E 00           call    list_del
*/
   uint64_t page_loc = 0;
   if(pgd_ptr > 0xffffffff7ffffffful)
   {
      page_loc = ctxt->phys_base + (pgd_ptr - 0xFFFFFFFF80000000ul);
   }
   else
   {
      page_loc = (pgd_ptr + 0x80000000ul + (0xFFFFFFFF80000000ul - ctxt->page_offset_base)) & 0x3FFFF000;
   }

   // Calculate the final CR3 and store it off
   task->info->cr3 = page_loc;

   return true;
}

static bool parse_task_struct(Linux* ctxt, CPUState* cpu, uint64_t ptask, Process* new_task)
{
   // uint64_t stack_canary = 0;

   // uint32_t search_len = 0;
   // uint32_t ret = 0;
   char *comm_name = NULL;

   // X86CPU *x86_cpu = X86_CPU(cpu);
   // CPUX86State *env = &x86_cpu->env;

   // EOUTPUT("cr3 = %#"PRIx64"\n", env->cr[3]);

   // uint64_t ptask = 0;

   // EOUTPUT("ctxt->current_task = %#"PRIx64"\n", ctxt->current_task);

   // EOUTPUT("ptask = %#"PRIx64"\n", ptask);

    // EOUTPUT("\n");

   new_task->info->procaddr = ptask;

   // EOUTPUT("base_task_ptr = %#"PRIx64"\n", new_task->procaddr);

   if(!qemu_get_virtual_memory(ctxt->cpu->cpu_index, ptask + TASK_LIST_COMM_OFS, LINUX_COMM_NAME_SIZE, (uint8_t**)&comm_name)){
      return false;
   }

   if(!comm_name){
      return false;
   }

         // printf("fs_struct_ptr\n");
   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_FS_STRUCT_OFS, &new_task->u.lnx.fs_struct_ptr)){
      return false;
   }
   
   // EOUTPUT("fs ptr = %#"PRIx64"\n", new_task->fs_struct_ptr);

         // printf("open_files_ptr\n");
   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_FILES_STRUCT_OFS, &new_task->u.lnx.open_files_ptr)){
      return false;
   }

   // EOUTPUT("files_struct ptr = %#"PRIx64"\n", new_task->open_files_ptr);

         // printf("real_parent_ptr\n");
   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_REAL_PARENT_OFS, &new_task->u.lnx.real_parent_ptr)){
      return false;
   }

   // EOUTPUT("real_parent_ptr = %#"PRIx64"\n", new_task->real_parent_ptr);

         // printf("tgid\n");
   if(!qemu_load_u32(ctxt->cpu->cpu_index, ptask + TASK_LIST_TGID_OFS, &new_task->u.lnx.tgid)){
      return false;
   }

   // EOUTPUT("tgid = %d\n", new_task->tgid);

         // printf("pid\n");
   if(!qemu_load_u32(ctxt->cpu->cpu_index, ptask + TASK_LIST_PID_OFS, &new_task->info->pid)){
      return false;
   }

   // EOUTPUT("pid = %d\n", new_task->pid);

         // printf("canary\n");
   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_STACK_CANARY_OFS, &new_task->u.lnx.stack_canary)){
      return false;
   }

   if (new_task->info->pid == 0)
   {
         // printf("new_task->info->pid == 0\n");
      uint64_t offset = 0;

      // default behavior is to just use a constant offset
      uint64_t pids_offset = TASK_LIST_PIDS_OFS;
      // however, if the offset was detected or specified then use that instead
      if( ctxt->task_pids_offset > 0 ){
         pids_offset = ctxt->task_pids_offset;
      }

      if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + pids_offset, &offset)){
         return false;
      }
      if (offset != 0)
      {
         if(!qemu_load_u64(ctxt->cpu->cpu_index, offset + 0x10, &offset)){
            return false;
         }
         if(!qemu_load_u32(ctxt->cpu->cpu_index, offset + 0x30, &new_task->info->pid)){
            return false;
         }
      }
   }
         // printf("new_task->info->pid != 0\n");

   // EOUTPUT("stack canary = %#"PRIx64"\n", new_task->stack_canary);

   // for(uint32_t i = 0; i < 0x1000; i+=8)
   // {
   //    uint64_t tmp = 0;
   //    uint8_t tmp_comm[16] = {0};
      
   //    EOUTPUT("ORIG OFS = %08X    comm = %s\n", i, tmp_comm);
   // }

   // For 32-bit change sizeof(uint64_t) to sizeof(uint32_t), 
   // this would preferably be done with a dynamically assigned pointer size per system
   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_CHILD_LIST_HEAD_OFS, &new_task->u.lnx.child_list_next)){
      // printf("TASK_LIST_ACTIVE_MM_OFS\n");
      return false;
   }

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_CHILD_LIST_HEAD_OFS + sizeof(uint64_t), &new_task->u.lnx.child_list_prev)){
      // printf("TASK_LIST_ACTIVE_MM_OFS\n");
      return false;

   }

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_SIBLING_LIST_HEAD_OFS, &new_task->u.lnx.sibling_list_next)){
      // printf("TASK_LIST_ACTIVE_MM_OFS\n");
      return false;
   }

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_SIBLING_LIST_HEAD_OFS + sizeof(uint64_t), &new_task->u.lnx.sibling_list_prev)){
      // printf("TASK_LIST_ACTIVE_MM_OFS\n");
      return false;
   }

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_MM_OFS, &new_task->u.lnx.mm_ptr)){
      // printf("TASK_LIST_ACTIVE_MM_OFS\n");
      return false;
   }

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_ACTIVE_MM_OFS, &new_task->u.lnx.active_mm_ptr)){
      // printf("TASK_LIST_ACTIVE_MM_OFS\n");
      return false;
   }

   // EOUTPUT("active_mm_ptr = %#"PRIx64"\n", new_task->active_mm_ptr);

   new_task->name = comm_name;
   new_task->u.lnx.children = NULL;
   new_task->u.lnx.siblings = NULL;

   parse_mm_struct(ctxt, new_task, cpu);

   // EOUTPUT("child_list_prev = %#"PRIx64"\n", new_task->child_list_prev);
   // EOUTPUT("child_list_next = %#"PRIx64"\n", new_task->child_list_next);

   // EOUTPUT("sibling_list_prev = %#"PRIx64"\n", new_task->sibling_list_prev);
   // EOUTPUT("sibling_list_next = %#"PRIx64"\n", new_task->sibling_list_next);


   uint64_t next_task = new_task->info->procaddr + TASK_LIST_CHILD_LIST_HEAD_OFS;
   if(new_task->u.lnx.child_list_next != next_task || new_task->u.lnx.child_list_prev != next_task)
      parse_task_child_ptrs(ctxt, new_task, cpu, new_task->u.lnx.children);

   // if(new_task->u.lnx.sibling_list_next != new_task->u.lnx.sibling_list_prev)
   //    parse_task_sibling_ptrs(new_task, cpu, new_task->u.lnx.siblings);

   // EOUTPUT("child list prev = %#"PRIx64"\nchild list next = %#"PRIx64"\n", child_list_prev, child_list_next);
   // EOUTPUT("\n");

   return true;

}

static void parse_task_and_subs(Linux* ctxt, CPUState* cpu, ProcessList** head, ProcessList** tail, uint64_t task_ptr)
{
   // Variables
   Process* new_task = process_new(PROCESS_TYPES_LNX);

    // Validate the current task pointer and make sure we haven't already added it.
   // If it points to a valid task, then process it and its children and siblings.
   if(parse_task_struct(ctxt, cpu, task_ptr, new_task))
   {
      // If we were able to calculate a CR3, then we'll add this task to the list
      if(new_task->info->cr3 != 0)
      {
         if (likely((*tail) != NULL))
         {
            (*tail)->next = processlist_new();
            *tail = (*tail)->next;
         }
         else
         {
            *head = *tail = processlist_new();
         }
         
         (*tail)->value = new_task;
      }

        // We have found a new branch in the tree, we should process its children  
      for(uint64List* cur = new_task->u.lnx.children; cur; cur = cur->next)
      {
         parse_task_and_subs(ctxt, cpu, head, tail, cur->value);
      }

        // And its siblings
      for(uint64List* cur = new_task->u.lnx.siblings; cur; cur = cur->next)
      {
         parse_task_and_subs(ctxt, cpu, head, tail, cur->value);
      }

      // We didn't save the task and we are done with it
      if(new_task->info->cr3 == 0)
      {
         qapi_free_Process(new_task);
      }
   }
   else
   {
      qapi_free_Process(new_task);
   }
   
}

static uint64_t find_top_parent(Linux* ctxt, CPUState* cpu, uint64_t cur_ptr)
{
   uint64_t new_parent = 0;
   uint64_t last_read = 0;

   new_parent = cur_ptr;

   while(true)
   {
      // EOUTPUT("real_parent_ptr = %#"PRIx64"\n", new_parent);

      last_read = new_parent;
      qemu_load_u64(ctxt->cpu->cpu_index, new_parent + TASK_LIST_REAL_PARENT_OFS, &new_parent);

      if(last_read == new_parent)
         break;
   }
   // EOUTPUT("real_parent_ptr = %#"PRIx64"\n", new_parent);
   return new_parent;
}

static int64_t find_comm_offset(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   x86_reg target_reg = X86_REG_INVALID;
   int inst_count = 0;
   int call_depth = 0;
   int64_t comm_offset = 0;

   cs_insn* instr = NULL;
   
   // for(uint32_t i = 0; i < 50; i++)
   // {
   //    num_instr = disassemble_mem(ctxt, &instr, cur_addr);

   //    for(uint32_t j = 0; j < num_instr; j++)
   //    {
   //       cs_insn* cur_instr = &instr[j];
   //       cs_detail *detail = cur_instr->detail;
   //       printf("cur_instr is %s (%d)\n", cur_instr->mnemonic, cur_instr->id);
   //       for(uint32_t n = 0; n < detail->x86.op_count; n++ )
   //       {
   //          cs_x86_op *op = &(detail->x86.operands[n]);
   //          printf("  op->type = %d: ", op->type);
   //          if( op->type == X86_OP_REG)
   //          {
   //             printf("    OP REG  %d\n", detail->x86.operands[n].reg);
   //          }else
   //          if( op->type == X86_OP_IMM )
   //          {
   //             printf("    OP IMM  %#"PRIx64"\n", detail->x86.operands[n].imm);
   //          }else
   //          if( op->type == X86_OP_MEM )
   //          {
   //             printf("    OP MEM SEGMENT %du\n", detail->x86.operands[n].mem.segment);
   //             printf("    OP MEM SCALE %d\n", detail->x86.operands[n].mem.scale);
   //             printf("    OP MEM BASE %du\n", detail->x86.operands[n].mem.base);
   //             printf("    OP MEM DISP %lX\n", detail->x86.operands[n].mem.disp);
   //          }
   //       }
   //    }

   //    cs_free(instr, num_instr);
   // }

   cur_addr = ctxt->do_trap;

   // look for it directly as an arg to printk in do_trap
   for(uint32_t i = 0; i < 150; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86 *detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         if(target_reg != X86_REG_INVALID)
         {
            // comm is passed as 1st arg when calling printk
            if(cur_instr->id == X86_INS_LEA
               && op1->type == X86_OP_REG
               && op1->reg == X86_REG_RSI
               && op2->type == X86_OP_MEM
               && op2->mem.base == target_reg)
            {
               comm_offset = op2->mem.disp;
            }else if(cur_instr->id == X86_INS_CALL && comm_offset > 0){
               // was rsi set prior to this call?
               cs_free(instr, num_instr);
               return comm_offset;
            }
         }else{
            // find register holding current task
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.segment == X86_REG_GS
               && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
            {
                  target_reg = op1->reg;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }
   
   // direct lookup failed... look for nameidata in sys_umount and subtract difference
   // sys_umount -> user_path_mountpoint_at -> filename_mountpoint
   qemu_load_u64(ctxt->cpu->cpu_index, ctxt->sys_call_table+8*166, &cur_addr);
   target_reg = X86_REG_INVALID;
   comm_offset = 0;

   for(uint32_t i = 0; i < 120; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86 *detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         // find sys_umount
         if(call_depth == 0)
         {
            // find first function accessing the current task
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.segment == X86_REG_GS
               && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
            {
               call_depth++;
            }else
            // we shouldn't hit any calls before accessing current_task
            // so follow the calls if we do find them...
            if(cur_instr->id == X86_INS_CALL
               && op1->type == X86_OP_IMM)
            {
               cur_addr = op1->imm;
               break;
            }
         }else if(call_depth <= 2){
            // follow the second call or jmp for two subsequent functions
            if((cur_instr->id == X86_INS_CALL || cur_instr->id == X86_INS_JMP)
               && op1->type == X86_OP_IMM)
            {
               inst_count++;
               if( inst_count == 2 ){
                  cur_addr = op1->imm;
                  inst_count = 0;
                  call_depth++;
                  break;
               }
            }
         }else if(call_depth == 3){
            // do we know which register is the current task?
            if(target_reg != X86_REG_INVALID)
            {
               if(cur_instr->id == X86_INS_MOV
                  && op1->type == X86_OP_REG
                  && op2->type == X86_OP_MEM
                  && op2->mem.base == target_reg)
               {
                  // actually nameidata so subtract the distance...
                  comm_offset = (op2->mem.disp - LINUX_COMM_NAME_SIZE);
                  cs_free(instr, num_instr);
                  return comm_offset;
               }
            }else{
               // find register holding current task
               if(cur_instr->id == X86_INS_MOV
                  && op1->type == X86_OP_REG
                  && op2->type == X86_OP_MEM
                  && op2->mem.segment == X86_REG_GS
                  && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
               {
                  target_reg = op1->reg;
               }
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return 0;
}
   // qemu_load_u64(ctxt->cpu->cpu_index, ctxt->sys_call_table+8*279, &cur_addr);
   // target_reg = X86_REG_INVALID;
   // comm_offset = 0;
   // stage = 0;

   // for(uint32_t i = 0; i < 120; i++)
   // {
   //    num_instr = disassemble_mem(ctxt, &instr, cur_addr);

   //    for(uint32_t j = 0; j < num_instr; j++)
   //    {
   //       cs_insn* cur_instr = &instr[j];
   //       cs_x86 *detail = &(cur_instr->detail->x86);

   //       // do we know which register is the current task?
   //       if(target_reg != X86_REG_INVALID)
   //       {
   //          // check if the register is being moved
   //          if(cur_instr->id == X86_INS_MOV
   //             && detail->operands[0].type == X86_OP_REG
   //             && detail->operands[1].type == X86_OP_REG
   //             && detail->operands[1].reg == target_reg)
   //          {
   //             // move the register
   //             target_reg = detail->operands[0].reg;
   //          }else
   //          // check if the register is being used
   //          if(stage == 2
   //             && cur_instr->id == X86_INS_MOV
   //             && detail->operands[0].type == X86_OP_REG
   //             && detail->operands[1].type == X86_OP_MEM
   //             && detail->operands[1].mem.base == target_reg)
   //          {
   //             // found a usage, wait for access to euid to validate
   //             comm_offset = (detail->operands[1].mem.disp + 0x10);
   //             comm_reg = detail->operands[0].reg;
   //          }else
   //          // check for use in comparison
   //          if(stage == 2
   //             && cur_instr->id == X86_INS_CMP
   //             && detail->operands[0].type == X86_OP_REG
   //             && detail->operands[0].size == 4
   //             && detail->operands[1].type == X86_OP_MEM
   //             && detail->operands[1].mem.base == comm_reg
   //             && comm_reg != X86_REG_INVALID)
   //          {
   //             // found it...
   //             cs_free(instr, num_instr);
   //             return comm_offset;
   //          }else
   //          // target reg is being passed into call... follow it...
   //          if(cur_instr->id == X86_INS_CALL
   //             && detail->operands[0].type == X86_OP_IMM
   //             && target_reg == X86_REG_RDI)
   //          {
   //             cur_addr = detail->operands[0].imm;
   //             stage++;
   //             break;
   //          }
   //       }else{
   //          // find register holding current task
   //          cs_x86_op *op1 = &(detail->operands[0]);
   //          cs_x86_op *op2 = &(detail->operands[1]);
   //          if(cur_instr->id == X86_INS_MOV
   //             && op1->type == X86_OP_REG
   //             && op2->type == X86_OP_MEM
   //             && op2->mem.segment == X86_REG_GS
   //             && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
   //          {
   //             target_reg = op1->reg;
   //          }else
   //          // we shouldn't hit any calls before accessing current_task
   //          // so follow the calls if we do find them...
   //          if(cur_instr->id == X86_INS_CALL
   //             && op1->type == X86_OP_IMM)
   //          {
   //             cur_addr = op1->imm;
   //             break;
   //          }
   //       }

   //       cur_addr += cur_instr->size;
   //    }

   //    cs_free(instr, num_instr);
   // }

static int64_t find_pid_offset(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   x86_reg target_reg = X86_REG_INVALID;
   cs_insn* instr = NULL;
   cur_addr = ctxt->do_trap;
   int64_t pid_offset = 0;

   for(uint32_t i = 0; i < 150; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86 *detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         if(target_reg != X86_REG_INVALID)
         {
            // find offset of pid into task_struct
            if(cur_instr->id == X86_INS_MOV)
            {
               // pid is 32 bit and passed as 3rd arg when calling printk
               if(op1->type == X86_OP_REG
                  && op1->size == X86_REG_EDX
                  && op2->type == X86_OP_MEM
                  && op2->mem.base == target_reg)
               {
                  pid_offset = op2->mem.disp;
               }
            }else if(cur_instr->id == X86_INS_CALL && pid_offset > 0){
               // was edx set prior to this call?
               cs_free(instr, num_instr);
               return pid_offset;
            }
         }else{
            // find register holding current task
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.segment == X86_REG_GS
               && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
            {
                  target_reg = op1->reg;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   // printk lookup failed... look in sys_exit -> do_exit
   qemu_load_u64(ctxt->cpu->cpu_index, ctxt->sys_call_table+8*60, &cur_addr);
   target_reg = X86_REG_INVALID;

   for(uint32_t i = 0; i < 120; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86 *detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         // do we know which register is the current task?
         if(target_reg != X86_REG_INVALID)
         {
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op1->size == 4
               && op2->type == X86_OP_MEM
               && op2->mem.base == target_reg)
            {
               pid_offset = op2->mem.disp;
               cs_free(instr, num_instr);
               return pid_offset;
            }
         }else{
            // find register holding current task
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.segment == X86_REG_GS
               && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
            {
               target_reg = op1->reg;
            }else
            // we shouldn't hit any calls before accessing current_task
            // so follow the calls if we do find them...
            if(cur_instr->id == X86_INS_CALL
               && op1->type == X86_OP_IMM)
            {
               cur_addr = op1->imm;
               break;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return 0;
}

static int64_t find_mm_offset(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   x86_reg target_reg = X86_REG_INVALID;
   cs_insn* instr = NULL;
   cur_addr = ctxt->__do_page_fault;

   for(uint32_t i = 0; i < 150; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86 *detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         if(target_reg != X86_REG_INVALID)
         {
            // find offset of mm into task_struct
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.base == target_reg)
            {
               cs_free(instr, num_instr);
               return op2->mem.disp;
            }
         }else{
            // find register holding current task
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.segment == X86_REG_GS
               && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
            {
               target_reg = op1->reg;
            }else
            // we shouldn't hit any calls before accessing current_task
            // so follow the calls if we do find them...
            if(cur_instr->id == X86_INS_CALL
               && op1->type == X86_OP_IMM)
            {
               cur_addr = op1->imm;
               break;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return 0;
}

static int64_t find_fs_offset(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   x86_reg target_reg = X86_REG_INVALID;
   cs_insn* instr = NULL;

   // load address for sys_umount
   qemu_load_u64(ctxt->cpu->cpu_index, ctxt->sys_call_table+8*166, &cur_addr);

   // perform an indirect lookup in sys_umount
   for(uint32_t i = 0; i < 150; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];
         cs_x86 *detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         if(target_reg != X86_REG_INVALID)
         {
            // find offset of fs into task_struct
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.base == target_reg)
            {
               cs_free(instr, num_instr);
               // actually nsproxy so subtract the distance...
               return (op2->mem.disp - 0x10);
            }
         }else{
            // find register holding current task
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.segment == X86_REG_GS
               && (ctxt->kern_gs_base + op2->mem.disp) == ctxt->current_task)
            {
               target_reg = op1->reg;
            }else
            // we shouldn't hit any calls before accessing current_task
            // so follow the calls if we do find them...
            if(cur_instr->id == X86_INS_CALL
               && op1->type == X86_OP_IMM)
            {
               cur_addr = op1->imm;
               break;
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return 0;
}


static int64_t find_pids_offset(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;
   int instr_count = 0;
   x86_reg target_reg = X86_REG_INVALID;
   cs_insn* instr = NULL;
   int set_pid_type = -1;
   bool in_change_pid = false;
   x86_reg passed_reg = X86_REG_INVALID;
   int64_t pids_offset = 0;

   // load address for sys_setpgid
   qemu_load_u64(ctxt->cpu->cpu_index, ctxt->sys_call_table+8*109, &cur_addr);

   // perform a direct lookup in sys_setpgid
   for(uint32_t i = 0; i < 150; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         // {
         //    cs_insn* cur_instr = &instr[j];
         //    cs_detail *detail = cur_instr->detail;
         //    printf("cur_instr is %s (%d)\n", cur_instr->mnemonic, cur_instr->id);
         //    for(uint32_t n = 0; n < detail->x86.op_count; n++ )
         //    {
         //       cs_x86_op *op = &(detail->x86.operands[n]);
         //       printf("  op->type (size) = %d (%d): ", op->type, op->size);
         //       if( op->type == X86_OP_REG)
         //       {
         //          printf("    OP REG  %d\n", detail->x86.operands[n].reg);
         //       }else
         //       if( op->type == X86_OP_IMM )
         //       {
         //          printf("    OP IMM  %#"PRIx64"\n", detail->x86.operands[n].imm);
         //       }else
         //       if( op->type == X86_OP_MEM )
         //       {
         //          printf("    OP MEM BASE %du\n", detail->x86.operands[n].mem.base);
         //          printf("    OP MEM DISP %ld\n", detail->x86.operands[n].mem.disp);
         //       }
         //    }
         //    printf("\n");
         // }

         cs_insn* cur_instr = &instr[j];
         cs_x86 *detail = &(cur_instr->detail->x86);
         cs_x86_op *op1 = NULL;
         cs_x86_op *op2 = NULL;
         switch(detail->op_count)
         {
            case 2:
               op2 = &(detail->operands[1]);
            case 1:
               op1 = &(detail->operands[0]);
               break;
         }

         // follow edi (pid) into p = find_task_by_vpid(pid);
         // follow p into change_pid(p, PIDTYPE_PGID, pgrp); where PIDTYPE_PGID is 1
         if(in_change_pid)
         {
            // check if the register is being moved
            if(cur_instr->id == X86_INS_MOV
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_REG
               && op2->reg == target_reg)
            {
               // move the register
               target_reg = op1->reg;
            }else
            // this works for both "pids" and "pids_links"
            // note: skip lea for head node access with check for greater than zero
            if(cur_instr->id == X86_INS_LEA
               && op1->type == X86_OP_REG
               && op2->type == X86_OP_MEM
               && op2->mem.base == target_reg
               && op2->mem.disp > 0)
            {
               // if there was no thread_pid access then this is "pids"
               pids_offset = op2->mem.disp;
               cs_free(instr, num_instr);
               return pids_offset;
            }
         }else{
            // looking for change_pid in sys_setpgid
            if(target_reg != X86_REG_INVALID)
            {
               // check if the pid type is being set
               if(cur_instr->id == X86_INS_MOV
                  && op1->type == X86_OP_REG
                  && op1->reg == X86_REG_ESI
                  && op2->type == X86_OP_IMM
                  && set_pid_type < 0)
               {
                  // found a usage, wait for call to validate
                  set_pid_type = op2->imm;
               }else
               // check if the register is being used in call
               if(cur_instr->id == X86_INS_MOV
                  && op1->type == X86_OP_REG
                  && op1->reg == X86_REG_RDI
                  && op2->type == X86_OP_REG
                  && op2->reg == target_reg)
               {
                  // found an arg pass, wait for call to validate
                  passed_reg = op1->reg;
               }else
               // we might need to follow this call
               if(cur_instr->id == X86_INS_CALL
                  && op1->type == X86_OP_IMM)
               {
                  // validate both arguments are set for change_pid
                  if(set_pid_type >= 0
                     && passed_reg != X86_REG_INVALID)
                  {
                     cur_addr = op1->imm;
                     target_reg = passed_reg;
                     in_change_pid = true;
                     break;
                  }

                  set_pid_type = -1;
                  passed_reg = X86_REG_INVALID;
               }
            }else{
               // first, get to find_task_by_vpid
               if(cur_instr->id == X86_INS_CALL
                  && op1->type == X86_OP_IMM
                  && instr_count < 2)
               {
                  instr_count++;
                  if(instr_count == 2){
                     // follow return value
                     passed_reg = X86_REG_RAX;
                  }
               }else
               // follow return register mov
               if(cur_instr->id == X86_INS_MOV
                  && op1->type == X86_OP_REG
                  && op2->type == X86_OP_REG
                  && op2->reg == passed_reg)
               {
                  // move the register and transition
                  // to look for change_pid
                  target_reg = op1->reg;
                  passed_reg = X86_REG_INVALID;
               }
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return 0;
}

static ProcessList* linux_get_process_list(OSHandler* ctxt)
{
   Linux* os = LINUX(ctxt);
   // Variables
   uint64_t cur_task = 0;
   ProcessList* proc_list = NULL;
   ProcessList* tail = NULL;

   // Read the location of the current task pointer from guest memory
   qemu_load_u64(os->cpu->cpu_index, os->current_task, &cur_task);
  
   // Traverse the task list to the first task (root node)
   cur_task = find_top_parent(os, os->cpu, cur_task);

   // Work from the first task down
   parse_task_and_subs(os, os->cpu, &proc_list, &tail, cur_task);

   return proc_list;
}

static bool scan_for_linux(Linux* ctxt)
{
   int64_t reg_val = 0;
   bool ret = true;
   ctxt->do_divide_error = 0;
   ctxt->do_error_trap = 0;
   ctxt->do_trap = 0;
   ctxt->current_task = 0;
   ctxt->kern_gs_base = 0;
   
   ret &= parse_do_syscall(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse do syscall\n");
      return false;
   }

   ret &= parse_div0_idte(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse div0 idte\n");
      return false;
   }

   ret &= parse_do_divide_error(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse do divide error\n");
      return false;
   }

   ret &= parse_do_error_trap(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse do error trap\n");
      return false;
   }

   ret &= parse_do_trap(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse do trap\n");
      return false;
   }

   ret &= parse_divE_idte(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse divE idte\n");
      return false;
   }

   ret &= parse_do_page_fault(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse do_page_fault\n");
      return false;
   }

   ret &= parse_inner_do_page_fault(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse inner_do_page_fault\n");
      return false;
   }

   ret &= parse_vmalloc_fault(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse vmalloc_fault\n");
      return false;
   }

   ret &= parse_sys_mprotect(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse sys_mprotect\n");
      return false;
   }

   if (ret)
   {
      reg_val = find_comm_offset(ctxt);
      if(reg_val <= 0){
         fprintf(stderr, "Failed to parse comm_offset\n");
         return false;
      }
      ctxt->task_comm_offset = reg_val;
      //EOUTPUT("comm_offset = %lX\n", ctxt->task_comm_offset);
   
      reg_val = find_pid_offset(ctxt);
      if(reg_val <= 0){
         fprintf(stderr, "Failed to parse pid_offset\n");
         return false;
      }
      ctxt->task_pid_offset = reg_val;
      //EOUTPUT("pid_offset = %lX\n", ctxt->task_pid_offset);

      reg_val = find_mm_offset(ctxt);
      if(reg_val <= 0){
         fprintf(stderr, "Failed to parse mm_offset\n");
         return false;
      }
      ctxt->task_mm_offset = reg_val;
      //EOUTPUT("mm_offset = %lX\n", ctxt->task_mm_offset);

      reg_val = find_fs_offset(ctxt);
      if(reg_val <= 0){
         fprintf(stderr, "Failed to parse fs_offset\n");
         return false;
      }
      ctxt->task_fs_offset = reg_val;
      //EOUTPUT("fs_offset = %lX\n", ctxt->task_fs_offset);

      // pids_offset is optional, when not set a constant offset is used
      reg_val = find_pids_offset(ctxt);
      if(reg_val > 0){
         ctxt->task_pids_offset = reg_val;
      }
      //EOUTPUT("pids_offset = %lX\n", ctxt->task_pids_offset);
   }

   return ret;
}

static bool fix_offsets_for_kaslr(Linux* ctxt)
{
   uint64_t kernel_base;
   X86CPU *x86_cpu = X86_CPU(ctxt->cpu);
   CPUX86State *env = &x86_cpu->env;
   ctxt->kern_gs_base = env->segs[R_GS].base;
   // EOUTPUT("fix_offsets_for_kaslr\n");

   if(ctxt->kern_gs_base == 0 && env->kernelgsbase > 0)
   {
      // EOUTPUT("kernelgsbase = %#"PRIx64"\n", env->kernelgsbase);
      ctxt->kern_gs_base = env->kernelgsbase;
   }


   // EOUTPUT("cr3 = %#"PRIx64"\n", env->cr[3]);
   if(!parse_div0_idte(ctxt))
   {
      fprintf(stderr, "Failed to parse div0\n");
      return false;
   }
   // Kernel is 2M aligned so mask at that.  
   // Assumes do_divide_error or alternate interrupt handler
   // is in first 2M of kernel but that should be safe.

   kernel_base = ctxt->do_divide_error & 0xFFFFFFFFFFE00000;
   // EOUTPUT("kernel_base = %#"PRIx64"\n", kernel_base);
   ctxt->do_trap = ctxt->do_trap + kernel_base;
   if(!parse_do_trap(ctxt))
   {
      fprintf(stderr, "Failed to parse do trap\n");
      return false;
   }
   if (ctxt->vmalloc_base != 0)
   {
      ctxt->vmalloc_base_ptr = ctxt->vmalloc_base + kernel_base;
      qemu_load_u64(ctxt->cpu->cpu_index, ctxt->vmalloc_base_ptr, &ctxt->vmalloc_base);
   }
   if (ctxt->page_offset_base != 0)
   {
      ctxt->page_offset_base_ptr = ctxt->page_offset_base + kernel_base;
      qemu_load_u64(ctxt->cpu->cpu_index, ctxt->page_offset_base_ptr, &ctxt->page_offset_base);
   }
   else
   {
      ctxt->page_offset_base = 0xffff880000000000;
   }

   return true;
}

static Process* linux_get_process_detail(OSHandler* ctxt, ProcessInfo *pi)
{
    ProcessList *procs = linux_get_process_list(ctxt);
   if(procs){
      for (ProcessList* cur_proc = procs; cur_proc; cur_proc = cur_proc->next)
      {
         Process *task = cur_proc->value;
         if( pi->pid == task->info->pid ){
            // Remove this process from the list.
            Process *p = cur_proc->value;
            cur_proc->value = NULL;
                qapi_free_ProcessList(procs);
            return p;
         }
      }
      qapi_free_ProcessList(procs);
   }

   return NULL;
}

static void linux_get_process_string(OSHandler* ctxt, ProcessInfo *pi, QString **pqstr)
{
   // set the process information for a process listing
   Process *p = linux_get_process_detail(ctxt, pi);
   if( p ) {
      QString *qstr = *pqstr;
      qstring_append(qstr, " \t");
      qstring_append_int(qstr, p->u.lnx.tgid);
      qstring_append(qstr, " \t");
      qstring_append(qstr, p->name);
   }
   qapi_free_Process(p);
}

static OSHandler *linux_scan_for_context(OSHandler* ctxt, OSArch *arch)
{
   // This os handler requires the x86 architecture helper.
   if(!arch || !object_dynamic_cast(OBJECT(arch), TYPE_OSARCHX86)) {
      return NULL;
   }

   OSHandler *os = NULL;
   if(ctxt) {
      // We can reuse this context.
      os = ctxt;
   }else{
      // The provided context is un-usable so make a new one.
      os = OSHANDLER(object_new(TYPE_LINUX));
   }

   if(!object_dynamic_cast(OBJECT(os), TYPE_LINUX)){
      return NULL;
   }

   Linux *l = LINUX(os);

   // Shameless duplication of CPUState
   l->cpu = arch->cpu;
   setup_disassemble(l);

   // If linux is prepped use that info.
   if (l->do_trap != 0 &&
      l->task_mm_offset != 0 &&
      l->task_pid_offset != 0 &&
      l->task_comm_offset != 0 &&
      l->task_fs_offset != 0 &&
      l->task_pids_offset != 0)
   {
      if(fix_offsets_for_kaslr(l)){
         cleanup_disassemble(l);
         return os;
      }
   }

   l->do_divide_error = 0;
   l->do_error_trap = 0;
   l->do_trap = 0;
   l->current_task = 0;
   l->kern_gs_base = 0;

   if (!scan_for_linux(l)){
      object_unref(OBJECT(l));
      cleanup_disassemble(l);
      return NULL;
   }

   cleanup_disassemble(l);
   return os;
}

static bool linux_is_active_by_processinfo(OSHandler* ctxt, CPUState* cpu, ProcessInfo *pi)
{
   uint64_t precr3 = OSARCH_GET_CLASS(ctxt->arch)->get_active_pagetable(ctxt->arch, cpu);
   precr3 &= PDPT_ENTRY_INVMASK;
   precr3 &= KVM_ENTRY_INVMASK;
   return (pi->cr3 & KVM_ENTRY_INVMASK) == precr3;
}

static ProcessInfo *linux_get_processinfo_by_pid(OSHandler* os, uint64_t pid)
{
    ProcessList *procs = linux_get_process_list(os);
   if(procs){
      for (ProcessList* cur_proc = procs; cur_proc; cur_proc = cur_proc->next)
      {
         const Process *task = cur_proc->value;
         if( task->info->pid == pid ){
            ProcessInfo *pi = g_memdup(task->info, sizeof(ProcessInfo));
                qapi_free_ProcessList(procs);
            return pi;
         }
      }
      qapi_free_ProcessList(procs);
   }

   return NULL;
}

static ProcessInfo *linux_get_processinfo_by_active(OSHandler* os, CPUState* cpu)
{
    // Need to mask out bits 31-30 and 12 for linux so we can identify the process.
   uint64_t pagedir = OSARCH_GET_CLASS(os->arch)->get_active_pagetable(os->arch, cpu);
   pagedir &= PDPT_ENTRY_INVMASK;
   pagedir &= KVM_ENTRY_INVMASK;
    ProcessList *procs = linux_get_process_list(os);
   if(procs){
      for (ProcessList* cur_proc = procs; cur_proc; cur_proc = cur_proc->next)
      {
         const Process *task = cur_proc->value;
         if( (task->info->cr3 & KVM_ENTRY_INVMASK) == pagedir ){
            ProcessInfo *pi = g_memdup(task->info, sizeof(ProcessInfo));
                qapi_free_ProcessList(procs);
            return pi;
         }
      }
      qapi_free_ProcessList(procs);
   }

   return NULL;
}

static ProcessInfo *linux_get_processinfo_by_name(OSHandler* os, const char *name)
{
   ProcessList *procs = linux_get_process_list(os);
   if(procs){
      for (ProcessList* cur_proc = procs; cur_proc; cur_proc = cur_proc->next)
      {
         const Process* task = cur_proc->value;
         if( !strncmp(task->name, name, LINUX_COMM_NAME_SIZE) ){
            ProcessInfo *pi = g_memdup(task->info, sizeof(ProcessInfo));
            qapi_free_ProcessList(procs);
            return pi;
         }
      }
     qapi_free_ProcessList(procs);
   }

   return NULL;
}

// Object setup: constructor
static void linux_initfn(Object *obj)
{
   OSHandler *os = OSHANDLER(obj);
   Linux *l = LINUX(os);

   // string to be printed for the process listing header
   qstring_append(os->process_header, "\t\tTGID \tNAME");

   object_property_add_uint64_ptr2(obj, "task_mm_offset", &(l->task_mm_offset), NULL);
   object_property_add_uint64_ptr2(obj, "task_pid_offset", &(l->task_pid_offset), NULL);
   object_property_add_uint64_ptr2(obj, "task_comm_offset", &(l->task_comm_offset), NULL);
   object_property_add_uint64_ptr2(obj, "task_fs_offset", &(l->task_fs_offset), NULL);
   object_property_add_uint64_ptr2(obj, "task_pids_offset", &(l->task_pids_offset), NULL);
   object_property_add_uint64_ptr2(obj, "do_trap", &(l->do_trap), NULL);
   object_property_add_uint64_ptr2(obj, "vmalloc_base", &(l->vmalloc_base), NULL);
   object_property_add_uint64_ptr2(obj, "page_offset_base", &(l->page_offset_base), NULL);
   object_property_add_uint64_ptr2(obj, "do_divide_error", &(l->do_divide_error), NULL);
}

// Object setup: destructor
static void linux_finalize(Object *obj)
{
}

// Object setup: class constructor 
static void linux_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    OSHandlerClass *os_klass = OSHANDLER_CLASS(klass);

    os_klass->scan = linux_scan_for_context;
    os_klass->get_process_list = linux_get_process_list;
    os_klass->get_process_detail = linux_get_process_detail;
    os_klass->get_process_string = linux_get_process_string;
    os_klass->get_processinfo_by_pid = linux_get_processinfo_by_pid;
    os_klass->get_processinfo_by_name = linux_get_processinfo_by_name;
    os_klass->get_processinfo_by_active = linux_get_processinfo_by_active;
    os_klass->is_active_by_processinfo = linux_is_active_by_processinfo;
}

// Object setup: Object info
static TypeInfo linux_info = {
    .parent = TYPE_OSHANDLER,
    .name = TYPE_LINUX,
    .instance_size = sizeof(Linux),
    .instance_init = linux_initfn,
    .instance_finalize = linux_finalize,
    .class_init = linux_class_init,
    .class_size = sizeof(LinuxClass)
};

// These functions are required to setup the plugins
bool plugin_setup(void *plugin, const char *path)
{
   // No need to use qemu_plugin_register_type since
   // this plugin only extends OS handlers and is not
   // meant for direct instantiation by the plugin system.
   type_register_static(&linux_info);

   return true;
}
