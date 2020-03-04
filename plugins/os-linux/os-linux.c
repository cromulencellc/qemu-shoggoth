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
#define LINUX_OPTS  ("linux-opts")

#define LINUX_COMM_NAME_SIZE (16)

#define PDPT_ENTRY_MASK (3 << 30)
#define PDPT_ENTRY_INVMASK (~PDPT_ENTRY_MASK)
#define KVM_ENTRY_MASK (1 << 12)
#define KVM_ENTRY_INVMASK (~KVM_ENTRY_MASK)

typedef struct Linux
{
    OSHandler obj;

    uint64_t do_divide_error;
    uint64_t do_page_fault;
    uint64_t __do_page_fault;
    uint64_t do_error_trap;
    uint64_t do_trap;
    uint64_t do_syscall_64;

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

    uint64_t mm_struct_pgd_offset;
    
    uint64_t vm_area_file_offset;

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

   bool found = false;

   cs_insn* instr = NULL;

   // EOUTPUT("parse_do_trap\n");

   cur_addr = ctxt->do_trap;
   for(uint32_t i = 0; i < 50; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);
      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

         // EOUTPUT("%lx @ mnemonic %s\n", cur_addr, cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "mov", sizeof(cur_instr->mnemonic)) == 0)
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
                     break;
                  case X86_OP_MEM:
                     // EOUTPUT("  OP MEM SEGMENT: %#"PRIx32" BASE %#"PRIx32" INDEX %#"PRIx32" SCALE %#"PRIx32
                     //    " DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[k].mem.segment,
                     //    cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
                     //    cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);

                     ctxt->current_task = ctxt->kern_gs_base + cur_instr->detail->x86.operands[k].mem.disp;
                     found = true;
                     break;
                  case X86_OP_FP:
                     // EOUTPUT("  OP FP \n");
                     break;
                  case X86_OP_INVALID:
                     break;
               }
            }
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);

      if(found)
         break;
   }

   // EOUTPUT("current task ofs = %#"PRIx64"\n", ctxt->current_task);

   if(!found)
   {
      // EOUTPUT("Could not find current task\n");
      goto fail;
   }

fail:
   return found;
}

static bool parse_div0_idte(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint64_t div0_addr = 0;
   uint64_t idt_addr = 0;

   uint32_t num_instr = 0;
   uint32_t inst_count = 0;

   bool found = false;

   cs_insn* instr = NULL;

   X86CPU *x86_cpu = X86_CPU(ctxt->cpu);
   CPUX86State *env = &x86_cpu->env;

   ctxt->kern_gs_base = env->segs[R_GS].base;
   // EOUTPUT("kernelgsbase = %#"PRIx64"\n", ctxt->kern_gs_base);

   if(ctxt->kern_gs_base == 0 && env->kernelgsbase > 0)
   {
      // EOUTPUT("kernelgsbase = %#"PRIx64"\n", env->kernelgsbase);
      ctxt->kern_gs_base = env->kernelgsbase;
   }

   idt_addr = env->idt.base;
   // EOUTPUT("idt.base = %#"PRIx64"\n", idt_addr);

   // EOUTPUT("cr3 = %#"PRIx64"\n", env->cr[3]);

   div0_addr = parse_idt_entry_base(ctxt->cpu, idt_addr, 0);

   // EOUTPUT("div0_addr = %#"PRIx64"\n", div0_addr);
   cur_addr = div0_addr;
   for(uint32_t i = 0; i < 20; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      // EOUTPUT("num Instr = %x\n", num_instr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

         // EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "call", sizeof(cur_instr->mnemonic)) == 0)
         {
            if(inst_count == 1)
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
                        ctxt->do_divide_error = cur_instr->detail->x86.operands[k].imm;
                        found = true;
                        break;
                     case X86_OP_MEM:
                        // EOUTPUT("  OP MEM SEGMENT: %#"PRIx32" BASE %#"PRIx32" INDEX %#"PRIx32" SCALE %#"PRIx32
                           // " DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[j].mem.segment,
                           // cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
                           // cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);
                        break;
                     case X86_OP_FP:
                        // EOUTPUT("  OP FP \n");
                        break;
                     case X86_OP_INVALID:
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

   if(!found)
   {
      // EOUTPUT("Failed to find do_divide_error\n");
      // return false;
      goto fail;
   }

   // EOUTPUT("do_divide_error = %#"PRIx64"\n", ctxt->do_divide_error);

fail:
   return found;
}

static bool parse_divE_idte(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint64_t divE_addr = 0;
   uint64_t idt_addr = 0;

   uint32_t num_instr = 0;
   uint32_t inst_count = 0;

   bool found = false;

   cs_insn* instr = NULL;

   X86CPU *x86_cpu = X86_CPU(ctxt->cpu);
   CPUX86State *env = &x86_cpu->env;

   ctxt->kern_gs_base = env->segs[R_GS].base;
   // EOUTPUT("kernelgsbase = %#"PRIx64"\n", ctxt->kern_gs_base);

   if(ctxt->kern_gs_base == 0 && env->kernelgsbase > 0)
   {
      // EOUTPUT("kernelgsbase = %#"PRIx64"\n", env->kernelgsbase);
      ctxt->kern_gs_base = env->kernelgsbase;
   }

   idt_addr = env->idt.base;
   // EOUTPUT("idt.base = %#"PRIx64"\n", idt_addr);

   // EOUTPUT("cr3 = %#"PRIx64"\n", env->cr[3]);

   divE_addr = parse_idt_entry_base(ctxt->cpu, idt_addr, 0x0E);

// EOUTPUT("divE_addr = %#"PRIx64"\n", divE_addr);
   cur_addr = divE_addr;
   for(uint32_t i = 0; i < 20; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      // EOUTPUT("num Instr = %x\n", num_instr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

//       EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "call", sizeof(cur_instr->mnemonic)) == 0)
         {
            if(inst_count == 1)
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
                        ctxt->do_page_fault = cur_instr->detail->x86.operands[k].imm;
                        found = true;
                        break;
                     case X86_OP_MEM:
                        // EOUTPUT("  OP MEM SEGMENT: %#"PRIx64" BASE %#"PRIx64" INDEX %#"PRIx64" SCALE %#"PRIx64
                        //    " DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[j].mem.segment,
                        //    cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
                        //    cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);
                        break;
                     case X86_OP_FP:
                        // EOUTPUT("  OP FP \n");
                        break;
                     case X86_OP_INVALID:
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

   if(!found)
   {
      // EOUTPUT("Failed to find do_divide_error\n");
      // return false;
      goto fail;
   }

   // EOUTPUT("do_page_fault = %#"PRIx64"\n", ctxt->do_page_fault);

fail:
   return found;
}

static bool parse_do_page_fault(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   // uint64_t divE_addr = 0;
// uint64_t idt_addr = 0;

   uint32_t num_instr = 0;
   uint32_t inst_count = 0;

   bool found = false;

   cs_insn* instr = NULL;

   cur_addr = ctxt->do_page_fault;
   for(uint32_t i = 0; i < 20; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      // EOUTPUT("num Instr = %x\n", num_instr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

//       EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "jmp", sizeof(cur_instr->mnemonic)) == 0)
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
                     ctxt->__do_page_fault = cur_instr->detail->x86.operands[k].imm;
                     found = true;
                     break;
                  case X86_OP_MEM:
                     // EOUTPUT("  OP MEM SEGMENT: %#"PRIx64" BASE %#"PRIx64" INDEX %#"PRIx64" SCALE %#"PRIx64
                     //    " DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[j].mem.segment,
                     //    cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
                     //    cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);
                     break;
                  case X86_OP_FP:
                     // EOUTPUT("  OP FP \n");
                     break;
                  case X86_OP_INVALID:
                     break;
               }
            }
            break;
         }
         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);

      if(found)
         break;
   }

   if(!found)
   {

      goto fail;
   }

// EOUTPUT("__do_page_fault = %#"PRIx64"\n", ctxt->__do_page_fault);

   found = false;
   inst_count = 0;
   cur_addr = ctxt->__do_page_fault;
   for(uint32_t i = 0; i < 200; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      // EOUTPUT("num Instr = %x\n", num_instr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

//       EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "call", sizeof(cur_instr->mnemonic)) == 0)
         {
            if(inst_count == 10)
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
//                      EOUTPUT("  OP IMM  %#"PRIx64"\n", cur_instr->detail->x86.operands[k].imm);
                        ctxt->vmalloc_fault = cur_instr->detail->x86.operands[k].imm;
                        found = true;
                        break;
                     case X86_OP_MEM:
                        // EOUTPUT("  OP MEM SEGMENT: %#"PRIx64" BASE %#"PRIx64" INDEX %#"PRIx64" SCALE %#"PRIx64
                        //    " DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[j].mem.segment,
                        //    cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
                        //    cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);
                        break;
                     case X86_OP_FP:
                        // EOUTPUT("  OP FP \n");
                        break;
                     case X86_OP_INVALID:
                        break;
                  }
               }
               // break;
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

   if(!found)
   {
      // EOUTPUT("Failed to find do_divide_error\n");
      // return false;
      // We may be in KVM which means we found trace_do_page_fault instead of __do_page_fault
      // However we can parse trace_do_page_fault exactly the same as do_page_fault so adjust and retry.
      ctxt->do_page_fault = ctxt->__do_page_fault;
      found = parse_do_page_fault(ctxt);
      if (!found)
      {
         goto fail;
      }
   }

// EOUTPUT("vmalloc_fault = %#"PRIx64"\n", ctxt->vmalloc_fault);

fail:
   return found;
}

// Assumes for ubuntu style kernels
static bool parse_do_page_fault2(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   // uint64_t divE_addr = 0;
// uint64_t idt_addr = 0;

   uint32_t num_instr = 0;
   uint32_t inst_count = 0;

   bool found = false;

   cs_insn* instr = NULL;

   // If it wasn't a jmp try again with a call for ubuntu
   cur_addr = ctxt->do_page_fault;
   for(uint32_t i = 0; i < 20; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      // EOUTPUT("num Instr = %x\n", num_instr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

//       EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "call", sizeof(cur_instr->mnemonic)) == 0)
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
                     ctxt->__do_page_fault = cur_instr->detail->x86.operands[k].imm;
                     found = true;
                     break;
                  case X86_OP_MEM:
                     // EOUTPUT("  OP MEM SEGMENT: %#"PRIx64" BASE %#"PRIx64" INDEX %#"PRIx64" SCALE %#"PRIx64
                     //    " DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[j].mem.segment,
                     //    cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
                     //    cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);
                     break;
                  case X86_OP_FP:
                     // EOUTPUT("  OP FP \n");
                     break;
                  case X86_OP_INVALID:
                     break;
               }
            }
            break;
         }
         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);

      if(found)
         break;
   }
   if (!found)
      goto fail;

// EOUTPUT("__do_page_fault = %#"PRIx64"\n", ctxt->__do_page_fault);

   found = false;
   inst_count = 0;
   cur_addr = ctxt->__do_page_fault;
   for(uint32_t i = 0; i < 200; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      // EOUTPUT("num Instr = %x\n", num_instr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

//       EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "call", sizeof(cur_instr->mnemonic)) == 0)
         {
            if(inst_count == 10)
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
//                      EOUTPUT("  OP IMM  %#"PRIx64"\n", cur_instr->detail->x86.operands[k].imm);
                        ctxt->vmalloc_fault = cur_instr->detail->x86.operands[k].imm;
                        found = true;
                        break;
                     case X86_OP_MEM:
                        // EOUTPUT("  OP MEM SEGMENT: %#"PRIx64" BASE %#"PRIx64" INDEX %#"PRIx64" SCALE %#"PRIx64
                        //    " DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[j].mem.segment,
                        //    cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
                        //    cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);
                        break;
                     case X86_OP_FP:
                        // EOUTPUT("  OP FP \n");
                        break;
                     case X86_OP_INVALID:
                        break;
                  }
               }
               // break;
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

   if(!found)
   {
      // EOUTPUT("Failed to find do_divide_error\n");
      // return false;
      // We may be in KVM which means we found trace_do_page_fault instead of __do_page_fault
      // However we can parse trace_do_page_fault exactly the same as do_page_fault so adjust and retry.
      ctxt->do_page_fault = ctxt->__do_page_fault;
      found = parse_do_page_fault2(ctxt);
      if (!found)
      {
         goto fail;
      }
   }

// EOUTPUT("vmalloc_fault = %#"PRIx64"\n", ctxt->vmalloc_fault);

fail:
   return found;
}

static bool parse_vmalloc_fault(Linux* ctxt)
{
   uint64_t cur_addr = 0;

   uint32_t num_instr = 0;

   bool found = false;

   cs_insn* instr = NULL;

   cur_addr = ctxt->vmalloc_fault;
   for(uint32_t i = 0; i < 10; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr && !found; j++)
      {
         cs_insn* cur_instr = &instr[j];

//       EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "mov", sizeof(cur_instr->mnemonic)) == 0)
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
                     // ctxt->vmalloc_base_ptr = cur_instr->detail->x86.operands[k].imm;
                     // ctxt->page_offset_base_ptr = ctxt->vmalloc_base + sizeof(uint64_t);
                     // found = true;
                     // fprintf(stderr, "Found it\n");
                     break;
                  case X86_OP_MEM:
//                   EOUTPUT("  OP MEM SEGMENT: %du BASE %du INDEX %du SCALE %d DISP %#"PRIx64"\n", cur_instr->detail->x86.operands[k].mem.segment,
//                      cur_instr->detail->x86.operands[k].mem.base, cur_instr->detail->x86.operands[k].mem.index,
//                      cur_instr->detail->x86.operands[k].mem.scale, cur_instr->detail->x86.operands[k].mem.disp);

                     ctxt->vmalloc_base_ptr = cur_addr + cur_instr->size + cur_instr->detail->x86.operands[k].mem.disp;
                     ctxt->page_offset_base_ptr = ctxt->vmalloc_base_ptr + sizeof(uint64_t);

//                   EOUTPUT("vmalloc_base_ptr = %#"PRIx64"\npage_offset_base_ptr = %#"PRIx64"\n", ctxt->vmalloc_base_ptr, ctxt->page_offset_base_ptr);

                     found = true;
                     break;
                  case X86_OP_FP:
                     // EOUTPUT("  OP FP \n");
                     break;
                  case X86_OP_INVALID:
                     break;
               }
            }
            if (found)
               break;
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   
      if(found)
         break;
   }

   if(!found)
   {
      // EOUTPUT("Failed to find do_error_trap\n");
      goto fail;
   }

   qemu_load_u64(ctxt->cpu->cpu_index, ctxt->vmalloc_base_ptr, &ctxt->vmalloc_base);
   qemu_load_u64(ctxt->cpu->cpu_index, ctxt->page_offset_base_ptr, &ctxt->page_offset_base);

// EOUTPUT("vmalloc_base = %#"PRIx64"\n", ctxt->vmalloc_base);
// EOUTPUT("page_offset_base = %#"PRIx64"\n", ctxt->page_offset_base);

   // TODO: This is a hack, a horrible hack.  Parse this actual pointer or offset to phys_base later
   ctxt->phys_base_ptr = ctxt->page_offset_base_ptr - 0x25dc0;

// EOUTPUT("phys_base_ptr = %#"PRIx64"\n", ctxt->phys_base_ptr);

   qemu_load_u64(ctxt->cpu->cpu_index, ctxt->phys_base_ptr, &ctxt->phys_base);
// EOUTPUT("phys_base = %#"PRIx64"\n", ctxt->phys_base);

fail:
   return found;
}

static bool parse_do_divide_error(Linux* ctxt)
{
   uint64_t cur_addr = 0;

   uint32_t num_instr = 0;

   bool found = false;

   cs_insn* instr = NULL;

   cur_addr = ctxt->do_divide_error;
   for(uint32_t i = 0; i < 10; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

         // EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "jmp", sizeof(cur_instr->mnemonic)) == 0)
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
               }
            }
            break;
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   
      if(found)
         break;
   }

   if(!found)
   {
      goto fail;
   }

   // EOUTPUT("do_error_trap = %#"PRIx64"\n", ctxt->do_error_trap);

fail:
   return found;
}

static bool parse_do_divide_error2(Linux* ctxt)
{
   uint64_t cur_addr = 0;

   uint32_t num_instr = 0;
   uint32_t call_count = 0;

   bool found = false;

   cs_insn* instr = NULL;

   cur_addr = ctxt->do_divide_error;
   for(uint32_t i = 0; i < 10; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);

      for(uint32_t j = 0; j < num_instr; j++)
      {
         cs_insn* cur_instr = &instr[j];

         // EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "call", sizeof(cur_instr->mnemonic)) == 0)
         {
            if (call_count == 1)
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
                  }
               }
            }
            else
            {
               call_count++;
            }
               
            break;
         }

         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   
      if(found)
         break;
      }
   if (!found)
      goto fail;

   // EOUTPUT("do_error_trap = %#"PRIx64"\n", ctxt->do_error_trap);

fail:
   return found;
}


static bool parse_do_syscall(Linux* ctxt)
{
   uint64_t cur_addr = 0;
   uint32_t num_instr = 0;

   cs_insn* instr = NULL;

   X86CPU *x86_cpu = X86_CPU(ctxt->cpu);
   CPUX86State *env = &x86_cpu->env;

   ctxt->do_syscall_64 = 0;
   cur_addr = env->sysenter_eip;

   for(uint32_t i = 0; i < 150 && ctxt->do_syscall_64 == 0; i++)
   {
      num_instr = disassemble_mem(ctxt, &instr, cur_addr);
      for(uint32_t j = 0; j < num_instr && ctxt->do_syscall_64 == 0; j++)
      {
         cs_insn* cur_instr = &instr[j];

         // EOUTPUT("mnemonic %s\n", cur_instr->mnemonic);
         if(strncmp(cur_instr->mnemonic, "call", sizeof(cur_instr->mnemonic)) == 0)
         {
            for(uint32_t k = 0; k < cur_instr->detail->x86.op_count && ctxt->do_syscall_64 == 0; k++)
            {
               // EOUTPUT("operands[%d] = ", k);
               switch(cur_instr->detail->x86.operands[k].type)
               {
                  case X86_OP_REG:
                     // EOUTPUT("  OP REG  %d\n", cur_instr->detail->x86.operands[k].reg);
                     break;
                  case X86_OP_IMM:
                     // EOUTPUT("  OP IMM  %#"PRIx64"\n", cur_instr->detail->x86.operands[k].imm);
                     ctxt->do_syscall_64 = cur_instr->detail->x86.operands[k].imm;
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
         }
         cur_addr += cur_instr->size;
      }

      cs_free(instr, num_instr);
   }

   return true;
}

static bool parse_do_error_trap(Linux* ctxt)
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
            if(inst_count == 1)
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
                        ctxt->do_trap = cur_instr->detail->x86.operands[k].imm;
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

fail:
   return found;
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
#define MM_STRUCT_PGD_OFS           (ctxt->mm_struct_pgd_offset)
#define MM_STRUCT_MMAP_BASE_OFS     0x0020
#define MM_STRUCT_MMAP_LEGACY_BASE_OFS  0x0028
#define MM_STRUCT_TASK_SIZE            0x0040
#define MM_STRUCT_HIGHEST_VM_END_OFS   0x0048

#define VM_AREA_VM_START_OFS        0x0000
#define VM_AREA_VM_END_OFS             0x0008
#define VM_AREA_VM_NEXT_OFS            0x0010
#define VM_AREA_VM_PREV_OFS            0x0018
#define VM_AREA_VM_PAGE_PROT_OFS    0x0048
#define VM_AREA_VM_FLAGS_OFS        0x0050
#define VM_AREA_VM_FILE_OFS            (ctxt->vm_area_file_offset)

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
            // If we are here, we are unlikely to 
            // recover
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

static void parse_vm_area_struct(Linux* ctxt, TaskMemoryInfo* mem_info, CPUState* cpu)
{
   uint64_t ptr = mem_info->base_ptr;

   VmAreaInfo* vm_info = NULL;
   VmAreaInfoList* tail = NULL;

   while(true)
   {
      uint64_t next = 0;
      uint64_t prev = 0;

      vm_info = g_new0(VmAreaInfo, 1);

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
      if (unlikely(mem_info->vm_areas == NULL))
         mem_info->vm_areas = entry;
      else
         tail->next = entry;
      tail = entry;

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

   // EOUTPUT("mmap_base = %#"PRIx64"\n", info->mmap_base);
   // EOUTPUT("mmap_legacy_base = %#"PRIx64"\n", info->mmap_legacy_base);
   // EOUTPUT("task_size = %#"PRIx64"\n", info->task_size);
   // EOUTPUT("highest_vm_end = %#"PRIx64"\n", info->highest_vm_end);

   parse_vm_area_struct(ctxt, info, cpu);

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
   
   // EOUTPUT("comm_name = %s\n", new_task->comm_name);

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_FS_STRUCT_OFS, &new_task->u.lnx.fs_struct_ptr)){
      return false;
   }
   
   // EOUTPUT("fs ptr = %#"PRIx64"\n", new_task->fs_struct_ptr);

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_FILES_STRUCT_OFS, &new_task->u.lnx.open_files_ptr)){
      return false;
   }

   // EOUTPUT("files_struct ptr = %#"PRIx64"\n", new_task->open_files_ptr);

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_REAL_PARENT_OFS, &new_task->u.lnx.real_parent_ptr)){
      return false;
   }

   // EOUTPUT("real_parent_ptr = %#"PRIx64"\n", new_task->real_parent_ptr);

   if(!qemu_load_u32(ctxt->cpu->cpu_index, ptask + TASK_LIST_TGID_OFS, &new_task->u.lnx.tgid)){
      return false;
   }

   // EOUTPUT("tgid = %d\n", new_task->tgid);

   if(!qemu_load_u32(ctxt->cpu->cpu_index, ptask + TASK_LIST_PID_OFS, &new_task->info->pid)){
      return false;
   }

   // EOUTPUT("pid = %d\n", new_task->pid);

   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_STACK_CANARY_OFS, &new_task->u.lnx.stack_canary)){
      return false;
   }

   if (new_task->info->pid == 0)
   {
      uint64_t offset = 0;
      if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_PIDS_OFS, &offset)){
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

   // EOUTPUT("stack canary = %#"PRIx64"\n", new_task->stack_canary);

   // for(uint32_t i = 0; i < 0x1000; i+=8)
   // {
   //    uint64_t tmp = 0;
   //    uint8_t tmp_comm[16] = {0};
      
   //    EOUTPUT("ORIG OFS = %08X    comm = %s\n", i, tmp_comm);
   // }

   // For 32-bit change sizeof(uint64_t) to sizeof(uint32_t), 
   // this would preferably be done with a dynamically assigned pointer size per system
   if(!qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_CHILD_LIST_HEAD_OFS, &new_task->u.lnx.child_list_next) ||
      !qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_CHILD_LIST_HEAD_OFS + sizeof(uint64_t), &new_task->u.lnx.child_list_prev) ||
      !qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_SIBLING_LIST_HEAD_OFS, &new_task->u.lnx.sibling_list_next) ||
      !qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_SIBLING_LIST_HEAD_OFS + sizeof(uint64_t), &new_task->u.lnx.sibling_list_prev) ||
      !qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_MM_OFS, &new_task->u.lnx.mm_ptr) ||
      !qemu_load_u64(ctxt->cpu->cpu_index, ptask + TASK_LIST_ACTIVE_MM_OFS, &new_task->u.lnx.active_mm_ptr)){
      return false;
   }

   // EOUTPUT("active_mm_ptr = %#"PRIx64"\n", new_task->active_mm_ptr);

   parse_mm_struct(ctxt, new_task, cpu);

   // EOUTPUT("child_list_prev = %#"PRIx64"\n", new_task->child_list_prev);
   // EOUTPUT("child_list_next = %#"PRIx64"\n", new_task->child_list_next);

   // EOUTPUT("sibling_list_prev = %#"PRIx64"\n", new_task->sibling_list_prev);
   // EOUTPUT("sibling_list_next = %#"PRIx64"\n", new_task->sibling_list_next);

   new_task->name = comm_name;
   new_task->u.lnx.children = NULL;
   new_task->u.lnx.siblings = NULL;

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

static bool scan_for_ubuntu(Linux* ctxt)
{
   bool ret = true;
   ctxt->do_divide_error = 0;
    ctxt->do_error_trap = 0;
    ctxt->do_trap = 0;
    ctxt->current_task = 0;
    ctxt->kern_gs_base = 0;

   ret &= parse_div0_idte(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse div0 idte\n");
      return false;
   }

   ret &= parse_divE_idte(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse divE idte\n");
      return false;
   }

   ret &= parse_do_page_fault2(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse do_page_fault\n");
      return false;
   }

   ret &= parse_vmalloc_fault(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse vmalloc_fault\n");
      return false;
   }

   ret &= parse_do_divide_error2(ctxt);
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

   ret &= parse_do_syscall(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse do trap\n");
      return false;
   }

   if (ret)
   {
      ctxt->task_comm_offset = 0x5d8;
      ctxt->task_pid_offset = 0x428;
      ctxt->task_mm_offset = 0x380;
      ctxt->task_fs_offset = 0x610;
      ctxt->mm_struct_pgd_offset = 0x40;
      ctxt->vm_area_file_offset = 0x90;
   }
   // EOUTPUT("after parse do trap\n");

   return ret;
}

static bool scan_for_debian(Linux* ctxt)
{
   bool ret = true;
   ctxt->do_divide_error = 0;
    ctxt->do_error_trap = 0;
    ctxt->do_trap = 0;
    ctxt->current_task = 0;
    ctxt->kern_gs_base = 0;

   
   ret &= parse_div0_idte(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse div0 idte\n");
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

   ret &= parse_vmalloc_fault(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse vmalloc_fault\n");
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

   ret &= parse_do_syscall(ctxt);
   if(!ret)
   {
      fprintf(stderr, "Failed to parse do trap\n");
      return false;
   }

   // EOUTPUT("after parse do trap\n");
   if (ret)
   {
      ctxt->task_comm_offset = 0x648;
      ctxt->task_pid_offset = 0x490;
      ctxt->task_mm_offset = 0x3e0;
      ctxt->task_fs_offset = 0x680;
      ctxt->mm_struct_pgd_offset = 0x40;
      ctxt->vm_area_file_offset = 0x90;
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

   if (ctxt->mm_struct_pgd_offset == 0)
      ctxt->mm_struct_pgd_offset = 0x40;
   if (ctxt->vm_area_file_offset == 0)
      ctxt->vm_area_file_offset = 0x90;

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
   if(ctxt && object_dynamic_cast(OBJECT(ctxt), TYPE_LINUX)) {
      // We can reuse this context.
      os = ctxt;
   }else{
      // The provided context is un-usable so make a new one.
      os = OSHANDLER(object_new(TYPE_LINUX));
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
      l->task_fs_offset != 0)
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

   if (!scan_for_debian(l)){
      if(!scan_for_ubuntu(l)){
         object_unref(OBJECT(l));
         cleanup_disassemble(l);
         return NULL;
      }
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

    qstring_append(os->process_header, "\t\tTGID \tNAME");

    object_property_add_uint64_ptr2(obj, "task_mm_offset", &(l->task_mm_offset), NULL);
    object_property_add_uint64_ptr2(obj, "task_pid_offset", &(l->task_pid_offset), NULL);
    object_property_add_uint64_ptr2(obj, "task_comm_offset", &(l->task_comm_offset), NULL);
    object_property_add_uint64_ptr2(obj, "task_fs_offset", &(l->task_fs_offset), NULL);
    object_property_add_uint64_ptr2(obj, "do_trap", &(l->do_trap), NULL);
    object_property_add_uint64_ptr2(obj, "vmalloc_base", &(l->vmalloc_base), NULL);
    object_property_add_uint64_ptr2(obj, "page_offset_base", &(l->page_offset_base), NULL);
    object_property_add_uint64_ptr2(obj, "do_divide_error", &(l->do_divide_error), NULL);
    object_property_add_uint64_ptr2(obj, "mm_struct_pgd_offset", &(l->mm_struct_pgd_offset), NULL);
    object_property_add_uint64_ptr2(obj, "vm_area_file_offset", &(l->vm_area_file_offset), NULL);
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
