#/*
# * Rapid Analysis QEMU System Emulator
# *
# * Copyright (c) 2020 Cromulence LLC
# *
# * Distribution Statement A
# *
# * Approved for Public Release, Distribution Unlimited
# *
# * Authors:
# *  Joseph Walker
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */

import sys
import binascii
import itertools
from pyqemu.plugin import *
from pyqemu.messages import *

EXCP00_DIVZ  = 0
EXCP01_DB    = 1
EXCP02_NMI   = 2
EXCP03_INT3  = 3
EXCP04_INTO  = 4
EXCP05_BOUND = 5
EXCP06_ILLOP = 6
EXCP07_PREX  = 7
EXCP08_DBLE  = 8
EXCP09_XERR  = 9
EXCP0A_TSS   = 10
EXCP0B_NOSEG = 11
EXCP0C_STACK = 12
EXCP0D_GPF   = 13
EXCP0E_PAGE  = 14
EXCP10_COPR  = 16
EXCP11_ALGN  = 17
EXCP12_MCHK  = 18

sinput = ''
done = False

UPPER_ALPHA   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER_ALPHA   = "abcdefghijklmnopqrstuvwxyz"
NUMERALS      = "0123456789"

# Roughly Metasploit's pattern generator algorithm
def generate_input(slen, *psets):
   patgen = itertools.product(*psets)
   pattern = ''

   while len(pattern) < slen:
      for p in patgen:
         for i, _ in enumerate(p):
            pattern += p[i]
         if len(pattern) > slen:
            break

   return pattern[:slen]

def find_input(pi, pinput):
   pb = ''
   while pi > 0:
      pb = chr(pi & 0xFF) + pb
      pi >>= 8

   print("Looking for ", pb, " in "+pinput)
   return pinput.find(pb)

def on_plugin_load(*args):
   global sinput
   sinput = generate_input(1, UPPER_ALPHA, LOWER_ALPHA, NUMERALS)

def on_ra_start(work_item):
   print("Python: RA Started")

def on_ra_stop(work_results):
   global done, sinput
   print("Python: RA Stopped")

   message = CommsMessage(work_results.buffer)
   message.show()
   try:
      exc = message.entries["CommsResponseJobReportExceptionEntry"]
      if (int(exc["exception_mask"]) & (1<<EXCP0D_GPF)) > 0:
         print("It worked!")
   except KeyError:
      pass
   sinput = generate_input(len(sinput)+1, UPPER_ALPHA, LOWER_ALPHA, NUMERALS)

def on_ra_idle():
   global done, sinput
   print("Python: RA Idle")

   message = CommsMessage() / CommsRequestJobAddMsg(
      queue = 1,
      job_id = 100,
      base_hash = "493c530cae5bf73435fb7fe813361c8e49568d7b",
      entries = [
         CommsRequestJobAddMemorySetup(flags="memory_virtual", size=len(sinput), offset=0x7fffffffe550, value=bytes(sinput, "UTF-8"))
      ]
   )

   if not done:
      message.show()
      RapidAnalysis.addJob(1, message)

def get_ra_report_type():
   return JOB_REPORT_IDS["report_processor"] | JOB_REPORT_IDS["report_exception"]

def on_exception(exception):
   global done, sinput
   if exception == EXCP00_DIVZ:
      # print('Divide by 0!')
      pass
   elif exception == EXCP01_DB:
      # print('Soft Breakpoint!')
      pass
   elif exception == EXCP02_NMI:
      # print('NMI Interrupt!')
      pass
   elif exception == EXCP03_INT3:
      # print('Breakpoint (INT3)!')
      pass
   elif exception == EXCP04_INTO:
      # print('Overflow (INTO)!')
      pass
   elif exception == EXCP05_BOUND:
      # print('Bounds range exceeded (BOUND)!')
      pass
   elif exception == EXCP06_ILLOP:
      # print('Invalid opcode (UD2)!')
      pass
   elif exception == EXCP07_PREX:
      # print('Device not available (WAIT/FWAIT)!')
      pass
   elif exception == EXCP08_DBLE:
      # print('Double fault!')
      pass
   elif exception == EXCP09_XERR:
      # print('Coprocessor segment overrun!')
      pass
   elif exception == EXCP0A_TSS:
      # print('Invalid TSS!')
      pass
   elif exception == EXCP0B_NOSEG:
      # print('Segment not present!')
      pass
   elif exception == EXCP0C_STACK:
      # print('Stack-segment fault!')
      pass
   elif exception == EXCP0D_GPF:
      print('General protection fault!')
      my_rip = int(Register(0,"RIP"))
      print("RIP is ", hex(my_rip))
      offset = find_input(my_rip, sinput)
      if offset >= 0:
         print("Found BAD RIP at position ", offset, "!")
         done = True
   elif exception == EXCP0E_PAGE:
      # print('Page fault!')
      pass
   elif exception == EXCP10_COPR:
      # print('x87 FPU error!')
      pass
   elif exception == EXCP11_ALGN:
      # print('Alignment check!')
      pass
   elif exception == EXCP12_MCHK:
      # print('Machine check!')
      pass

# def on_execute_instruction(vaddr, addr):
#    print("Python: On Instruction")

#def on_memory_write(paddr, pval, pbytes):
#    print("Python: On Memory Write " + hex(paddr) + " value " + hex(pval))
#    print(binascii.hexlify(CPU.getPhysicalMemory(paddr, len(pbytes))))

#def on_memory_read(paddr, vaddr, pval, pbytes):
#    print("Python: On Memory Read " + hex(paddr) + " value " + hex(pval))
#    print(binascii.hexlify(CPU.getPhysicalMemory(paddr, len(pbytes))))

#def on_syscall(number, args):
#    print("on_syscall")

#def on_vm_change_state(running, state):
#    print('on_vm_change_state' , running)

#def on_interrupt(mask):
#    print('on_interrupt')

#def on_packet_recv(data):
#    print('on_packet_recv: ', ''.join('{:02x}'.format(x) for x in bytearray(data)))
#    return None

#def on_packet_send(data):
#    print('on_packet_send ', ''.join('{:02x}'.format(x) for x in bytearray(data)))
#    return None

def on_vm_shutdown():
    print('VM is closing')
