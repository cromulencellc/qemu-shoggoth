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
import random
from pyqemu.plugin import *
from pyqemu.messages import *
from capstone import *

blob_length = 20
sinput = ''
md = None
count = 0

def on_plugin_load(*args):
   global md, sinput, blob_length
   md = Cs(CS_ARCH_X86, CS_MODE_64)
   sinput = ''.join([chr(random.randrange(0, 255)) for _ in range(0, blob_length)])

def on_ra_start(work_item):
   print("Python: RA Started")

def on_ra_stop(work_results):
   global count, sinput, blob_length
   print("Python: RA Stopped")

   message = CommsMessage(work_results.buffer)
   message.show()
   sinput = ''.join([chr(random.randrange(0, 255)) for _ in range(0, blob_length)])
   count += 1

def on_ra_idle():
   global count, sinput
   print("Python: RA Idle")

   message = CommsMessage() / CommsRequestJobAddMsg(
      queue = 1,
      job_id = 100,
      base_hash = "be9f86320f28ec64fa257f6c57a61dc90ded648b",
      entries = [
         CommsRequestJobAddMemorySetup(flags="memory_virtual", size=len(sinput), offset=0x7FFFF7FE0000, value=bytes(sinput, "UTF-8"))
      ]
   )

   # Run 5 times
   if count < 5:
      message.show()
      RapidAnalysis.addJob(1, message)

def get_ra_report_type():
   return JOB_REPORT_IDS["report_processor"] | JOB_REPORT_IDS["report_exception"]

def on_execute_instruction(vaddr, insn):
    global md
    insns = md.disasm(insn, vaddr)
    try:
        i = next(insns)
        print(('0x%x:\t%s\t%s\t' % (i.address, i.mnemonic, i.op_str)), end=' ')
        print()
    except StopIteration:
        print('0x%x: Disassemble failed!' % vaddr)

def on_vm_shutdown():
    print('VM is closing')
