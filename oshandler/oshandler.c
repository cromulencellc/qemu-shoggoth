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
#include "qemu-common.h"
#include "oshandler/oshandler.h"
#include "qom/cpu.h"
#include "qom/object_interfaces.h"
#include "qapi/qmp/qpointer.h"
#include "qapi/qapi-commands-oshandler.h"
#include "exec/gdbstub.h"
#include "monitor/monitor.h"
#include "qemu/error-report.h"

OSHandler* os_handler = NULL;

#define OSPID_TO_PROCINFO(pb, p) ((ProcessInfo*)(((void*)p) + ((uintptr_t)pb)))
#define OSPID_TO_OFFSET(p)   (((uintptr_t)p) - sizeof(OSPidPool))
#define POOL_TO_OSPID(pb, p) ((OSPid)((((void*)p) + sizeof(OSPidPool)) - ((uintptr_t)pb)))
#define OSPID_TO_POOL(pb, p) ((OSPidPool *)((((void*)p) - sizeof(OSPidPool)) + ((uintptr_t)pb)))
#define POOL_OFFSET(p, o)    ((OSPidPool *)(((void*)p) + (o)))

typedef struct OSPidPool{
   uint64_t free_pid;
   uint64_t next_pid;
   uint64_t refcount;
   // some implicit memory here...
} OSPidPool;

static OSPid alloc_pid(OSHandler* ctxt, size_t s) {
   const size_t pid_region_size = s + sizeof(OSPidPool);
   OSPidPool *pool = ctxt->pid_pool;
   OSPidPool *prev_pool = NULL, *next_pool = NULL;

   // Look for a free allocation...
   while( pool->next_pid > 0 ) {
      // Look for a free pool here or at the end of free pointer.
      OSPidPool *free_pool = NULL;
      if( !pool->free_pid ) {
         free_pool = pool;
      }else{
         prev_pool = pool;
         free_pool = POOL_OFFSET(pool, pool->free_pid);
      }

      // Is it free and allocated with enough space?
      if( !free_pool->free_pid &&
         free_pool->next_pid >= pid_region_size ) {
         // It's allocated and we have enough space for this request.
         next_pool = POOL_OFFSET(free_pool, free_pool->next_pid);

         const size_t free_pid_stride = free_pool->next_pid + next_pool->free_pid;

         if( prev_pool ) {
            // Move up the previous free pid pointer.
            prev_pool->free_pid += free_pid_stride;
         }

         free_pool->free_pid = free_pid_stride;
         pool = free_pool;
         break;
      }

      prev_pool = pool;
      pool = POOL_OFFSET(pool, pool->next_pid);
   }

   // pool should point to a free pid, either allocated with enough
   // space or unallocated entirely.
   if( !pool->next_pid  ) {
      // Not allocated. We're at the end so reserve some more.
      if( prev_pool ) {
         // Move up the previous free pid pointer.
         prev_pool->free_pid += pid_region_size;
      }

      OSPidPool *new_pool = realloc(ctxt->pid_pool, ctxt->pool_size + pid_region_size);
      if(!new_pool) {
         error_printf("Unable to allocate more pool memory for pids!");
         abort();
      }
      ctxt->pid_pool = new_pool;

      OSPidPool *next_pool = POOL_OFFSET(new_pool, ctxt->pool_size + s);
      next_pool->free_pid = 0;
      next_pool->next_pid = 0;

      pool = POOL_OFFSET(new_pool, ctxt->pool_size - sizeof(OSPidPool));
      pool->free_pid = pid_region_size;
      pool->next_pid = pid_region_size;
      pool->refcount = 1;

      ctxt->pool_size += pid_region_size;
   }

   return POOL_TO_OSPID(ctxt->pid_pool, pool);
}

static void free_pid(OSHandler* ctxt, OSPid p) {
   // sanity check
   if( p == NULL_PID ){
      return;
   }

   uintptr_t pid_offset = OSPID_TO_OFFSET(p);
   OSPidPool *free_pool = OSPID_TO_POOL(ctxt->pid_pool, p);
   OSPidPool *pool = ctxt->pid_pool;

   free_pool->free_pid = 0;
   
   // Only look for pools below us.
   uintptr_t pool_offset = OSPID_TO_OFFSET(POOL_TO_OSPID(ctxt->pid_pool, pool));
   while(pool_offset < pid_offset) {
      OSPidPool *search_pool = POOL_OFFSET(pool, pool->free_pid);

      // Look for the first free pointer that jumps to a false free.
      if( search_pool->free_pid > 0 ) {
         const uintptr_t jump_to = (pid_offset - pool_offset);
         pool->free_pid = jump_to;
         break;
      }

      pool = POOL_OFFSET(pool, pool->next_pid);
      pool_offset = OSPID_TO_OFFSET(POOL_TO_OSPID(ctxt->pid_pool, pool));
   }
}

static void incref_pid(OSHandler* ctxt, OSPid p)
{
   if( p != NULL_PID ){
      OSPID_TO_POOL(ctxt->pid_pool, p)->refcount++;
   }
}

static void decref_pid(OSHandler* ctxt, OSPid p)
{
   if( p != NULL_PID ){
      OSPidPool *pool = OSPID_TO_POOL(ctxt->pid_pool, p);
      pool->refcount--;
      if( !pool->refcount ) {
         free_pid(ctxt, p);
      }
   }
}

Process *process_new(ProcessTypes pt)
{
   Process* new_task = g_new0(Process, 1);
   new_task->info = g_new0(ProcessInfo, 1);
   new_task->type = pt;
   return new_task;
}

ProcessList *processlist_new(void)
{
   return g_new0(ProcessList, 1);
}

static OSPid oshandler_get_ospid_by_pid(OSHandler* ctxt, uint64_t pid)
{
   ProcessInfo *pi = OSHANDLER_GET_CLASS(ctxt)->get_processinfo_by_pid(ctxt, pid);
   if(!pi){
      return NULL_PID;
   }

   OSPid hpid = alloc_pid(ctxt, sizeof(ProcessInfo));
   memcpy(OSPID_TO_PROCINFO(ctxt->pid_pool, hpid), pi, sizeof(ProcessInfo));
   return hpid;
}

static OSPid oshandler_get_ospid_by_active(OSHandler* ctxt, CPUState *cpu)
{
   ProcessInfo *pi = OSHANDLER_GET_CLASS(ctxt)->get_processinfo_by_active(ctxt, cpu);
   if(!pi){
      return NULL_PID;
   }

   OSPid hpid = alloc_pid(ctxt, sizeof(ProcessInfo));
   memcpy(OSPID_TO_PROCINFO(ctxt->pid_pool, hpid), pi, sizeof(ProcessInfo));
   return hpid;
}

static OSPid oshandler_get_ospid_by_name(OSHandler* ctxt, const char *name)
{
   ProcessInfo *pi = OSHANDLER_GET_CLASS(ctxt)->get_processinfo_by_name(ctxt, name);
   if(!pi){
      return NULL_PID;
   }

   OSPid hpid = alloc_pid(ctxt, sizeof(ProcessInfo));
   memcpy(OSPID_TO_PROCINFO(ctxt->pid_pool, hpid), pi, sizeof(ProcessInfo));
   return hpid;
}

static ProcessInfo* oshandler_get_processinfo_by_ospid(OSHandler* ctxt, OSPid hpid)
{
   if(hpid != NULL_PID){
      return OSPID_TO_PROCINFO(ctxt->pid_pool, hpid);
   }

   return NULL;
}

static void oshandler_release_ospid(OSHandler* ctxt, OSPid hpid)
{
   decref_pid(ctxt, hpid);
}

ProcessList* qmp_os_proclist(Error** error)
{
    Error* local_err = NULL;
    ProcessList* result = NULL;
    if(is_oshandler_active())
    {
        OSHandler *os_handler = oshandler_get_instance();

        result = OSHANDLER_GET_CLASS(os_handler)->get_process_list(os_handler);
        if (!result)
           error_setg(&local_err, "Empty Process list");
    }
    else
    {
        error_setg(&local_err, "OSHandler not active");
    }
    error_propagate(error, local_err);
    return result;
}

Process* qmp_os_procdetail(uint64_t pid, Error** error)
{
    Error* local_err = NULL;
    if(is_oshandler_active())
    {
        OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *cl = OSHANDLER_GET_CLASS(os_handler);

        ProcessInfo *pi = cl->get_processinfo_by_pid(os_handler, pid);
        if( pi ) {
            return cl->get_process_detail(os_handler, pi);
        } else {
            error_setg(&local_err, "Failed to lookup process");			
        }
    }
    else
    {
        error_setg(&local_err, "OSHandler not active");
    }
    error_propagate(error, local_err);
    return NULL;
}

BP_ID* qmp_os_set_breakpoint(uint64_t pid, uint64_t bp_addr, Error** error)
{
   Error* local_err = NULL;
   if (is_oshandler_active())
   {
      OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *cl = OSHANDLER_GET_CLASS(os_handler);
        OSPid hpid = cl->get_ospid_by_pid(os_handler, pid);

      if( hpid != NULL_PID ) {
         OSBreakpoint *osb = cl->set_breakpoint(os_handler, bp_addr, 1, OS_BREAKPOINT_HW, hpid);
         if( osb ) {
            BP_ID* result = g_new0(BP_ID, 1);
            result->id = osb->id;
            return result;
         }else{
            error_setg(&local_err, "Unable to set breakpoint");
         }
      }else{
         error_setg(&local_err, "PID not found");
      }
   }
   else
   {
      error_setg(&local_err, "OShandler not active");
   }
   error_propagate(error, local_err);
   return NULL;
}

void qmp_os_clear_breakpoint(uint64_t bp_id, Error** error)
{
    Error* local_err = NULL;
    if (is_oshandler_active())
    {
        OSHandler *os_handler = oshandler_get_instance();
        OSHandlerClass *cl = OSHANDLER_GET_CLASS(os_handler);
        OSBreakpoint* bp = cl->get_breakpoint(os_handler, bp_id);
        if (!bp){
            error_setg(&local_err, "Invalid BP id");
        }else {
            cl->remove_breakpoint(os_handler, bp);
            return;
        }
    }
    else
    {
        error_setg(&local_err, "OShandler not active");
    }
    error_propagate(error, local_err);
}


void qmp_os_begin(const char *name, Error** error)
{
   Error* local_err = NULL;
    if(!is_oshandler_active())
    {
        OSHandler *os_handler = oshandler_init(qemu_get_cpu(0), name);
      if (!os_handler || !is_oshandler_active())
         error_setg(&local_err, "OShandler not created");

    }
   error_propagate(error, local_err);
}

void qmp_os_find(Error** error)
{
	Error* local_err = NULL;
    if(!is_oshandler_active())
    {
        OSHandler *os_handler = oshandler_init(qemu_get_cpu(0), NULL);
		if (!os_handler || !is_oshandler_active())
			error_setg(&local_err, "OShandler not created");

    }
	error_propagate(error, local_err);
}

static void oshandler_print_process_list(OSHandler* ctxt, ProcessInfo *cur_pi)
{ 
   if( !cur_mon ){
      return;
   }

    OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(ctxt);
    OSArchClass *arch_cc = OSARCH_GET_CLASS(ctxt->arch);
    // Assume active on first cpu
    ProcessInfo *pi = os_cc->get_processinfo_by_active(ctxt, qemu_get_cpu(0));

   monitor_printf(cur_mon, "%s%s\n",
      qstring_get_str(ctxt->arch->process_header),
      qstring_get_str(ctxt->process_header));

      ProcessList *procs = os_cc->get_process_list(ctxt);
   if(procs){
      for (ProcessList* cur_proc = procs; cur_proc; cur_proc = cur_proc->next)
      {
         QString *pistr = qstring_new();
         if(cur_pi && arch_cc->is_same_process(ctxt->arch, cur_proc->value->info, cur_pi)){
            qstring_append(pistr, "*");
         }
         if(pi && arch_cc->is_same_process(ctxt->arch, cur_proc->value->info, pi)){
            qstring_append(pistr, "->");
         }
         // Get base process info by architecture
         if( arch_cc->get_process_string ){
            arch_cc->get_process_string(ctxt->arch, cur_proc->value->info, &pistr);
         }
         // Get extendend process info by OS
         if( os_cc->get_process_string ){
            os_cc->get_process_string(ctxt, cur_proc->value->info, &pistr);
         }
         if(qstring_get_length(pistr) > 0){
            monitor_printf(cur_mon, "%s", qstring_get_str(pistr));
         }
         monitor_printf(cur_mon, "\n");
         qobject_unref(pistr);
      }
      qapi_free_ProcessList(procs);
   }
}

static void oshandler_enable_breakpoint(OSHandler *ctxt, OSBreakpoint *bp)
{
   if( bp->disabled ) {
      bp->disabled = false;
      if( !bp->suppressed ) {
         OSARCH_GET_CLASS(ctxt->arch)->set_breakpoint(
               ctxt->arch,
               bp->addr,
               bp->length,
               bp->flags,
               OSPID_TO_PROCINFO(ctxt->pid_pool, bp->pid)
            );
      }
   }
}

static void oshandler_reset_breakpoint(OSHandler *ctxt, OSBreakpoint *bp)
{
   if( bp->suppressed ) {
      bp->suppressed = false;
      if( !bp->disabled ) {
         OSARCH_GET_CLASS(ctxt->arch)->set_breakpoint(
               ctxt->arch,
               bp->addr,
               bp->length,
               bp->flags,
               OSPID_TO_PROCINFO(ctxt->pid_pool, bp->pid)
            );
      }
   }
}

static void oshandler_disable_breakpoint(OSHandler *ctxt, OSBreakpoint *bp)
{
   if( !bp->disabled ) {
      bp->disabled = true;
      if( !bp->suppressed ) {
         OSARCH_GET_CLASS(ctxt->arch)->remove_breakpoint(
               ctxt->arch,
               bp->addr,
               bp->length,
               bp->flags,
               OSPID_TO_PROCINFO(ctxt->pid_pool, bp->pid)
            );
      }
   }
}

static void oshandler_suppress_breakpoint(OSHandler *ctxt, OSBreakpoint *bp)
{
   if( !bp->suppressed ) {
      bp->suppressed = true;
      if( !bp->disabled ) {
         OSARCH_GET_CLASS(ctxt->arch)->remove_breakpoint(
               ctxt->arch,
               bp->addr,
               bp->length,
               bp->flags,
               OSPID_TO_PROCINFO(ctxt->pid_pool, bp->pid)
            );
      }
   }
}

static bool oshandler_breakpoint_check(OSHandler *ctxt, CPUState* cpu, OSBreakpoint *bp)
{
   return !bp->disabled && OSARCH_GET_CLASS(ctxt->arch)->breakpoint_check(ctxt->arch, cpu, bp);
}

static OSBreakpoint* oshandler_set_breakpoint(OSHandler* ctxt, uint64_t addr, uint64_t length, OSBreakpointType bp_type, OSPid hpid)
{
   OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(ctxt);
    int flags = 0;

    switch(bp_type)
    {
        case OS_BREAKPOINT_SW:
            flags = GDB_BREAKPOINT_SW;
            break;
        case OS_BREAKPOINT_HW:
            flags = GDB_BREAKPOINT_HW;
            break;
        case OS_WATCHPOINT_WRITE:
            flags = GDB_WATCHPOINT_WRITE;
            break;
        case OS_WATCHPOINT_READ:
            flags = GDB_WATCHPOINT_READ;
            break;
        case OS_WATCHPOINT_ACCESS:
            flags = GDB_WATCHPOINT_ACCESS;
            break;
    }
   
   ProcessInfo *pi = NULL;
   if( hpid != NULL_PID ) {
      pi = OSPID_TO_PROCINFO(ctxt->pid_pool, hpid);
      Process *p = os_cc->get_process_detail(ctxt, pi);
      if( !p ){
         return NULL;
      }
      qapi_free_Process(p);
   }

   if( !OSARCH_GET_CLASS(ctxt->arch)->set_breakpoint(
      ctxt->arch,
      addr,
      length,
      flags,
      pi
      ) ) {
      OSBreakpoint* bp = g_new0(OSBreakpoint, 1);

      bp->id = ctxt->num_bp++;
      bp->addr = addr;
      bp->length = length;
      bp->type = bp_type;
      bp->flags = flags;
      bp->pid = hpid;
      bp->disabled = false;
      bp->suppressed = false;

      incref_pid(ctxt, hpid);

      qlist_append(ctxt->breakpoints, qpointer_from_pointer((void*)bp, g_free));

      return bp;
    }

   return NULL;
}

static int oshandler_remove_breakpoint(OSHandler* ctxt, OSBreakpoint *bp)
{
   int r = -1;
    QListEntry *e = NULL;
    QPointer* qptr = NULL;
   OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(ctxt);

    QLIST_FOREACH_ENTRY(ctxt->breakpoints, e){
        QPointer *this_qptr = qobject_to(QPointer, qlist_entry_obj(e));
        OSBreakpoint* this_bp = qpointer_get_pointer(this_qptr);
        if(this_bp->id == bp->id)
        {
            qptr = this_qptr;
            break;
        }
    }

    if(!qptr)
    {
        // End of list did not find the BP
        return false;
    }

    QTAILQ_REMOVE(&ctxt->breakpoints->head, e, next);

   if( bp->pid != NULL_PID ){
      // Does this process still exist?
      ProcessInfo *pi = OSPID_TO_PROCINFO(ctxt->pid_pool, bp->pid);
      Process *p = os_cc->get_process_detail(ctxt, pi);
      if( p ){
         qapi_free_Process(p);

         // gently remove the breakpoint
         r = OSARCH_GET_CLASS(ctxt->arch)->remove_breakpoint(
            ctxt->arch,
            bp->addr,
            bp->length,
            bp->flags,
            pi);
      }else{
         // try to force remove the orphaned breakpoint
         r = OSARCH_GET_CLASS(ctxt->arch)->remove_breakpoint(
            ctxt->arch,
            bp->addr,
            bp->length,
            bp->flags,
            NULL);
      }
      decref_pid(ctxt, bp->pid);
   }else{
      // remove an unassociated breakpoint
      r = OSARCH_GET_CLASS(ctxt->arch)->remove_breakpoint(
         ctxt->arch,
         bp->addr,
         bp->length,
         bp->flags,
         NULL);
   }

    qobject_unref(qptr);
    g_free(e);

   return r;
}

static OSBreakpoint* oshandler_get_breakpoint(OSHandler* ctxt, uint64_t bp_id)
{
    QListEntry *e = NULL;

    QLIST_FOREACH_ENTRY(ctxt->breakpoints, e){
        QPointer *this_qptr = qobject_to(QPointer, qlist_entry_obj(e));
        OSBreakpoint* this_bp = qpointer_get_pointer(this_qptr);
        if(this_bp->id == bp_id)
        {
            return this_bp;
        }
    }

   return NULL;
}

static QList* oshandler_get_breakpoints(OSHandler* ctxt)
{
    return ctxt->breakpoints;
}

static void oshandler_remove_all_breakpoints(OSHandler* ctxt)
{
   QObject *qobj;
   OSARCH_GET_CLASS(ctxt->arch)->remove_all_breakpoints(ctxt->arch);

    while ((qobj = qlist_pop(ctxt->breakpoints))) {
        QPointer *bp_qptr = qobject_to(QPointer, qobj);
        OSBreakpoint* bp = qpointer_get_pointer(bp_qptr);
      decref_pid(ctxt, bp->pid);
      qobject_unref(qobj);
    }
}

static void oshandler_remove_breakpoints(OSHandler* ctxt, OSBreakpointType bp_type)
{
    QListEntry *entry, *next_entry;
   OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(ctxt);

    QTAILQ_FOREACH_SAFE(entry, &ctxt->breakpoints->head, next, next_entry) {
        QPointer *bp_qptr = qobject_to(QPointer, qlist_entry_obj(entry));
        OSBreakpoint* bp = qpointer_get_pointer(bp_qptr);
        if(bp->type == bp_type)
        {
         QTAILQ_REMOVE(&ctxt->breakpoints->head, entry, next);

         if( bp->pid != NULL_PID ) {
            // Does this process still exist?
            ProcessInfo *pi = OSPID_TO_PROCINFO(ctxt->pid_pool, bp->pid);
            Process *p = os_cc->get_process_detail(ctxt, pi);
            if( p ){
               qapi_free_Process(p);

               // gently remove the breakpoint
               OSARCH_GET_CLASS(ctxt->arch)->remove_breakpoint(
                  ctxt->arch,
                  bp->addr,
                  bp->length,
                  bp->flags,
                  pi
               );
            }else{
               // try to force remove the orphaned breakpoint
               OSARCH_GET_CLASS(ctxt->arch)->remove_breakpoint(
                  ctxt->arch,
                  bp->addr,
                  bp->length,
                  bp->flags,
                  NULL);
            }
            decref_pid(ctxt, bp->pid);
         }else{
            // remove an unassociated breakpoint
            OSARCH_GET_CLASS(ctxt->arch)->remove_breakpoint(
               ctxt->arch,
               bp->addr,
               bp->length,
               bp->flags,
               NULL
            );
         }

         qobject_unref(entry->value);
         g_free(entry);
        }
    }
}


static void oshandler_initfn(Object* obj)
{
   OSHandler* ctxt = OSHANDLER(obj);
    ctxt->pid_pool = g_new0(OSPidPool, 1);
    ctxt->pool_size = sizeof(OSPidPool);
    ctxt->breakpoints = qlist_new();
   ctxt->process_header = qstring_new();
    ctxt->singlestep_enabled = 0;
   ctxt->arch = NULL;
}

static void oshandler_finalize(Object* obj)
{
   OSHandler* ctxt = OSHANDLER(obj);
   g_free(ctxt->pid_pool);
   qobject_unref(ctxt->breakpoints);
   qobject_unref(ctxt->process_header);
   if( ctxt->arch ) {
      object_unref(OBJECT(ctxt->arch));
      ctxt->arch = NULL;
   }
}

static bool oshandler_is_active_process(OSHandler* ctxt, CPUState* cpu, ProcessInfo *pi)
{
   OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(ctxt);

   // Can we use processinfo to identify the active process?
   if(os_cc->is_active_by_processinfo) {
      // Yes, so use it.
      return os_cc->is_active_by_processinfo(ctxt, cpu, pi);
   }

   // Nope, so default to directly using process information.
   ProcessInfo *api = os_cc->get_processinfo_by_active(ctxt, cpu);
   if(!api){
      return false;
   }

   return OSARCH_GET_CLASS(ctxt->arch)->is_same_process(ctxt->arch, pi, api);
}

static void *oshandler_generic_do_process_coroutine(OSHandler *ctxt, ProcessInfo *pi, OSHANDLER_PROC_COROUTINE func, void *args)
{
   OSArchClass *arch_cc = OSARCH_GET_CLASS(ctxt->arch);
   void *proc_state = NULL;

   if(!arch_cc->process_enter || !arch_cc->process_exit) {
      return NULL;
   }

   proc_state = arch_cc->process_enter(ctxt->arch, pi);
   if(!proc_state){
      return NULL;
   }

   void *ret = func(pi, args);

   arch_cc->process_exit(ctxt->arch, proc_state);

   return ret;
}


static void oshandler_class_init(ObjectClass *klass, void* class_data)
{
   OSHandlerClass* oshandler_class = OSHANDLER_CLASS(klass);

   oshandler_class->get_process_list = NULL;
   oshandler_class->get_process_detail = NULL;
   oshandler_class->get_process_string = NULL;
   oshandler_class->get_processinfo_by_pid = NULL;
   oshandler_class->get_processinfo_by_active = NULL;
   oshandler_class->get_processinfo_by_name = NULL;
   oshandler_class->is_active_by_processinfo = NULL;

   oshandler_class->breakpoint_check = oshandler_breakpoint_check;
   oshandler_class->enable_breakpoint = oshandler_enable_breakpoint;
   oshandler_class->disable_breakpoint = oshandler_disable_breakpoint;
   oshandler_class->remove_breakpoints = oshandler_remove_breakpoints;
   oshandler_class->suppress_breakpoint = oshandler_suppress_breakpoint;
   oshandler_class->reset_breakpoint = oshandler_reset_breakpoint;
   oshandler_class->print_process_list = oshandler_print_process_list;
   oshandler_class->get_ospid_by_pid = oshandler_get_ospid_by_pid;
   oshandler_class->get_ospid_by_active = oshandler_get_ospid_by_active;
   oshandler_class->get_ospid_by_name = oshandler_get_ospid_by_name;
   oshandler_class->get_breakpoints = oshandler_get_breakpoints;
   oshandler_class->get_breakpoint = oshandler_get_breakpoint;
   oshandler_class->set_breakpoint = oshandler_set_breakpoint;
   oshandler_class->remove_breakpoint = oshandler_remove_breakpoint;
   oshandler_class->remove_all_breakpoints = oshandler_remove_all_breakpoints;
   oshandler_class->release_ospid = oshandler_release_ospid;
   oshandler_class->get_processinfo_by_ospid = oshandler_get_processinfo_by_ospid;
   oshandler_class->is_active_process = oshandler_is_active_process;
   oshandler_class->do_process_coroutine = oshandler_generic_do_process_coroutine;
}

static void property_get_uint64_ptr(Object *obj, Visitor *v, const char *name,
                                    void *opaque, Error **errp)
{
    uint64_t value = *(uint64_t *)opaque;
    visit_type_uint64(v, name, &value, errp);
}

static void property_set_uint64_ptr(Object *obj, Visitor *v, const char *name,
                                    void *opaque, Error **errp)
{
    uint64_t value;
    visit_type_uint64(v, name, &value, errp);
   *(uint64_t *)opaque = value;
}

void object_property_add_uint64_ptr2(Object *obj, const char *name,
                                    uint64_t *v, Error **errp)
{
   object_property_add(obj, name, "uint64", property_get_uint64_ptr,
                        property_set_uint64_ptr, NULL, (void *)v, errp);
}

OSHandler *oshandler_init(CPUState *cpu, const char *hint)
{
   if(!os_handler)
   {
      OSArch *cpu_arch = osarch_init(cpu);

      if(hint){
         os_handler = OSHANDLER(object_new(hint));
      }else{
         Object *os_obj = object_resolve_path_component(object_get_objects_root(), "os_handler");
         if (os_obj && object_dynamic_cast(os_obj, TYPE_OSHANDLER))
         {
            os_handler = OSHANDLER(os_obj);
         }
      }

      if(os_handler)
      {
         os_handler = OSHANDLER_GET_CLASS(os_handler)->scan(os_handler, cpu_arch);
      }else{
         GSList *list = object_class_get_list(TYPE_OSHANDLER, false);
         while (!os_handler && list) {
            OSHandlerClass *hc = OBJECT_CLASS_CHECK(OSHandlerClass, list->data,
                                    TYPE_OSHANDLER);
            if(hc->scan){
               os_handler = hc->scan(NULL, cpu_arch);
            }
            GSList *next = list->next;
            g_slist_free_1(list);
            list = next;
         }

         if(list) {
            g_slist_free(list);
         }
      }

      if(os_handler){
         os_handler->arch = cpu_arch;
      }
   }

   return os_handler;
}

bool is_oshandler_active(void)
{
   return !!os_handler;
}

OSHandler *oshandler_get_instance(void)
{
   return os_handler;
}

static const TypeInfo oshandler_info = {
   .parent = TYPE_OBJECT,
   .name = TYPE_OSHANDLER,
    .abstract = true,
   .instance_size = sizeof(OSHandler),
   .instance_init = oshandler_initfn,
   .instance_finalize = oshandler_finalize,
   .class_size = sizeof(OSHandlerClass),
   .class_init = oshandler_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void oshandler_register_types(void)
{
   type_register_static(&oshandler_info);
}

type_init(oshandler_register_types);
