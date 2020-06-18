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
 *  Joseph Walker
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 * 
 * The creation of this code was funded by the US Government.
 */

#include <Python.h>
#include <stdio.h>
#include <dlfcn.h>

// This is the interface to QEMU
#include "qemu/qemu-plugin.h"
#include "plugin/plugin-object.h"
#include "plugin/plugin-command.h"
#include "plugin/qemu-registers.h"
#include "plugin/qemu-memory.h"
#include "plugin/qemu-processes.h"
#include "plugin/qemu-vm.h"
#include "qom/cpu.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qmp-event.h"
#include "qapi/qapi-commands-oshandler.h"
#include "python-qapi-commands.h"
#include "sysemu/sysemu.h"
#include "sysemu/hw_accel.h"
#include "monitor/monitor.h"
#include "migration/snapshot.h"
#include "qemu/timer.h"

// These macros define object operations
#define TYPE_PYTHON "python-interface"
#define PYTHON(obj)                                    \
    OBJECT_CHECK(PythonInterface, (obj), TYPE_PYTHON)
#define PYTHON_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(PythonInterfaceClass, klass, TYPE_PYTHON)
#define PYTHON_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(PythonInterfaceClass, obj, TYPE_PYTHON)

// This is the extended type for directly loading python plugins
#define TYPE_PYTHON_PLUGIN "python-plugin"
#define PYTHON_PLUGIN(obj)                                    \
    OBJECT_CHECK(PythonInterface, (obj), TYPE_PYTHON_PLUGIN)
#define PYTHON_PLUGIN_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(PythonInterfaceClass, klass, TYPE_PYTHON_PLUGIN)
#define PYTHON_PLUGIN_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(PythonInterfaceClass, obj, TYPE_PYTHON_PLUGIN)

#define PYTHON_OPTS  ("python-plugin-opts")
#define SCRIPT_PATH_MAX (PATH_MAX+9)
#define PYQEMU_FOLDER ("python")

// We need to keep track of some instance information 
// and modules that can only happen once. 
static PyObject *script_loader = NULL;
static PyObject *bytecode_loader = NULL;
static PyObject *stop_vm_error = NULL;
static PyObject *continue_vm_error = NULL;

static QmpCommandList* qmp_commands = NULL;

// Object type data
typedef struct PythonCallbacks PythonCallbacks;
typedef struct PythonInterface PythonInterface;
typedef struct PythonInterfaceClass PythonInterfaceClass;

struct PythonCallbacks
{
    PyObject *ra_start;
    PyObject *ra_stop;
    PyObject *ra_idle;
    PyObject *get_ra_report_type;
    PyObject *breakpoint;
    PyObject *exception;
    PyObject *execute_instruction;
    PyObject *memory_read;
    PyObject *memory_write;
    PyObject *on_syscall;
    PyObject *on_syscall_exit;
    PyObject *vm_change_state_handler;
    PyObject *on_interrupt;
    PyObject *on_packet_recv;
    PyObject *on_packet_send;
    PyObject *on_vm_startup;
    PyObject *on_vm_shutdown;
    PyObject *on_command;
};

struct PythonInterface 
{
    PluginObject obj;
    char script_path[SCRIPT_PATH_MAX];
    char instance_name[16];
    PyObject *script_module;
    PythonCallbacks py_callbacks;
};

struct PythonInterfaceClass
{
    PluginObjectClass parent;
};

typedef struct PythonPluginObject PythonPluginObject;
typedef struct PythonPluginObjectClass PythonPluginObjectClass;

struct PythonPluginObject
{
    PythonInterface pobj;
};

struct PythonPluginObjectClass
{
    PythonInterfaceClass parent;
};

static QList *PyQList_AsQList(PyObject *qobj);
static QDict *PyQDict_AsQDict(PyObject *qobj);

static void python_call_check(void)
{
    PyObject *err = PyErr_Occurred();
    if (err)
    {
        PyErr_Print();
        abort();    
    }
}

static void python_error_check(PyObject *check)
{
    if (!check)
    { 
        PyErr_Print();
        abort();
    }
}

static void python_put_check(int flag)
{
    if (flag != 0)
    {
        PyErr_Print();
        abort();        
    }
}

static JOB_REPORT_TYPE python_get_ra_report_type(void *opaque)
{
    // variables
    long data;
    PyObject *report_mask;
    PythonInterface *p = PYTHON(opaque);
        
    // call the python callback 
    report_mask = PyObject_CallObject(p->py_callbacks.get_ra_report_type, NULL);
    python_error_check(report_mask);

    // convert the value from python to c
    data = PyLong_AsLong(report_mask);
    Py_DECREF(report_mask);

    // return
    return (uint8_t) data;
}

static void python_on_ra_start(void *opaque, CommsWorkItem *work)
{
    // Variables
    WorkEntryItem *wi;
    PyObject *work_item_class, *comms_message, *buffer, *item_list, *callback_args;
    PythonInterface *p = PYTHON(opaque);    
    
    // Get a work item object
    work_item_class = PyObject_GetAttrString(p->script_module, "WorkItem");
    python_error_check(work_item_class);

    comms_message = PyObject_CallObject(work_item_class, NULL);
    python_error_check(comms_message);
    
    // Get a byte string array
    buffer = PyByteArray_FromStringAndSize((const char *)work->msg, work->msg->size);
    python_error_check(buffer);

    // Add the byte string to the work item
    python_put_check(PyObject_SetAttrString(comms_message, "buffer", buffer));

    // Create an empty list for the pointers into the byte string
    item_list = PyList_New(0);
    python_error_check(item_list);

    // For each work item, add a pointer and type id
    QLIST_FOREACH(wi, &work->entry_list, next)
    {
        PyObject *entry;

        // Fill the tuple with the offset and type id then put it in the list
        entry = Py_BuildValue("Ii", wi->offset, wi->entry_type);
        python_put_check(PyList_Append(item_list, entry));
        Py_DECREF(entry);
    }

    // Add the list to the work item
    python_put_check(PyObject_SetAttrString(comms_message, "item_list", item_list));

    // Build an args tuple 
    callback_args = PyTuple_New(1);
    python_error_check(callback_args);
    python_put_check(PyTuple_SetItem(callback_args, 0, comms_message));
    
    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.ra_start, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args);
    Py_DECREF(work_item_class);
}

static void python_on_ra_stop(void *opaque, CommsResultsItem *work_results)
{
    // Variables
    PyObject *result_item_class, *comms_message, *buffer, *callback_args;
    PythonInterface *p = PYTHON(opaque);  

    // Get a result item object
    result_item_class = PyObject_GetAttrString(p->script_module, "ResultItem");
    python_error_check(result_item_class);

    comms_message = PyObject_CallObject(result_item_class, NULL);
    python_error_check(comms_message);

    // Get a byte string array
    buffer = PyByteArray_FromStringAndSize((const char *)work_results->msg, work_results->msg->size);
    python_error_check(buffer);

    // Add the byte string to the work item
    python_put_check(PyObject_SetAttrString(comms_message, "buffer", buffer));   

    // Build an args tuple from the work item
    callback_args = PyTuple_New(1);
    python_error_check(callback_args);
    python_put_check(PyTuple_SetItem(callback_args, 0, comms_message)); 

    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.ra_stop, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args);
    Py_DECREF(result_item_class);
}

static void python_on_ra_idle(void *opaque)
{
    // Variables
    PythonInterface *p = PYTHON(opaque);
    
    // This function requires no args
    // So, we will simply call the script
    PyObject_CallObject(p->py_callbacks.ra_idle, NULL);

    // Check for issues with the call
    python_call_check();
}

static void python_on_execute_instruction(void *opaque, uint64_t vaddr, void *addr)
{
    // Variables
    PyObject *callback_args;
    PythonInterface *p = PYTHON(opaque);

    // Create a tuple to contain arguments
    callback_args = Py_BuildValue("Ky#", vaddr, addr, 15);
    python_error_check(callback_args);

    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.execute_instruction, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args);
}

static void python_on_breakpoint(void *opaque, int cpu_idx, uint64_t vaddr, int bp_id)
{
    // Variables
    PyObject *callback_args;
    PythonInterface *p = PYTHON(opaque);

    // Build an args tuple from the cpu index, breakpoint address, and id
    callback_args = Py_BuildValue("iKi", cpu_idx, vaddr, bp_id);
    python_error_check(callback_args);

    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.breakpoint, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args);      
}

static void python_on_exception(void *opaque, int32_t exception)
{
    // Variables
    PyObject *callback_args;
    PythonInterface *p = PYTHON(opaque);

    // Build an args tuple 
    callback_args = Py_BuildValue("(i)", exception);
    python_error_check(callback_args);

    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.exception, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args); 
}

static void python_on_memory_write(void *opaque, uint64_t paddr, uint64_t vaddr, const uint8_t *value, void *addr, int size)
{
    PyObject *callback_args;
    PythonInterface *p = PYTHON(opaque);

    callback_args = Py_BuildValue("KKKy#", paddr, vaddr, value, addr, size);
    python_error_check(callback_args);

    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.memory_write, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args); 
}

static void python_on_memory_read(void *opaque, uint64_t paddr, uint64_t vaddr, uint8_t *value, void *addr, int size)
{
    PyObject *callback_args;
    PythonInterface *p = PYTHON(opaque);

    callback_args = Py_BuildValue("KKKy#", paddr, vaddr, value, addr, size);
    python_error_check(callback_args);

    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.memory_read, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args); 
}

static void python_on_syscall(void *opaque, uint64_t number, va_list args)
{
    PythonInterface *p = PYTHON(opaque);
    unsigned long syscall_number;
    PyObject *arg_list, *callback_args;

    // Prepare syscall number, its the first entry in the arg list
    syscall_number = va_arg(args, uint64_t);

    // Prepare list
    arg_list = PyList_New(number - 1);
    python_error_check(arg_list);

    // place the remaining args in the list to be treated as syscall arguments
    int x;
    for (x = 0; x < number - 1; ++x)
    {
        python_put_check(PyList_SetItem(arg_list, x, PyLong_FromUnsignedLong(va_arg(args, uint64_t))));
    }

    callback_args = Py_BuildValue("KO", syscall_number, arg_list);
    python_error_check(callback_args);

    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.on_syscall, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args);
}

static void python_on_syscall_exit(void *opaque, uint64_t number, va_list args)
{
    PythonInterface *p = PYTHON(opaque);
    PyObject *arg_list, *callback_args;

    // Prepare list
    arg_list = PyList_New(number);
    python_error_check(arg_list);

    // place the remaining args in the list to be treated as syscall arguments
    int x;
    for (x = 0; x < number; ++x)
    {
        python_put_check(PyList_SetItem(arg_list, x, PyLong_FromUnsignedLong(va_arg(args, uint64_t))));
    }

    callback_args = Py_BuildValue("(O)", arg_list);
    python_error_check(callback_args);

    // Call the callback and check for an error
    PyObject_CallObject(p->py_callbacks.on_syscall_exit, callback_args);
    python_call_check();

    // decref
    Py_DECREF(callback_args);
}

static void python_change_state_handler(void *opaque, int running, RunState state)
{
    PythonInterface *p = PYTHON(opaque);
    PyObject *callback_args;

    callback_args = Py_BuildValue("KK", running, state);
    python_error_check(callback_args);

    PyObject_CallObject(p->py_callbacks.vm_change_state_handler, callback_args);
    python_call_check();

    Py_DECREF(callback_args);
}

static void python_on_interrupt(void *opaque, int mask)
{
    PythonInterface *p = PYTHON(opaque);
    PyObject *callback_args;

    callback_args = Py_BuildValue("(i)", mask);
    python_error_check(callback_args);

    PyObject_CallObject(p->py_callbacks.on_interrupt, callback_args);
    python_call_check();

    Py_DECREF(callback_args);
}

static void python_on_packet_recv(void *opaque, uint8_t **pkt_buf, uint32_t *pkt_size)
{
    PythonInterface *p = PYTHON(opaque);
    PyObject *buff_return, *bytes, *callback_args;
    char *replacement_data;
    Py_ssize_t len = 0;

    callback_args = Py_BuildValue("(y#)", *pkt_buf, *pkt_size);
    python_error_check(callback_args);

    buff_return = PyObject_CallObject(p->py_callbacks.on_packet_recv, callback_args);
    python_error_check(buff_return);

    if (buff_return != Py_None)
    {
        bytes = PyByteArray_FromObject(buff_return);
        if (bytes)
        {
            replacement_data = PyByteArray_AsString(buff_return);
            if (replacement_data)
            {
                len = PyByteArray_Size(buff_return);

                *pkt_buf = g_new0(uint8_t, len);
                if (*pkt_buf)
                {
                    memcpy(*pkt_buf, replacement_data, len);
                    *pkt_size = len;
                }  
            } 
        }
        else
        {
            error_report("TypeError: python_on_packet_recv expects to be returned None or  somthing expressable as a bytearray");
            abort();            
        }
             
    }

    Py_DECREF(callback_args);
    Py_DECREF(buff_return);
}

static void python_on_packet_send(void *opaque, uint8_t **pkt_buf, uint32_t *pkt_size)
{
    PythonInterface *p = PYTHON(opaque);
    PyObject *buff_return, *bytes, *callback_args;
    char *replacement_data;
    Py_ssize_t len = 0;

    callback_args = Py_BuildValue("(y#)", *pkt_buf, *pkt_size);
    python_error_check(callback_args);

    buff_return = PyObject_CallObject(p->py_callbacks.on_packet_send, callback_args);
    python_error_check(buff_return);

    if (buff_return != Py_None)
    {
        bytes = PyByteArray_FromObject(buff_return);
        if (bytes)
        {
            replacement_data = PyByteArray_AsString(bytes);
            if (replacement_data)
            {
                len = PyByteArray_Size(buff_return);

                *pkt_buf = g_new0(uint8_t, len);
                if (*pkt_buf)
                {
                    memcpy(*pkt_buf, replacement_data, len);
                    *pkt_size = len;
                }        
            }
        }
        else
        {
            error_report("TypeError: python_on_packet_recv expects to be returned None or something expressable as a bytearray");
            abort();        
        }
    }    
        
    Py_DECREF(callback_args);
    Py_DECREF(buff_return);
}

static void python_on_vm_startup(void *opaque)
{
    PythonInterface *p = PYTHON(opaque);

    // This function requires no args
    // So, we will simply call the script
    PyObject_CallObject(p->py_callbacks.on_vm_startup, NULL);

    // Check for issues with the call
    python_call_check();
}

static void python_on_vm_shutdown(void *opaque)
{
    PythonInterface *p = PYTHON(opaque);

    // This function requires no args
    // So, we will simply call the script
    PyObject_CallObject(p->py_callbacks.on_vm_shutdown, NULL);

    // Check for issues with the call
    python_call_check();
}

static bool python_on_command(void *opaque, const char *cmd, const char *args)
{
    PythonInterface *p = PYTHON(opaque);

    PyObject *callback_args;

    callback_args = Py_BuildValue("zz", cmd, args);
    python_error_check(callback_args);

    PyObject *ret = PyObject_CallObject(p->py_callbacks.on_command, callback_args);
    python_call_check();

    bool handled = (Py_True == ret);
    Py_DECREF(callback_args);
    Py_DECREF(ret);

    return handled;
}

static PyObject *python_get_virtual_memory(PyObject *self, PyObject *args)
{
    int cpu_id;
    unsigned long long address;
    Py_ssize_t size;
    PyObject *pydata = NULL;

    if (PyArg_ParseTuple(args, "iLn", &cpu_id, &address, &size))
    {
        pydata = PyByteArray_FromStringAndSize((char*)NULL, size);
        python_error_check(pydata);

        uint8_t *data = (uint8_t *)PyByteArray_AsString(pydata);
        qemu_get_virtual_memory(cpu_id, address, size, &data);
        return pydata;
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_get_virtual_memory requires cpu id (int), address (long int), and  size (int).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_set_virtual_memory(PyObject *self, PyObject *args)
{
    unsigned long long address;
    int cpu_id;
    Py_ssize_t size;
    PyObject *bytes = NULL;

    if (PyArg_ParseTuple(args, "iLO", &cpu_id, &address, &bytes))
    {
        uint8_t *data = (uint8_t *)PyByteArray_AsString(bytes);
        size = PyByteArray_Size(bytes);
        qemu_set_virtual_memory(cpu_id, address, size, data);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_set_virtual_memory requires cpu id (int), address (long int), and  data (bytearray).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_get_physical_memory(PyObject *self, PyObject *args)
{
    unsigned long long address;
    Py_ssize_t size;
    PyObject *pydata = NULL;

    if (PyArg_ParseTuple(args, "Ln", &address, &size))
    {
        pydata = PyByteArray_FromStringAndSize((char*)NULL, size);
        python_error_check(pydata);

        uint8_t *data = (uint8_t *)PyByteArray_AsString(pydata);
        qemu_get_physical_memory(address, size, &data);
        return pydata;
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_get_physical_memory requires address (long int) and size (int).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_set_physical_memory(PyObject *self, PyObject *args)
{
    unsigned long long address;
    Py_ssize_t size;
    PyObject *bytes = NULL;

    if (PyArg_ParseTuple(args, "LO", &address, &bytes)) 
    {
        uint8_t *data = (uint8_t *)PyByteArray_AsString(bytes);
        size = PyByteArray_Size(bytes);
        qemu_set_physical_memory(address, size, data);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_set_physical_memory requires address (long int) and data (bytearray).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_get_cpu_register(PyObject *self, PyObject *args)
{
    int cpu_id;
    PyObject *reg_obj = NULL;
    char *reg_name = NULL; 

    if (PyArg_ParseTuple(args, "is", &cpu_id, &reg_name))
    {
        uint8_t *data;
        int reg_id, amt_read;

        reg_id = qemu_get_cpu_register_id(reg_name);
        if (reg_id >= 0)
        {
            amt_read = qemu_get_cpu_register(cpu_id, reg_id, &data);
            reg_obj = Py_BuildValue("y#i", data, amt_read, amt_read);
            python_error_check(reg_obj);
            return reg_obj;
        }else{
            char message[500];
            snprintf(message, sizeof(message), "%s is not a valid register", reg_name);
            PyErr_SetString(PyExc_ValueError, message);
	}
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_get_cpu_register requires cpu id (int) and register name (string).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_set_breakpoint(PyObject *self, PyObject *args)
{
    OSBreakpoint* result = NULL;
    uint64_t bp_adder = 0;
    uint64_t process_pid = 0;
    int is_hwbp = 0;

    if (PyArg_ParseTuple(args, "iKp", &process_pid, &bp_adder, &is_hwbp))
    {
        OSPid os_pid = NULL_PID;
        if(process_pid > 0){
            os_pid = qemu_get_ospid(process_pid);
        }

        OSBreakpointType bp_type = OS_BREAKPOINT_SW;
        if(is_hwbp){
            bp_type = OS_BREAKPOINT_HW;
        }
    
        result = qemu_set_os_breakpoint_full(os_pid, bp_adder, 1, bp_type);

        if(os_pid != NULL_PID){
            qemu_free_ospid(os_pid);
        }

        if (result){
            return PyLong_FromLong(result->id);
        }

        PyErr_SetString(continue_vm_error, "python_set_breakpoint failed to set breakpoint on address");
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_set_breakpoint requires process pid (int), address (uint64_t), and is_hardware (bool).");
        PyErr_SetString(PyExc_TypeError, message);
    }
    
    Py_RETURN_NONE;
}

static PyObject *python_clear_breakpoint(PyObject *self, PyObject *args)
{
    uint64_t bp_id = 0;

    if (PyArg_ParseTuple(args, "K", &bp_id))
    {
        OSBreakpoint *bp = qemu_find_os_breakpoint(bp_id);
        if(bp){
            qemu_remove_os_breakpoint(bp);
        }else{
            PyErr_SetString(continue_vm_error, "python_clear_breakpoint failed to find breakpoint with id");
        }
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_clear_breakpoint requires BP_ID (uint64_t).");
        PyErr_SetString(PyExc_TypeError, message);
    }
    
    Py_RETURN_NONE;    
}


static PyObject *python_set_cpu_register(PyObject *self, PyObject *args)
{
    uint8_t *data = NULL;
    char *reg_name = NULL;
    int cpu_id, reg_id, size;
    PyObject *bytes = NULL;

    if (PyArg_ParseTuple(args, "isO", &cpu_id, &reg_name, &bytes)) 
    {
        data = (uint8_t *) PyByteArray_AsString(bytes);
        size = PyByteArray_Size(bytes);
        reg_id = qemu_get_cpu_register_id(reg_name);
        if (reg_id < 0)
        {
            char message[500];
            snprintf(message, sizeof(message), "%s is not a valid register", reg_name);
            PyErr_SetString(PyExc_ValueError, message);
            Py_RETURN_NONE; 
        }

        qemu_set_cpu_register(cpu_id, reg_id, size, data);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_set_cpu_register requires cpu id (int), register name (string), and data (bytearray).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE; 
}

static PyObject *python_get_current_cpu(PyObject *self, PyObject *args)
{
    return PyLong_FromLong(current_cpu->cpu_index);
} 

static PyObject *python_get_register_names(PyObject *self, PyObject *args)
{
    PyObject *pyregs = PyList_New(0);
    int cur_reg = qemu_get_cpu_first_register_id();
    while(cur_reg >= 0){
        const char *reg_name = qemu_get_cpu_register_name(cur_reg);
        if(reg_name) {
            PyObject *pyname = PyUnicode_FromString(reg_name);
            if(pyname) {
                PyList_Append(pyregs, pyname);
                Py_DECREF(pyname);
            }
        }
        cur_reg = qemu_get_cpu_next_register_id(cur_reg);
    }
    return pyregs;
}

static int PyQObject_Determine_Type(PyObject *qobj)
{
    PyObject *type_id = PyObject_GetAttrString(qobj, "o_type");
    if (!type_id) return -1;
    
    int ret_val = PyLong_AsLong(type_id);
    if (type_id) Py_DECREF(type_id);

    return ret_val;
}

static QList *PyQList_AsQList(PyObject *qobj)
{
    PyObject *list, *val;

    list = PyObject_GetAttrString(qobj, "value");
    if (!list) goto list_error;

    QList *ret_val = qlist_new();
    int x, list_len = PyList_Size(list);

    for (x = 0; x < list_len; ++x)
    {
        PyObject *value = PyList_GetItem(list, x);
        if (!value) goto list_error;

        val = PyObject_GetAttrString(value, "value");
        if (!val)
        {
            PyErr_SetString(PyExc_TypeError, "QLists must be filled with QObject types.");
            goto list_error;
        }

        switch(PyQObject_Determine_Type(value))
        {
        case QTYPE_QNULL:
            qlist_append_null(ret_val);
            break;
        case QTYPE_QSTRING:
            {
                const char *v = PyUnicode_AsUTF8(val);
                if (!v) 
                {
                    PyErr_SetString(PyExc_TypeError, "QString should be loaded with a string.");
                    goto list_error;
                }                

                qlist_append_str(ret_val, v);
            }
            break;
        case QTYPE_QNUM: 
            {
                int v = PyLong_AsLong(val);

                PyObject *err = PyErr_Occurred();
                if (err)
                { 
                    PyErr_SetString(PyExc_TypeError, "QNum should be loaded with a number");
                    goto list_error;
                }        
                
                qlist_append_int(ret_val, v); 
            }   
            break;
        case QTYPE_QBOOL: 
            {
                int v = PyLong_AsLong(val);

                PyObject *err = PyErr_Occurred();
                if (err)
                { 
                    PyErr_SetString(PyExc_TypeError, "QBool should be loaded with a boolean value");
                    goto list_error;
                }

                bool b = (v != 0);
                qlist_append_bool(ret_val, b);
            }
            break;
        case QTYPE_QLIST:
            {
                QList *v = PyQList_AsQList(value);
                if (!v)
                {
                    goto list_error; 
                }

                qlist_append_obj(ret_val, QOBJECT(v));
            }
            break;
        case QTYPE_QDICT:
            {
                QDict *v = PyQDict_AsQDict(value);
                if (!v)
                {
                    goto list_error;
                } 

                qlist_append_obj(ret_val, QOBJECT(v));
            }
            break;
        default: 
            PyErr_SetString(PyExc_TypeError, "Unknown QObject Type");
            goto list_error;
        }
        

        if (val) Py_DECREF(val);
    }

    if (list) Py_DECREF(list);

    return ret_val;

list_error:
    if (ret_val) g_free(ret_val);
    if (val) Py_DECREF(val);
    if (list) Py_DECREF(list);
    return NULL;
}

static QDict *PyQDict_AsQDict(PyObject *qobj)
{

    PyObject *dict, *keys, *key, *value, *val;
    QDict *d = qdict_new();

    dict = PyObject_GetAttrString(qobj, "value");
    if (!dict) goto dict_error;

    keys = PyDict_Keys(dict);
    if (!keys) goto dict_error;

    int x, keys_len = PyList_Size(keys);

    for (x = 0; x < keys_len; ++x)
    {    
        key = PyList_GetItem(keys, x);
        if (!key) goto dict_error;

        value = PyDict_GetItem(dict, key);
        if (!value) goto dict_error;

        val = PyObject_GetAttrString(value, "value");
        if (!val)
        {
            PyErr_SetString(PyExc_TypeError, "QDicts must be filled with QObject types.");
            goto dict_error;
        }

        const char *k = PyUnicode_AsUTF8(key);
        if (!k) goto dict_error;


        switch(PyQObject_Determine_Type(value))
        {
        case QTYPE_QNULL:
                qdict_put_null(d, k);
            break;
        case QTYPE_QSTRING:
            {
                const char *v = PyUnicode_AsUTF8(val);
                if (!v) 
                {
                    PyErr_SetString(PyExc_TypeError, "QString should be loaded with a string.");
                    goto dict_error;
                }

                qdict_put_str(d, k, v);
            }
            break;
        case QTYPE_QNUM:
            {
                int v = PyLong_AsLong(val);

                PyObject *err = PyErr_Occurred();
                if (err)
                { 
                    PyErr_SetString(PyExc_TypeError, "QNum should be loaded with a number");
                    goto dict_error;
                }

                qdict_put_int(d, k, v);   
            }      
            break;
        case QTYPE_QBOOL:
            {
                int v = PyLong_AsLong(val);

                PyObject *err = PyErr_Occurred();
                if (err)
                { 
                    PyErr_SetString(PyExc_TypeError, "QBool should be loaded with a boolean value");
                    goto dict_error;
                }

                bool b = (v != 0);

                qdict_put_bool(d, k, b); 
            }
            break;
        case QTYPE_QLIST:     
            {
                QList *v = PyQList_AsQList(value);
                if (!v)
                {
                    goto dict_error; 
                }

                qdict_put_obj(d, k, QOBJECT(v));
            }
            break;
        case QTYPE_QDICT:
            {
                QDict *v = PyQDict_AsQDict(value);
                if (!v)
                {
                    goto dict_error;
                } 

                qdict_put_obj(d, k, QOBJECT(v));     
            }   
            break;
        default: 
            PyErr_SetString(PyExc_TypeError, "Unknown QObject Type");
            goto dict_error;
        }    
        if (val) Py_DECREF(val);             
    }

    if (dict) Py_DECREF(dict);         
    if (keys) Py_DECREF(keys);  

    return d;  

dict_error:
    if (d) g_free(d);
    if (dict) Py_DECREF(dict);         
    if (keys) Py_DECREF(keys);  
    if (val) Py_DECREF(val);  
    return NULL;
}

static PyObject *python_qmp_command(PyObject *self, PyObject *args)
{
    PyObject* qmp = NULL;

    if (PyArg_ParseTuple(args, "O", &qmp))
    {
        QDict* qdict = PyQDict_AsQDict(qmp);
        if (PyErr_Occurred()) {
            Py_RETURN_NONE;
        }
        QObject* request = QOBJECT(qdict);
        QDict* result = NULL;
        result = qmp_dispatch(qmp_commands, request, false);

        if (qdict_haskey(result, "error"))
        {
            PyErr_Format(PyExc_TypeError, "QMP Error: %s Description %s",  qdict_get_str(qdict_get_qdict(result, "error"), "class"), qdict_get_str(qdict_get_qdict(result, "error"), "desc"));
            Py_RETURN_NONE;
        }
        QString* json = qobject_to_json(QOBJECT(result));
        PyObject* res = PyUnicode_FromString(qstring_get_str(json));
        qobject_unref(json);
        return res;
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_qmp_command requires qmp_command (Qdict).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_qmp_emit(PyObject *self, PyObject *args)
{
    PyObject *qdict; 
    int event_no;

    if (PyArg_ParseTuple(args, "iO", &event_no, &qdict))
    {
        Error *err = NULL;
        QDict *d = PyQDict_AsQDict(qdict);
        if (!d) return NULL;

        QMPEventFuncEmit emit;

        QDict *ts;
        qemu_timeval tv;

        int error = qemu_gettimeofday(&tv);
        /* Put -1 to indicate failure of getting host time */
        ts = qdict_from_jsonf_nofail("{ 'seconds': %lld, 'microseconds': %lld }",
                                 error < 0 ? -1LL : (long long)tv.tv_sec,
                                 error < 0 ? -1LL : (long long)tv.tv_usec);
        qdict_put(d, "timestamp", ts);


        emit = qmp_event_get_func_emit();
        emit(event_no, d, &err);      
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_qmp_emit requires event number (int) and data (qdict).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_vm_stop(PyObject *self, PyObject *args)
{
    int reason;

    if (PyArg_ParseTuple(args, "i", &reason))
    {
        qemu_vm_stop(reason);
    }else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_vm_stop requires reason (int).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_vm_singlestep(PyObject *self, PyObject *args)
{
    Error *err = NULL;
    int cpu_idx;
    if (PyArg_ParseTuple(args, "i", &cpu_idx)) {
        CPUState* cpu = qemu_get_cpu(cpu_idx);
        if(cpu) {
            cpu_single_step(cpu, SSTEP_ENABLE|SSTEP_NOIRQ|SSTEP_NOTIMER);
        }
    }

    if (err)
    {
        PyErr_SetString(continue_vm_error, error_get_pretty(err));
        return NULL;
    }

    // continue_vm(&err);
    // if (err)
    // {
    //     PyErr_SetString(continue_vm_error, error_get_pretty(err));
    //     return NULL;
    // }

    Py_RETURN_NONE;
}

static PyObject *python_vm_continue(PyObject *self, PyObject *args)
{
    qemu_vm_continue();

    Py_RETURN_NONE;
}


static PyObject *python_vm_shutdown(PyObject *self, PyObject *args)
{
    qemu_vm_shutdown();

    // Does not raise an error
    Py_RETURN_NONE;
}

static PyObject *python_vm_restart(PyObject *self, PyObject *args)
{
    qemu_vm_reset();

    // Does not raise an error
    Py_RETURN_NONE;
}

static PyObject *python_vm_quit(PyObject *self, PyObject *args)
{
    qemu_vm_quit();

    // Does not raise an error
    Py_RETURN_NONE;
}

static PyObject *python_vm_get_state(PyObject *self, PyObject *args)
{
    PyObject *callback_args;

    callback_args = Py_BuildValue("i", qemu_vm_get_state());
    python_error_check(callback_args);

    // Does not raise an error
    return callback_args;
}

static PyObject *python_ra_add_job(PyObject *self, PyObject *args)
{
    int queue_idx;
    char message[500];
    uint8_t *msg_data = NULL;
    Py_ssize_t msg_size = 0;

    if (PyArg_ParseTuple(args, "is#", &queue_idx, &msg_data, &msg_size)) {
        if (queue_idx < 0)
        {
            snprintf(message, sizeof(message), "%d is not a valid queue identifier", queue_idx);
            PyErr_SetString(PyExc_ValueError, message);
            Py_RETURN_NONE;
        }

        CommsMessage *dup_msg = (CommsMessage *)g_memdup(msg_data, msg_size);
        if(!dup_msg)
        {
            snprintf(message, sizeof(message), "Unable to duplicate message memory");
            PyErr_SetString(PyExc_ValueError, message);
            Py_RETURN_NONE;
        }

        CommsQueue *q = get_comms_queue(queue_idx);
        if (!q)
        {
            snprintf(message, sizeof(message), "Unable to get queue number %d", queue_idx);
            PyErr_SetString(PyExc_ValueError, message);
            g_free(dup_msg);
            Py_RETURN_NONE;
        }

        if(!racomms_queue_add_job(q, dup_msg))
        {
            snprintf(message, sizeof(message), "Unable to parse job add message");
            PyErr_SetString(PyExc_ValueError, message);
            Py_RETURN_NONE;
        }
    }else{
        snprintf(message, sizeof(message), "Unable to parse job add arguments");
        PyErr_SetString(PyExc_ValueError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_send_key(PyObject *self, PyObject *args)
{
    char *key_string = NULL;

    if (PyArg_ParseTuple(args, "s", &key_string)) 
    {
        qemu_vm_send_key(key_string);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_send_key keys (string).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_send_key_string(PyObject *self, PyObject *args)
{
    char *key_string = NULL;

    if (PyArg_ParseTuple(args, "s", &key_string)) 
    {
        qemu_vm_send_keystring(key_string);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_send_key_string key_string (string).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_init_oshandler(PyObject *self, PyObject *args)
{
    char *hint_string = NULL;
    PyObject *os_string;

    if (PyArg_ParseTuple(args, "z", &hint_string))
    {
        const char *os_found = qemu_init_oshandler(0, hint_string);

        if(os_found){
            os_string = PyByteArray_FromStringAndSize(os_found, strlen(os_found));
            python_error_check(os_string);
            return os_string;
        }
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_init_oshandler os_hint (string).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_get_process_vma_list(PyObject *self, PyObject *args)
{
    uint64_t process_pid = 0;

    if (PyArg_ParseTuple(args, "i", &process_pid) && process_pid > 0)
    {
        OSPid os_pid = qemu_get_ospid(process_pid);
        if(os_pid == NULL_PID){
            PyErr_SetString(continue_vm_error, "python_get_process_vma_list failed to find process");
            Py_RETURN_NONE;
        }

        Process *ps = qemu_get_process(os_pid);
        if(ps){
            uint64_t start, end, flags, pgprot;
            PyObject *vma_list = PyList_New(0);
            void *next_vma = qemu_get_process_vma_first(ps);

            while(next_vma)
            {
                PyObject *entry;
                qemu_get_process_vma_next(ps, &next_vma, &start, &end, &flags, &pgprot, NULL);

                // Fill the tuple with the vma info then put it in the list
                entry = Py_BuildValue("KKK", start, end, flags);
                python_put_check(PyList_Append(vma_list, entry));
                Py_DECREF(entry);
            }

            qemu_free_process(ps);
            qemu_free_ospid(os_pid);
            return vma_list;
        }

        qemu_free_ospid(os_pid);
        PyErr_SetString(continue_vm_error, "python_get_process_vma_list failed to get process information");
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_get_process_vma_list requires pid (int).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_get_process_detail_list(PyObject *self, PyObject *args)
{
    ProcessList *plist = qemu_get_process_list();
    if(plist){
        uint64_t pid, base, dir;
        const char *name;
        PyObject *detail_list = PyList_New(0);

        for(ProcessList *p = plist; p; p = p->next)
        {
            PyObject *entry;
            qemu_get_process_detail(p->value, &pid, &base, &dir, &name);

            // Fill the tuple with the vma info then put it in the list
            entry = Py_BuildValue("zKKK", name, pid, base, name);
            python_put_check(PyList_Append(detail_list, entry));
            Py_DECREF(entry);
        }

        qemu_free_process_list(plist);
        return detail_list;
    }

    PyErr_SetString(continue_vm_error, "python_get_process_detail_list failed to get process information");

    Py_RETURN_NONE;
}

static PyObject *python_get_process_pid_by_name(PyObject *self, PyObject *args)
{
    char *name = NULL;
    PyObject *pylong;

    if (PyArg_ParseTuple(args, "s", &name)) 
    {
        OSPid os_pid = qemu_get_ospid_by_name(name);

        if( os_pid != NULL_PID ){
            pylong = PyLong_FromLong(qemu_get_pid_by_os_process(os_pid));
            qemu_free_ospid(os_pid);
            return pylong;
        }
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_get_process_pid_by_name name (string).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_get_process_pid_by_active(PyObject *self, PyObject *args)
{
    uint64_t cpu_idx = 0;
    PyObject *pylong;

    if (PyArg_ParseTuple(args, "i", &cpu_idx) && cpu_idx > 0)
    {
        OSPid os_pid = qemu_get_ospid_by_active(cpu_idx);

        if( os_pid != NULL_PID ){
            pylong = PyLong_FromLong(qemu_get_pid_by_os_process(os_pid));
            qemu_free_ospid(os_pid);
            return pylong;
        }
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_get_process_pid_by_name name (string).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_load_snapshot(PyObject *self, PyObject *args)
{
    char *snapshot_name;

    if (PyArg_ParseTuple(args, "s", &snapshot_name))
    {
        Error *err = NULL;
        load_snapshot(snapshot_name, &err);
        if( err ){
            PyErr_SetString(PyExc_TypeError, "Failed to load snapshot");
        }
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_load_snapshot snapshot_name (string).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_save_snapshot(PyObject *self, PyObject *args)
{
    char *snapshot_name;

    if (PyArg_ParseTuple(args, "s", &snapshot_name))
    {
        Error *err = NULL;
        save_snapshot(snapshot_name, &err);
        if( err ){
            PyErr_SetString(PyExc_TypeError, "Failed to save snapshot");
        }
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_save_snapshot snapshot_name (string).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static void python_timer_delete(PyObject *self)
{
    // convert pytimer to timer
    QEMUTimer *timer = (QEMUTimer*)PyCapsule_GetPointer(self, NULL);

    timer_del(timer);
    timer_free(timer);
}

static void python_timer_trigger(void *callable_pyobject)
{
    PyObject *timer = (PyObject *)callable_pyobject;

    PyObject_CallObject(timer, NULL);
    python_call_check();
}

static PyObject *python_timer_create(PyObject *self, PyObject *args)
{
    int clock_type;
    PyObject *pytimer, *callable_pyobject;
    QEMUTimer *timer;

    if (PyArg_ParseTuple(args, "iO", &clock_type, &callable_pyobject))
    {
        if(!PyCallable_Check(callable_pyobject)){
            PyErr_SetString(PyExc_TypeError, "Python object needs to be callable");
            Py_RETURN_NONE;
        }

        timer = timer_new_ms(clock_type, python_timer_trigger, callable_pyobject);

        // convert timer to pytimer
        pytimer = PyCapsule_New(timer, NULL, python_timer_delete);

        return pytimer;
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_timer_create clock_type (int), callable_pyobject (object)");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_timer_start(PyObject *self, PyObject *args)
{
    int clock_type;
    int64_t clock_frequency;
    PyObject *pytimer;
    QEMUTimer *timer;

    if (PyArg_ParseTuple(args, "ikO", &clock_type, &clock_frequency, &pytimer))
    {
        // convert pytimer to timer
        timer = (QEMUTimer*)PyCapsule_GetPointer(pytimer, NULL);

        timer_mod(timer, qemu_clock_get_ms(clock_type) + clock_frequency);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_timer_start clock_type (int), clock_frequency (int64_t), pytimer (object)");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_save_screenshot(PyObject *self, PyObject *args)
{
    char *file_name;

    if (PyArg_ParseTuple(args, "s", &file_name))
    {
        if(!qemu_vm_save_screenshot(file_name, false, NULL, false, 0)){
            PyErr_SetString(PyExc_TypeError, "python_save_screenshot error taking screenshot");
        }
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_save_screenshot  file_name (string)");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_is_kvm_enabled(PyObject *self, PyObject *args)
{
    if(kvm_enabled()){
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *python_is_tcg_enabled(PyObject *self, PyObject *args)
{
    if(tcg_enabled()){
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *python_get_snapshots(PyObject *self, PyObject *args)
{
    ImageInfoList *snapshots = NULL;
    ImageInfoList *infoiter;

    qemu_vm_get_snapshots(&snapshots);

    PyObject *snaps_list = PyList_New(0);

    for (infoiter = snapshots; infoiter; infoiter = infoiter->next)
    {
        ImageInfo *imginfo = infoiter->value;

        if (imginfo->has_snapshots) {
            SnapshotInfoList *snapiter;

            for (snapiter = imginfo->snapshots; snapiter; snapiter = snapiter->next) {
                PyObject *entry;
                SnapshotInfo *snapinfo = snapiter->value;
                // Fill the tuple with the snapshot info then put it in the list
                entry = Py_BuildValue("{z:z,z:z,z:k,z:k,z:k,z:k,z:k}",
                    "name", snapinfo->name,
                    "id", snapinfo->id,
                    "size", snapinfo->vm_state_size,
                    "date_s", snapinfo->date_sec,
                    "date_ns", snapinfo->date_nsec,
                    "vmclock_s",snapinfo->vm_clock_sec,
                    "vmclock_ns",snapinfo->vm_clock_nsec);
                python_put_check(PyList_Append(snaps_list, entry));
                Py_DECREF(entry);
            }
        }
    }

    qapi_free_ImageInfoList(snapshots);

    return snaps_list;
}

static PyObject *python_add_command(PyObject *self, PyObject *args)
{
    PluginObject *po = NULL;
    const char *plugin_name;
    const char *cmd_name;
    const char *cmd_desc;

    if (PyArg_ParseTuple(args, "zss", &plugin_name, &cmd_name, &cmd_desc))
    {
        if(plugin_name){
            po = qemu_plugin_find_plugin(plugin_name);
            if(!po){
                PyErr_SetString(PyExc_TypeError, "python_add_command could not find provider plugin");
            }
        }

        qemu_command_add(po, cmd_name, cmd_desc, NULL);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_add_command  cmd_name (string) cmd_desc (string)");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_remove_command(PyObject *self, PyObject *args)
{
    PluginObject *po = NULL;
    const char *plugin_name;
    const char *cmd_name;

    if (PyArg_ParseTuple(args, "zs", &plugin_name, &cmd_name))
    {
        if(plugin_name){
            po = qemu_plugin_find_plugin(plugin_name);
            if(!po){
                PyErr_SetString(PyExc_TypeError, "python_remove_command could not find provider plugin");
            }
        }

        qemu_command_remove(po, cmd_name);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_remove_command  cmd_name (string)");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_command_print(PyObject *self, PyObject *args)
{
    const char *print_str;

    if (PyArg_ParseTuple(args, "s", &print_str))
    {
        qemu_command_printf("%s", print_str);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_command_print  print_str (string)");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_command_pretty_print(PyObject *self, PyObject *args)
{
    const char *print_str;

    if (PyArg_ParseTuple(args, "s", &print_str))
    {
        qemu_command_pretty_printf("%s", print_str);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_command_pretty_print  print_str (string)");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_get_process_memory(PyObject *self, PyObject *args)
{
    int cpu_id, process_pid;
    unsigned long long address;
    Py_ssize_t size;
    PyObject *pydata = NULL;

    if (PyArg_ParseTuple(args, "iiLn", &cpu_id, &process_pid, &address, &size))
    {
        OSPid os_pid = NULL_PID;
        if(process_pid > 0){
            os_pid = qemu_get_ospid(process_pid);
        }

        pydata = PyByteArray_FromStringAndSize((char*)NULL, size);
        python_error_check(pydata);

        uint8_t *data = (uint8_t *)PyByteArray_AsString(pydata);
        qemu_process_get_memory(cpu_id, os_pid, address, size, &data);
        qemu_free_ospid(os_pid);
        return pydata;
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_get_process_memory requires cpu id (int), pid (int), address (long int), and  size (int).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_set_process_memory(PyObject *self, PyObject *args)
{
    unsigned long long address;
    int cpu_id, process_pid;
    Py_ssize_t size;
    PyObject *bytes = NULL;

    if (PyArg_ParseTuple(args, "iiLO", &cpu_id, &process_pid, &address, &bytes))
    {
        OSPid os_pid = NULL_PID;
        if(process_pid > 0){
            os_pid = qemu_get_ospid(process_pid);
        }

        uint8_t *data = (uint8_t *)PyByteArray_AsString(bytes);
        size = PyByteArray_Size(bytes);
        qemu_process_set_memory(cpu_id, os_pid, address, size, data);
        qemu_free_ospid(os_pid);
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_set_process_memory requires cpu id (int), pid (int). address (long int), and  data (bytearray).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

static PyObject *python_get_cpu_type(PyObject *self, PyObject *args)
{
    int cpu_id;
    PyObject *arch_string;

    if (PyArg_ParseTuple(args, "i", &cpu_id))
    {
        const char *arch_type = qemu_vm_get_arch(cpu_id);

        if(arch_type){
            arch_string = PyByteArray_FromStringAndSize(arch_type, strlen(arch_type));
            python_error_check(arch_string);
            return arch_string;
        }
    }
    else
    {
        char message[500];
        snprintf(message, sizeof(message), "python_get_cpu_type cpu_id (int).");
        PyErr_SetString(PyExc_TypeError, message);
    }

    Py_RETURN_NONE;
}

void qmp_python_exec(const char *script, Error **errp)
{
    Error* local_err = NULL;
    PyObject *m, *d, *v;
    m = PyImport_AddModule("__main__");
    if (m == NULL)
    {
        PyObject *err = PyErr_Occurred();
        PyErr_Print();
        error_setg(&local_err, "%s", PyUnicode_AsUTF8(PyObject_Str(err)));
        Py_DECREF(err);
        return;
    }
    d = PyModule_GetDict(m);
    v = PyRun_StringFlags(script, Py_file_input, d, d, NULL);
    if (v == NULL)
    {
        PyObject *err = PyErr_Occurred();
        error_setg(&local_err, "%s", PyUnicode_AsUTF8(PyObject_Str(err)));
        Py_DECREF(err);
    }

    error_propagate(errp, local_err);
}

void qmp_python_exec_file(const char *file, Error **errp)
{
	Error* local_err = NULL;

    FILE* fp = fopen(file, "rb");
    if (!fp) {
        error_setg(&local_err, "Error opening file %s: %d", file, errno);
        error_propagate(errp, local_err);
        return;
    }
    PyRun_SimpleFileEx(fp, file, 1);
    PyObject *err = PyErr_Occurred();
    if (err)
    {
        PyErr_Print();
        error_setg(&local_err, "%s", PyUnicode_AsUTF8(PyObject_Str(err)));
        Py_DECREF(err);
    }

	error_propagate(errp, local_err);

	return;

}

struct module_state {
    PyObject* error;
};

static int myextension_traverse(PyObject *m, visitproc visit, void* arg) {
    Py_VISIT(((struct module_state*)PyModule_GetState(m))->error);
    return 0;
}

static int myextension_clear(PyObject *m) {
    Py_CLEAR(((struct module_state*)PyModule_GetState(m))->error);
    return 0;
}

static PyMethodDef pyToQemu[] = {
    {"get_virtual_memory", python_get_virtual_memory, METH_VARARGS,
     "Access the requested virtual memory."},
    {"set_virtual_memory", python_set_virtual_memory, METH_VARARGS,
     "Set the requested virtual memory with the given data."},
    {"get_physical_memory", python_get_physical_memory, METH_VARARGS,
     "Access the requested physical memory."},
    {"set_physical_memory", python_set_physical_memory, METH_VARARGS,
     "Set the requested physical memory with the given data."},
    {"get_cpu_register", python_get_cpu_register, METH_VARARGS,
     "Access the requested register data."},
    {"set_breakpoint", python_set_breakpoint, METH_VARARGS,
     "Set a breakpoint at the given address."},
    {"clear_breakpoint", python_clear_breakpoint, METH_VARARGS,
     "Set a breakpoint at the given address."},
    {"set_cpu_register", python_set_cpu_register, METH_VARARGS,
     "Set the requested register with the given data."},
    {"get_current_cpu", python_get_current_cpu, METH_VARARGS,
     "Gets the current CPU number."},
    {"get_register_names", python_get_register_names, METH_VARARGS,
     "Gets the names for all registers on the cpu."},
    {"qmp_emit", python_qmp_emit, METH_VARARGS,
     "Calls the QMP emit function."},
    {"qmp_command", python_qmp_command, METH_VARARGS,
     "Send a qmp command."},
    {"continue_vm", python_vm_continue, METH_VARARGS,
     "Continues VM execution."},
    {"singlestep_vm", python_vm_singlestep, METH_VARARGS,
     "Single step vm from breakpoint."},
    {"stop_vm", python_vm_stop, METH_VARARGS,
     "Stops VM execution."},
    {"shutdown_vm", python_vm_shutdown, METH_VARARGS,
     "Shuts down the VM."},
    {"restart_vm", python_vm_restart, METH_VARARGS,
     "Restarts the VM."},
    {"quit_vm", python_vm_quit, METH_VARARGS,
     "Quits VM execution."},
    {"get_vm_state", python_vm_get_state, METH_VARARGS,
     "Returns the current state of the VM."},
    {"ra_add_job", python_ra_add_job, METH_VARARGS,
     "Add work to the rapid analysis queue."},
    {"send_key", python_send_key, METH_VARARGS,
     "Send one keypress of the combined values."},
    {"send_key_string", python_send_key_string, METH_VARARGS,
     "Send succession of keys that correspond to string."},
    {"init_oshandler", python_init_oshandler, METH_VARARGS,
     "Initialize the OS handler. Will use existing OS handler otherwise it will create a new one."},
    {"get_process_vma_list", python_get_process_vma_list, METH_VARARGS,
     "Get a list of the VMA information in tuples."},
    {"get_process_pid_by_name", python_get_process_pid_by_name, METH_VARARGS,
     "Get a pid given the name."},
    {"get_process_pid_by_active", python_get_process_pid_by_active, METH_VARARGS,
     "Get a pid given the active process."},
    {"load_snapshot", python_load_snapshot, METH_VARARGS,
     "Loads a snapshot from the VM."},
    {"save_snapshot", python_save_snapshot, METH_VARARGS,
     "Saves a snapshot from the VM."},
    {"qtimer_create", python_timer_create, METH_VARARGS,
     "Create a timer for periodic notifications."},
    {"qtimer_start", python_timer_start, METH_VARARGS,
     "Start a timer."},
    {"save_screenshot", python_save_screenshot, METH_VARARGS,
     "Save a screenshot of the VM to the specified file path."},
    {"is_kvm_enabled", python_is_kvm_enabled, METH_VARARGS,
     "Returns true when KVM mode is enabled."},
    {"is_tcg_enabled", python_is_tcg_enabled, METH_VARARGS,
     "Returns true when TCG mode is enabled."},
    {"get_snapshots", python_get_snapshots, METH_VARARGS,
     "Returns info for the snapshots in the current block drive."},
    {"get_process_detail_list", python_get_process_detail_list, METH_VARARGS,
     "Get a list of all processes in the guest OS."},
    {"add_command", python_add_command, METH_VARARGS,
     "Add the command to this plugin\'s list of handled commands."},
    {"remove_command", python_remove_command, METH_VARARGS,
     "Removes the command from this plugin\'s list of handled commands."},
    {"command_print", python_command_print, METH_VARARGS,
     "Print to the command console."},
    {"command_pretty_print", python_command_pretty_print, METH_VARARGS,
     "Pretty print to the command console."},
    {"get_process_memory", python_get_process_memory, METH_VARARGS,
     "Access the specified process virtual memory."},
    {"set_process_memory", python_set_process_memory, METH_VARARGS,
     "Set the requested process memory with the given data."},
    {"get_cpu_type", python_get_cpu_type, METH_VARARGS,
     "Get the type as a string for the specified cpu."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_PyQemu",
    NULL,
    sizeof(struct module_state),
    pyToQemu,
    NULL,
    myextension_traverse,
    myextension_clear,
    NULL
};

PyMODINIT_FUNC PyInit__PyQemu(void);

PyMODINIT_FUNC PyInit__PyQemu(void)
{
    return PyModule_Create(&moduledef);
}

static bool python_load_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    // Variables
    PluginObjectClass *poc = PLUGIN_OBJECT_GET_CLASS(opaque);
    PyObject *args_list, *error, *plugin_load;
    PyObject *module_loader;

    PythonInterface *p = PYTHON(opaque);

    strncpy(p->script_path, path, sizeof(p->script_path));

    // Derive the module name from the script name.
    char *module_name = g_strdup(path);
    // Remove the file extension
    char *file_ext = strrchr(module_name, '.');
    if(!strcasecmp(file_ext, ".pyc")){
        module_loader = bytecode_loader;
    }else if(!strcasecmp(file_ext, ".py")){
        module_loader = script_loader;
    }else{
        error_printf("Unable to identify loader for python file!\n\n");
        return false;
    }
    if(file_ext) { *file_ext = '\0'; }
    // Replace dash and colon with underscore
    char *rep_char = NULL;
    while((rep_char = strrchr(module_name, '-')) != NULL){
        *rep_char = '_';
    }
    while((rep_char = strrchr(module_name, ':')) != NULL){
        *rep_char = '_';
    }
    char* module_base = strrchr(module_name, '/');
    module_base = module_base ? module_base + 1 : module_name;

    strncpy(p->instance_name, module_base, sizeof(p->instance_name));
    g_free(module_name);

    // We'll use the module name we generated and the 
    // file path passed in to load a Python module from a
    // given source file.
    if (p->instance_name && p->script_path)
    {
        // Build args to the load_source function
        // This is a module name (we made one up) and
        // the path to the script. 
        args_list = Py_BuildValue("UU", p->instance_name, p->script_path);
        python_error_check(args_list);
        
        // Now we can call the load_source function
        p->script_module = PyObject_CallObject(module_loader, args_list);
        python_call_check();
        Py_DECREF(args_list);

        // Error check
        if (!p->script_module)
        {
            // Check the nature of the error
            error = PyErr_Occurred();

            // Check if we have an error and attempt to print it.
            if (error)
            {
                PyErr_Print();
            }

            // We have a error and need to stop
            return false;
        }

        args_list = Py_BuildValue("sz", path, poc->get_args(opaque));
        if (!args_list)
        {
            // Check the nature of the error
            error = PyErr_Occurred();

            // Check if we have an error and attempt to print it.
            if (error)
            {
                PyErr_Print();
            }

            return false;
        }

        plugin_load = PyObject_GetAttrString(p->script_module, "on_plugin_load");
        if (!plugin_load){
            Py_DECREF(args_list);
            return false;
        }

        if(!PyCallable_Check(plugin_load)) {
            Py_DECREF(args_list);
            Py_DECREF(plugin_load);
            return false;
        }
    
        PyObject_CallObject(plugin_load, args_list);
        python_call_check();
        Py_DECREF(args_list);
        Py_DECREF(plugin_load);
    }
    else
    {
        // Check the nature of the error
        error = PyErr_Occurred();

        // Check if we have an error and attempt to print it.
        if (error)
        {
            PyErr_Print();
        }

        return false;
    }

    return true;
}

static bool python_object_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    return python_load_plugin(opaque, path, opts);
}

static bool python_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    // Set the QEMU object variables
    const char *script = qemu_opt_get(opts, "script");
    if(!script){
        error_printf("Please specify a script to run!\n\n");
        abort();
    }

    return python_load_plugin(opaque, script, opts);
}

static void python_set_callbacks(void *opaque, PluginCallbacks *callbacks)
{
    // Variables
    PythonInterface *p = PYTHON(opaque);

    // We want to try to load the python function
    p->py_callbacks.ra_start = PyObject_GetAttrString(p->script_module, "on_ra_start");
    
    // If the python function loaded, then we will populate the callback.
    if (p->py_callbacks.ra_start && PyCallable_Check(p->py_callbacks.ra_start))
    {
        callbacks->on_ra_start = python_on_ra_start;
    }
    else
    {
        // This isn't a fatal error.
        PyErr_Clear();
    }
 
    // We will repeat this process for all the callbacks
    p->py_callbacks.ra_stop = PyObject_GetAttrString(p->script_module, "on_ra_stop");
    if (p->py_callbacks.ra_stop && PyCallable_Check(p->py_callbacks.ra_stop))
    {
        callbacks->on_ra_stop = python_on_ra_stop;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.ra_idle = PyObject_GetAttrString(p->script_module, "on_ra_idle");
    if (p->py_callbacks.ra_idle && PyCallable_Check(p->py_callbacks.ra_idle))
    {
        callbacks->on_ra_idle = python_on_ra_idle;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.get_ra_report_type = PyObject_GetAttrString(p->script_module, "get_ra_report_type");
    if (p->py_callbacks.get_ra_report_type && PyCallable_Check(p->py_callbacks.get_ra_report_type))
    {
        callbacks->get_ra_report_type = python_get_ra_report_type;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.breakpoint = PyObject_GetAttrString(p->script_module, "on_breakpoint");
    if (p->py_callbacks.breakpoint && PyCallable_Check(p->py_callbacks.breakpoint))
    {
        callbacks->on_breakpoint = python_on_breakpoint;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.exception = PyObject_GetAttrString(p->script_module, "on_exception");
    if (p->py_callbacks.exception && PyCallable_Check(p->py_callbacks.exception))
    {
        callbacks->on_exception = python_on_exception;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.execute_instruction = PyObject_GetAttrString(p->script_module, "on_execute_instruction");
    if (p->py_callbacks.execute_instruction && PyCallable_Check(p->py_callbacks.execute_instruction))
    {
        callbacks->on_execute_instruction = python_on_execute_instruction;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.memory_write = PyObject_GetAttrString(p->script_module, "on_memory_write");
    if (p->py_callbacks.memory_write && PyCallable_Check(p->py_callbacks.memory_write))
    {
        callbacks->on_memory_write = python_on_memory_write;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.memory_read = PyObject_GetAttrString(p->script_module, "on_memory_read");
    if (p->py_callbacks.memory_read && PyCallable_Check(p->py_callbacks.memory_read))
    {
        callbacks->on_memory_read = python_on_memory_read;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.on_syscall = PyObject_GetAttrString(p->script_module, "on_syscall");
    if (p->py_callbacks.on_syscall && PyCallable_Check(p->py_callbacks.on_syscall))
    {
        callbacks->on_syscall = python_on_syscall;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.on_syscall_exit = PyObject_GetAttrString(p->script_module, "on_syscall_exit");
    if (p->py_callbacks.on_syscall_exit && PyCallable_Check(p->py_callbacks.on_syscall_exit))
    {
        callbacks->on_syscall_exit = python_on_syscall_exit;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.vm_change_state_handler = PyObject_GetAttrString(p->script_module, "on_vm_change_state");
    if (p->py_callbacks.vm_change_state_handler && PyCallable_Check(p->py_callbacks.vm_change_state_handler))
    {
        callbacks->change_state_handler = python_change_state_handler;
    }
    else
    {
        PyErr_Clear();
    }    

    p->py_callbacks.on_interrupt = PyObject_GetAttrString(p->script_module, "on_interrupt");
    if (p->py_callbacks.on_interrupt && PyCallable_Check(p->py_callbacks.on_interrupt))
    {
        callbacks->on_interrupt = python_on_interrupt;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.on_packet_recv = PyObject_GetAttrString(p->script_module, "on_packet_recv");
    if (p->py_callbacks.on_packet_recv && PyCallable_Check(p->py_callbacks.on_packet_recv))
    {
        callbacks->on_packet_recv = python_on_packet_recv;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.on_packet_send = PyObject_GetAttrString(p->script_module, "on_packet_send");
    if (p->py_callbacks.on_packet_send && PyCallable_Check(p->py_callbacks.on_packet_send))
    {
        callbacks->on_packet_send = python_on_packet_send;
    }
    else
    {
        PyErr_Clear();
    }

    p->py_callbacks.on_vm_startup = PyObject_GetAttrString(p->script_module, "on_vm_startup");
    if (p->py_callbacks.on_vm_startup)
    {
        callbacks->on_vm_startup = python_on_vm_startup;
    }
    else
    {
        PyErr_Clear();   
    }

    p->py_callbacks.on_vm_shutdown = PyObject_GetAttrString(p->script_module, "on_vm_shutdown");
    if (p->py_callbacks.on_vm_shutdown)
    {
        callbacks->on_vm_shutdown = python_on_vm_shutdown;
    }
    else
    {
        PyErr_Clear();   
    }

    p->py_callbacks.on_command = PyObject_GetAttrString(p->script_module, "on_command");
    if (p->py_callbacks.on_command)
    {
        callbacks->on_command = python_on_command;
    }
    else
    {
        PyErr_Clear();   
    }
}

// Object setup: constructor
static void python_iface_initfn(Object *obj)
{
    PythonInterface *p = PYTHON(obj);

    // Make sure that we have no garbage here
    p->script_module = NULL;
    p->py_callbacks.ra_start = NULL;
    p->py_callbacks.ra_stop = NULL;
    p->py_callbacks.ra_idle = NULL;
    p->py_callbacks.get_ra_report_type = NULL;
    p->py_callbacks.execute_instruction = NULL;
    p->py_callbacks.exception = NULL;
    p->py_callbacks.breakpoint = NULL;
    p->py_callbacks.memory_read = NULL;
    p->py_callbacks.memory_write = NULL;
    p->py_callbacks.on_syscall = NULL;
    p->py_callbacks.on_syscall_exit = NULL;
    p->py_callbacks.vm_change_state_handler = NULL;
    p->py_callbacks.on_interrupt = NULL;
    p->py_callbacks.on_packet_recv = NULL;
    p->py_callbacks.on_packet_send = NULL;
    p->py_callbacks.on_vm_shutdown = NULL;
    p->py_callbacks.on_command = NULL;

}

// Object setup: destructor
static void python_iface_finalize(Object *obj)
{
    PythonInterface *p = PYTHON(obj);

    // If the module is set up
    // we want to deref it and nullify the pointer
    if (p->script_module)
    {
        Py_DECREF(p->script_module);
        p->script_module = NULL;
    }

    // We want to unref all the callbacks
    if (p->py_callbacks.ra_start)
    {
        Py_DECREF(p->py_callbacks.ra_start);
        p->py_callbacks.ra_start = NULL;
    }
    if (p->py_callbacks.ra_stop)
    {
        Py_DECREF(p->py_callbacks.ra_stop);
        p->py_callbacks.ra_stop = NULL;
    }
    if (p->py_callbacks.ra_idle)
    {
        Py_DECREF(p->py_callbacks.ra_idle);
        p->py_callbacks.ra_idle = NULL;
    }
    if (p->py_callbacks.get_ra_report_type)
    {
        Py_DECREF(p->py_callbacks.get_ra_report_type);
        p->py_callbacks.get_ra_report_type = NULL;
    }
    if (p->py_callbacks.execute_instruction)
    {
        Py_DECREF(p->py_callbacks.execute_instruction);
        p->py_callbacks.execute_instruction = NULL;
    }
    if (p->py_callbacks.exception)
    {
        Py_DECREF(p->py_callbacks.exception);
        p->py_callbacks.exception = NULL;
    }
    if (p->py_callbacks.breakpoint)
    {
        Py_DECREF(p->py_callbacks.breakpoint);
        p->py_callbacks.breakpoint = NULL;
    }
    if (p->py_callbacks.memory_read)
    {
        Py_DECREF(p->py_callbacks.memory_read);
        p->py_callbacks.memory_read = NULL;
    }
    if (p->py_callbacks.memory_write)
    {
        Py_DECREF(p->py_callbacks.memory_write);
        p->py_callbacks.memory_write = NULL;
    }
    if (p->py_callbacks.on_syscall)
    {
        Py_DECREF(p->py_callbacks.on_syscall);
        p->py_callbacks.on_syscall = NULL;
    }
    if (p->py_callbacks.vm_change_state_handler)
    {
        Py_DECREF(p->py_callbacks.vm_change_state_handler);
        p->py_callbacks.vm_change_state_handler = NULL;
    }
    if (p->py_callbacks.on_interrupt)
    {
        Py_DECREF(p->py_callbacks.on_interrupt);
        p->py_callbacks.on_interrupt = NULL;
    }
    if (p->py_callbacks.on_packet_recv)
    {
        Py_DECREF(p->py_callbacks.on_packet_recv);
        p->py_callbacks.on_packet_recv = NULL;
    }
    if (p->py_callbacks.on_packet_send)
    {
        Py_DECREF(p->py_callbacks.on_packet_send);
        p->py_callbacks.on_packet_send = NULL;
    }
    if (p->py_callbacks.on_vm_shutdown)
    {
        Py_DECREF(p->py_callbacks.on_vm_shutdown);
        p->py_callbacks.on_vm_shutdown = NULL;
    }
    if (p->py_callbacks.on_command)
    {
        Py_DECREF(p->py_callbacks.on_command);
        p->py_callbacks.on_command = NULL;
    }
}

// Object setup: class constructor 
static void python_iface_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    p_klass->init_plugin = python_init_plugin;
    p_klass->set_callbacks = python_set_callbacks;
}

// Object setup: Object info
static TypeInfo python_iface_info = {
    .parent = TYPE_PLUGIN_OBJECT,
    .name = TYPE_PYTHON,
    .instance_size = sizeof(PythonInterface),
    .instance_init = python_iface_initfn,
    .instance_finalize = python_iface_finalize,
    .class_init = python_iface_class_init,
    .class_size = sizeof(PythonInterfaceClass)
};

static void python_object_iface_class_init(ObjectClass *klass,
                              void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    // We use a slightly different initialization function
    p_klass->init_plugin = python_object_init_plugin;
}

// Object setup: Object info
static TypeInfo python_plugin_iface_info = {
    .parent = TYPE_PYTHON,
    .name = TYPE_PYTHON_PLUGIN,
    .instance_size = sizeof(PythonPluginObject),
    .instance_init = NULL,
    .instance_finalize = NULL,
    .class_init = python_object_iface_class_init,
    .class_size = sizeof(PythonPluginObjectClass)
};

// Setup options to configure the plugin
static QemuOptsList qemu_python_iface_opts = {
    .name = PYTHON_OPTS,
    .implied_opt_name = "script",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_python_iface_opts.head),
    .desc = {
        {
            .name = "script",
            .type = QEMU_OPT_STRING,
            .help = "Provides the plugin will execute.",
        },
        { NULL }
    },
};

// These functions are required to setup the plugins
bool plugin_setup(void *plugin, const char *path)
{
    PyObject *import_module_name, *import_module, *error, *module;

    if( path )
    {
        char *path_dir = g_strdup(path);
        char *file_name = strrchr(path_dir, '/');
        if(file_name){
            *file_name = '\0';
            file_name++;
        }else{
            printf("Malformed path %s!", path);
            return false;
        }

        Py_SetProgramName((wchar_t*)g_utf8_to_ucs4_fast(path, strlen(path), NULL));

        char *this_pp=getenv("PYTHONPATH");
        if( this_pp ){
            char *new_pp = g_alloca(strlen(this_pp) + strlen(path_dir) + strlen(PYQEMU_FOLDER) + 3);
            strcpy(new_pp, this_pp);
            strcat(new_pp, ":");
            strcat(new_pp, path_dir);
            strcat(new_pp, "/");
            strcat(new_pp, PYQEMU_FOLDER);
            setenv("PYTHONPATH", new_pp, 1);
        }else{
            char *new_pp = g_alloca(strlen(path_dir) + strlen(PYQEMU_FOLDER) + 2);
            strcpy(new_pp, path_dir);
            strcat(new_pp, "/");
            strcat(new_pp, PYQEMU_FOLDER);
            setenv("PYTHONPATH", new_pp, 1);
        }

        g_free(path_dir);
    }

    // This is a work around for a linking issue with libraries
    // that python uses.
    char buf[50];
    void *python_lib = NULL;
    snprintf(buf, sizeof(buf), "libpython%d.%dm.so", PY_MAJOR_VERSION, PY_MINOR_VERSION);
    python_lib = dlopen(buf, RTLD_LAZY | RTLD_GLOBAL);
    if (!python_lib)
    {
        snprintf(buf, sizeof(buf), "libpython%d.%d.so", PY_MAJOR_VERSION, PY_MINOR_VERSION);
        python_lib = dlopen(buf, RTLD_LAZY | RTLD_GLOBAL);
        if (!python_lib)
        {
            printf("Python-Interface: Could not open python libraries %s\n", buf);
            return false;
        }
    }

    // Initialize the Python environment
    PyImport_AppendInittab("_PyQemu", PyInit__PyQemu);
    Py_Initialize();
    module = PyImport_ImportModule("_PyQemu");

    char stp_vm_err_name[] = "_PyQemu.StopVMError";
    stop_vm_error = PyErr_NewException(stp_vm_err_name, NULL, NULL);
    PyObject *err = PyErr_Occurred();
    if (err)
    {
        PyErr_Print();
    }    
    Py_INCREF(stop_vm_error);
    PyModule_AddObject(module, "error", stop_vm_error);

    char ctn_vm_err_name[] = "_PyQemu.ContinueVMError";
    continue_vm_error = PyErr_NewException(ctn_vm_err_name, NULL, NULL);
    Py_INCREF(continue_vm_error);
    PyModule_AddObject(module, "error", continue_vm_error);

    // We want to load the imp module so that we can load a source file
    import_module_name = PyUnicode_FromString("imp");

    // Error checking
    if (import_module_name)
    {
        // Get the imp module
        import_module = PyImport_Import(import_module_name);

        // More error checking
        if (import_module)
        {
            // We will stach this function in a global variable.
            // This is because we only want to load this function once.
            script_loader = PyObject_GetAttrString(import_module, "load_source");

            if (!PyCallable_Check(script_loader)) {
                PyErr_Format(PyExc_TypeError,
                            "attribute of type '%.200s' is not callable",
                            Py_TYPE(script_loader)->tp_name);
                return false;
            }

            // We will stach this function in a global variable.
            // This is because we only want to load this function once.
            bytecode_loader = PyObject_GetAttrString(import_module, "load_compiled");

            if (!PyCallable_Check(bytecode_loader)) {
                PyErr_Format(PyExc_TypeError,
                            "attribute of type '%.200s' is not callable",
                            Py_TYPE(bytecode_loader)->tp_name);
                return false;
            }

            // We are done with the imp module object
            Py_DECREF(import_module);
        }
        else
        {
            // Check the nature of the error
            error = PyErr_Occurred();

            // Check if we have an error and attempt to print it.
            if (error)
            {
                PyErr_Print();
            }  

            // We have an error and need to stop
            return false;
        }
        
        // We are done with the imp module name
        Py_DECREF(import_module_name);
    }
    else
    {
        // Check the nature of the error
        error = PyErr_Occurred();

        // Check if we have an error and attempt to print it.
        if (error)
        {
            PyErr_Print();
        }

        // We have an error and need to stop 
        return false;
    }

    // Load the data required by QEMU
    qmp_commands =  qmp_init_plugin_cmd(python_qmp_init_marshal);

    qemu_plugin_register_type(plugin, &python_iface_info);
    qemu_plugin_register_options(plugin, &qemu_python_iface_opts);
    qemu_plugin_register_loader(plugin, "*.@(py|pyc)", &python_plugin_iface_info);

    return true;
}
