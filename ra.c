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
#include "qemu/units.h"
#include "qemu-common.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/help_option.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/sockets.h"
#include "monitor/qdev.h"
#include "migration/snapshot.h"
#include "rsave-tree.h"
#include "migration/ram_rapid.h"
#include "hw/boards.h"
#include "racomms/interface.h"
#include "migration/misc.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qpointer.h"
#include "oshandler/oshandler.h"
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "ra.h"

#define RAPID_ANALYSIS_CHANNEL_POOL_INIT   ((uint64_t)400ul * MiB)
#define RAPID_ANALYSIS_REFERENCE_POOL_INIT ((uint64_t)400ul * MiB)
#define RAPID_ANALYSIS_MAX_INS     (512)
#define RAPID_ANALYSIS_ILIMIT_INIT (1000)
#define RAPID_ANALYSIS_MSGSZ_LIMIT_INIT ((uint64_t) 0)
#define RAPID_ANALYSIS_ISTEP_INIT  (0)
#define RAPID_ANALYSIS_OPTS        ("rapidanalysis")
#define RAPID_ANALYSIS_TIMEOUT     (0)

static RSaveTree *global_rst = NULL;

// Error state variables
static uint32_t error_id = ERROR_STATE_NONE;
static uint64_t error_loc = 0;
static char *error_text = NULL;

QemuOptsList qemu_rapidanalysis_opts = {
    .name = RAPID_ANALYSIS_OPTS,
    .implied_opt_name = "file",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_rapidanalysis_opts.head),
    .desc = {
        {
            .name = "listen",
            .type = QEMU_OPT_STRING,
            .help = "Listen for a controller that supplies jobs to rapid analysis mode",
        }, {
            .name = "connect",
            .type = QEMU_OPT_STRING,
            .help = "Connect to a controller that supplies jobs to rapid analysis mode",
        }, {
            .name = "file",
            .type = QEMU_OPT_STRING,
            .help = "Sets the rapid analysis image to be loaded",
        }, {
            .name = "mode",
            .type = QEMU_OPT_STRING,
            .help = "Use a preset mode that defines a collection of options",
        }, {
            .name = "istep",
            .type = QEMU_OPT_NUMBER,
            .help = "Sets the number of instructions to be executed before\n"
                    "taking a rapid snapshot. Set to zero for optimal performance.",
        }, {
            .name = "ilimit",
            .type = QEMU_OPT_NUMBER,
            .help = "Sets the number of instructions to be executed before\n"
                    "ending analysis. Set to zero for no limit.",
        }, {
            .name = "notrace",
            .type = QEMU_OPT_BOOL,
            .help = "Skips collecting a system trace\n",
        }, {
            .name = "notree",
            .type = QEMU_OPT_BOOL,
            .help = "Skips the building of the tree, inherently also skips saving state\n",
        }, {
            .name = "nosave",
            .type = QEMU_OPT_BOOL,
            .help = "Do no automatically save final states back to the vmstate file\n",
        }, {
            .name = "noblocks",
            .type = QEMU_OPT_BOOL,
            .help = "Skips dumping disk data to the blocks file\n",        
        }, {
            .name = "hash",
            .type = QEMU_OPT_STRING,
            .help = "Hash of state to use for initialization\n",
        }, {
            .name = "chnl_pool",
            .type = QEMU_OPT_SIZE,
            .help = "Initial size of global memory pool for memory channel\n",
        }, {
            .name = "chnl_limit",
            .type = QEMU_OPT_SIZE,
            .help = "Size limit for the global memory channel pool (use zero for no limit)\n",
        }, {
            .name = "os",
            .type = QEMU_OPT_STRING,
            .help = "Enables the operating system introspection support\n",
        }, {
            .name = "process",
            .type = QEMU_OPT_STRING,
            .help = "Target the specified process when performing dynamic analysis\n",
        }, {
            .name = "msg_limit",
            .type = QEMU_OPT_SIZE,
            .help = "Puts an upper bound on the size of an outgoing message\n",
        }, {
            .name = "ints",
            .type = QEMU_OPT_BOOL,
            .help = "Enable or disable interrupts. Disables some CPU/OS functions such as IO and task swapping\n",
        }, {
            .name = "ref_pool",
            .type = QEMU_OPT_SIZE,
            .help = "Size of global memory pool for the reference cache\n",
        },
        { /* end of list */ }
    },
};

static void ra_sigalrm_handler(int signal)
{
    rapid_analysis_set_error(ERROR_STATE_TIMEOUT, 0, "Job Timeout");
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        int interrupt_request = cpu->interrupt_request;
        CPUClass *cc = CPU_GET_CLASS(cpu);
        if (cc && 
            cc->cpu_exec_interrupt &&
            cc->cpu_exec_interrupt(cpu, interrupt_request))
        {
            cpu->exception_index = -1;
            qemu_cpu_kick(cpu);
        }       
    }
}

bool is_rapid_analysis_active(void)
{
    return !!global_rst;
}

bool rapid_analysis_awaiting_work(CPUState *cpu)
{
    return (global_rst != NULL) && !global_rst->has_work;
}

bool rapid_analysis_load_work(CPUState *cpu)
{
    RSaveTree *rst = rapid_analysis_get_instance(cpu);

    return rst && load_work(cpu, rst);
}

void rapid_analysis_end_work(CPUState *cpu, bool send_report)
{
    RSaveTree *rst = rapid_analysis_get_instance(cpu);

    if (rst)
    {
        vm_stop(RUN_STATE_PAUSED);

        close_work(rst, cpu, rst->active_hash, send_report);
    }
}

void rapid_analysis_increment_analysis(CPUState *cpu, TranslationBlock *tb)
{
    RSaveTree *rst = rapid_analysis_get_instance(cpu);

    if( rst ) {
        increment_snapshot_rsave(cpu, rst, tb);
    }
}

QemuOpts *rapid_analysis_parse(const char *optstr)
{
    return qemu_opts_parse_noisily(qemu_find_opts(RAPID_ANALYSIS_OPTS), optstr, true);
}

RSaveTree *rapid_analysis_get_instance(CPUState *cpu)
{
    if( cpu ) {
        return RSAVE_TREE(cpu->rapid_analysis);
    }

    return global_rst;
}

void rapid_analysis_set_configuration(CommsRequestConfigMsg *req, CommsQueue *q)
{
    if(!global_rst){
        error_report("Error attempting to get tree from rapid analysis");
        return;
    }

    if( req->valid_settings & CONFIG_JOB_REPORT_MASK ){
        global_rst->report_mask = req->report_mask;
    }
    if( req->valid_settings & CONFIG_JOB_TIMEOUT_MASK ){
        // We use the job timeout to set the actual alarm
        // The job timer will be reset to the config timeout after 
        // each job.
        global_rst->config_timeout = req->timeout;
    }

    // Respond with the new settings.
    CommsMessage *out = racomms_create_config_response_msg(req->queue);
    CommsResponseConfigMsg *config_out = (CommsResponseConfigMsg *) MSG_OFFSET(out, sizeof(CommsMessage));
    config_out->report_mask = global_rst->report_mask;
    config_out->timeout = global_rst->config_timeout;

    CommsResultsItem *work_results = g_new(CommsResultsItem, 1);
    work_results->msg = out;
    queue_push_results(q, work_results);
}

void rapid_analysis_send_tree(CommsRequestRapidSaveTreeMsg *req, CommsQueue *q)
{
    const QDictEntry *entry;
    QList *insn_state;
    const char *insn_label;
    QListEntry *e;
    uint64_t insn_offset;
    uint64_t node_hdr_offset;
    uint64_t node_state_offset;
    VMStateIndexEntry *se;

    if(!global_rst){
        error_report("Error attempting to get tree from rapid analysis");
        return;
    }

    RSaveTreeClass *rcc = RSAVE_TREE_GET_CLASS(global_rst);

    rcc->lock_tree(global_rst);

    CommsMessage *msg = racomms_create_rapid_save_tree_response_msg(req->queue, req->job_id);

    for (entry = qdict_first(global_rst->node_reference); entry;
         entry = qdict_next(global_rst->node_reference, entry))
    {
        CommsResponseRapidSaveTreeMsg *rst_msg = (CommsResponseRapidSaveTreeMsg*)(msg + 1);
        rst_msg->num_insns++;

        insn_label = qdict_entry_key(entry);
        insn_state = qobject_to(QList, qdict_entry_value(entry));
        insn_offset = msg->size;
        msg = racomms_msg_rapid_save_tree_put_InstructionEntry(msg, insn_label);

        QLIST_FOREACH_ENTRY(insn_state, e) {
            QPointer *node_ptr = qobject_to(QPointer, qlist_entry_obj(e));
            RSaveTreeNode *node = qpointer_get_pointer(node_ptr);

            if(req->job_id == INVALID_JOB || node->job_id == req->job_id)
            {
                // Get our initial instruction entry pointer
                CommsResponseRapidSaveTreeInstructionEntry *insn_entry = MSG_OFFSET(msg, insn_offset);
                insn_entry->num_nodes++;

                node_hdr_offset = msg->size;
                msg = racomms_msg_rapid_save_tree_put_NodeHeader(msg,
                        node->timestamp,
                        node->instruction_number,
                        node->cpu_exception_index,
                        node->job_id);

                // Get our initial node header entry pointer
                CommsResponseRapidSaveTreeNodeHeader *node_hdr = MSG_OFFSET(msg, node_hdr_offset);
                // Set the index offset from the node header
                node_hdr->index_offset = msg->size - node_hdr_offset;

                QLIST_FOREACH(se, &node->device_list, next) {
                    node_hdr->num_indices++;
                    msg = racomms_msg_rapid_save_tree_put_NodeIndex(msg,
                            se->idstr,
                            se->instance_id,
                            se->section_id,
                            se->offset);
                    // Update our node header entry pointer in case of a realloc adjustment
                    node_hdr = MSG_OFFSET(msg, node_hdr_offset);
                }

                // Set the state offset from the node header
                node_hdr->state_offset = msg->size - node_hdr_offset;

                // Collect the size of the memory channel
                MemoryChannelClass *mcc = MEMORY_CHANNEL_GET_CLASS(node->vm_state);
                size_t state_size = mcc->get_size(node->vm_state);

                // Pre-allocate a node state big enough to hold the memory channel
                node_state_offset = msg->size;
                msg = racomms_msg_rapid_save_tree_put_NodeState(msg, state_size);
                CommsResponseRapidSaveTreeNodeState *node_state = MSG_OFFSET(msg, node_state_offset);

                // Proceed to copy the memory channel to the node state
                size_t total = 0;
                while(state_size > total){
                    ssize_t r = mcc->get_buffer(node->vm_state, &node_state->state[total], total, state_size - total);
                    if( r < 0 ){
                        // some error
                        error_report("Error attempting to get node vm state");
                        break;
                    }
                    total += r;
                }
            }
        }

        // There is a potential issue here, we may be writing the
        // last item in the list while exceeding the limit of a message size.
        // We may actually send the complete message while indicating that there
        // is more data coming. Try checking if this is the last item in the loop.
        if (global_rst->msgsz_limit && msg->size > global_rst->msgsz_limit && qdict_next(global_rst->node_reference, entry))
        {
            // Set the incomplete message flag then 
            // send the message.
            msg->has_next_message = 1;
            
            CommsResultsItem *work_results = g_new(CommsResultsItem, 1);
            work_results->msg = msg;
            queue_push_results(q, work_results);

            // If we reset our pointers, then
            // we should be able to continue on our loop
            msg = racomms_create_rapid_save_tree_response_msg(req->queue, req->job_id);
        }
    }

    CommsResultsItem *work_results = g_new(CommsResultsItem, 1);
    work_results->msg = msg;
    queue_push_results(q, work_results);
    
    rcc->unlock_tree(global_rst);
}

void rapid_analysis_accel_init(QemuOpts *ra_opts, QemuOpts *accel_opts, Error **errp)
{
    QemuOpts *accelopts = qemu_opts_create(qemu_find_opts("accel"), NULL, 0, errp);
    if( !accelopts ){
        error_report("Error building accel options for Rapid Analysis");
        exit(1);
    }

    qemu_opt_set(accelopts, "accel", "tcg", errp);
    qemu_opt_set(accelopts, "thread", "single", errp);
    qemu_tcg_configure(accelopts, errp);
}

void rapid_analysis_drive_init(QemuOpts *ra_opts, MachineState *machine)
{
    const char *filename;
    Error *err = NULL;
    MachineClass *mc = MACHINE_GET_CLASS(machine);
    QemuOpts *devopts = qemu_opts_create(qemu_find_opts("drive"), NULL, 0, &err);
    if( !devopts ){
        error_report("Error building drive options for Rapid Analysis");
        exit(1);
    }

    filename = qemu_opt_get(ra_opts, "file");
    if (!filename) {
        error_report("No rapid save file specified");
        error_printf("Use file=[*.rsave] to specify a rapid anlysis file");
        exit(1);
    }

    qemu_opt_set(devopts, "format", "qcow2", &err);
    qemu_opt_set(devopts, "snapshot", "on", &err);
    qemu_opt_set(devopts, "file", filename, &err);
    drive_new(devopts, mc->block_default_type, &err);
    qemu_opts_del(devopts);
}

static void string_to_hash(const char *str, SHA1_HASH_TYPE hash)
{
    uint8_t len = 0, pos = 0;
    char part[256];
    uint32_t partv;

    while(*str && (pos < sizeof(SHA1_HASH_TYPE)/sizeof(uint32_t)))
    {
        if(isalnum(*str)){
            part[len] = *str;
            len++;
        }
        if(len == 8){
            part[len] = '\0';
            len = 0;
            partv = strtol(part, NULL, 16);
            memcpy(&hash[pos], &partv, sizeof(uint32_t));
            pos++;
        }
        str++;
    }
}

void rapid_analysis_init(QemuOpts *ra_opts, MachineState *machine)
{
    CPUState *cpu;
    uint64_t num_steps, step_limit, channel_pool_size, message_size_limit, reference_pool_size, channel_pool_limit, timeout;
    bool skip_tree, skip_trace, skip_save, interrupts, skip_blocks;
    const char *filename;
    const char *ctrl;
    const char *osname;
    const char *process;
    const char *hashstring;
    const char *execmode;
    SHA1_HASH_TYPE *hash = NULL;
    Error *err = NULL;
    RSaveTreeClass *rcc = NULL;
    int ctrl_fd = 0;
    bool use_connect = false;

    if(global_rst){
        error_report("Error attempting to reinitialize rapid analysis");
        exit(1);
    }

    if(QTAILQ_FIRST(&cpus) != QTAILQ_LAST(&cpus)){
        error_report("Error rapid analysis doesn't support multiple processors... yet...");
        exit(1);
    }

    ram_rapid_blocks_init();

    global_rst = rsave_tree_create();
    rcc = RSAVE_TREE_GET_CLASS(global_rst);

	signal(SIGALRM, ra_sigalrm_handler);

    ctrl = qemu_opt_get(ra_opts, "listen");
    if (!ctrl) {
        ctrl = qemu_opt_get(ra_opts, "connect");
        if (ctrl) {
            use_connect = true;
        }
    }

    if( ctrl ) {
        SocketAddress *saddr = socket_parse(ctrl, &err);
        if (err) {
            error_propagate(&err, err);
            error_report("Could not parse supplied controller address");
            error_printf("Use listen=ip:port or connect=ip:port (X.X.X.X:1234) to specify a controller server\n");
            exit(1);
        }
        if (use_connect) {
            ctrl_fd = socket_connect(saddr, &err);
        }else{
            ctrl_fd = socket_listen(saddr, &err);
        }
        if (err) {
            error_report("Failed to communicate with controller");
            error_printf("Use listen=ip:port or connect=ip:port (X.X.X.X:1234) to specify a controller server\n");
            exit(1);
        }
        global_rst->send_to_queue = true;
    }else{
        global_rst->send_to_queue = false;
    }

    racomms_queue_start(1, ctrl_fd, &err);
    if (err) {
        error_propagate(&err, err);
        error_report("Could not start rapid analysis queue");
        exit(1);
    }

    num_steps = qemu_opt_get_number(ra_opts, "istep", RAPID_ANALYSIS_ISTEP_INIT);
    message_size_limit = qemu_opt_get_size(ra_opts, "msg_limit", RAPID_ANALYSIS_MSGSZ_LIMIT_INIT);
    step_limit = qemu_opt_get_number(ra_opts, "ilimit", RAPID_ANALYSIS_ILIMIT_INIT);
    channel_pool_size = qemu_opt_get_size(ra_opts, "chnl_pool", RAPID_ANALYSIS_CHANNEL_POOL_INIT);
    channel_pool_limit = qemu_opt_get_size(ra_opts, "chnl_limit", channel_pool_size);
    reference_pool_size = qemu_opt_get_size(ra_opts, "ref_pool", RAPID_ANALYSIS_REFERENCE_POOL_INIT);
    skip_trace = qemu_opt_get_bool(ra_opts, "notrace", false);
    skip_tree = qemu_opt_get_bool(ra_opts, "notree", false);
    skip_save = qemu_opt_get_bool(ra_opts, "nosave", false);
    interrupts = qemu_opt_get_bool(ra_opts, "ints", true);
    skip_blocks = qemu_opt_get_bool(ra_opts, "noblocks", false);
    timeout =  qemu_opt_get_number(ra_opts, "timeout", RAPID_ANALYSIS_TIMEOUT);
    execmode = qemu_opt_get(ra_opts, "mode");

    if( num_steps > RAPID_ANALYSIS_MAX_INS ){
        error_report("Too many instructions per incremental snapshot");
        error_printf("Use %d or fewer instructions\n", RAPID_ANALYSIS_MAX_INS);
        exit(1);
    }

    global_rst->istep = num_steps;
    global_rst->ilimit = step_limit;
    global_rst->msgsz_limit = message_size_limit;
    global_rst->skip_save = skip_save;
    global_rst->skip_tree = skip_tree;
    global_rst->skip_trace = skip_trace;
    global_rst->skip_blocks = skip_blocks;
    global_rst->enable_interrupts = interrupts;
    global_rst->config_timeout = timeout;
    global_rst->job_timeout = timeout;

    if(execmode && strncmp(execmode, "basic", 5)){
        global_rst->enable_interrupts = false;
        global_rst->skip_blocks = true;
        global_rst->skip_save = true;
        global_rst->skip_tree = true;
        global_rst->skip_trace = true;
    }

    rcc->init_ram_cache(global_rst, reference_pool_size, &err);
    if (err) {
        error_propagate(&err, err);
        error_report("Cannot setup RAM cache");
        exit(1);
    }
    memory_channel_alloc_pool(channel_pool_size, channel_pool_limit);

    hashstring = qemu_opt_get(ra_opts, "hash");
    if(hashstring) {
        hash = g_new0(SHA1_HASH_TYPE,1);
        string_to_hash(hashstring, *hash);
    }

    filename = qemu_opt_get(ra_opts, "file");
    if (!filename) {
        error_report("No rapid save file specified");
        error_printf("Use file=[*.rsave] to specify a rapid anlysis file");
        exit(1);
    }
    strncpy(global_rst->backing_file_path, filename, sizeof(global_rst->backing_file_path)-1);
    global_rst->backing_file_path[sizeof(global_rst->backing_file_path)-1] = '\0';

    CPU_FOREACH(cpu)
    {
        cpu->rapid_analysis = OBJECT(global_rst);
    }

    load_snapshot_rsave(filename, hash, &err);
    if (err) {
        error_report_err(err);
        exit(1);
    }

    osname = qemu_opt_get(ra_opts, "os");
    if (osname) {
        OSHandler *os_handler = NULL;
        if(!strcmp(osname, "auto")){
            os_handler = oshandler_init(qemu_get_cpu(0), NULL);
        }else{
            os_handler = oshandler_init(qemu_get_cpu(0), osname);
        }
        OSHandlerClass *os_cc = OSHANDLER_GET_CLASS(os_handler);

        process = qemu_opt_get(ra_opts, "process");
        if( process && is_oshandler_active() )
        {
            OSPid process_id = NULL_PID;

            // Figure out which process to analyze.
            if(!strcmp(process, "auto")){
                // Just use the active process as the process to analyze.
                CPU_FOREACH(cpu) {
                    process_id = os_cc->get_ospid_by_active(os_handler, cpu);
                    break;
                }
            }else{
                char *parsed = NULL;
                // Try to parse the process string as an integer.
                uint64_t pid = strtoull(process, &parsed, 10);
                if( parsed == process ){
                    // No integers were parsed so assume this is a process name.
                    process_id = os_cc->get_ospid_by_name(os_handler, process);
                    if( !process_id ) {
                        error_report("No rapid save file specified");
                        error_printf("Could not find process of name %s", process);
                        exit(1);
                    }
                }else{
                    // We parsed an integer so assume it's a pid.
                    process_id = os_cc->get_ospid_by_pid(os_handler, pid);
                    if( !process_id ) {
                        error_report("No rapid save file specified");
                        error_printf("Use file=[*.rsave] to specify a rapid anlysis file");
                        exit(1);
                    }
                }
            }

            global_rst->target_process = process_id;
        }
    }

    if(hash){
        g_free(hash);
    }

    // Start the system paused so we can wait for work.
    // vm_start();
    if(!vm_prepare_start(RUN_STATE_PAUSED)){
        resume_all_vcpus();
    }
}

void rapid_analysis_cleanup(MachineState *machine)
{
    if(global_rst) object_unref(OBJECT(global_rst));

    ram_rapid_blocks_cleanup();
    memory_channel_free_pool();
}

void rapid_analysis_partial_init(Error **errp)
{
    memory_channel_alloc_pool(RAPID_ANALYSIS_CHANNEL_POOL_INIT, 0);
    ram_mig_destroy();
    ram_rapid_init(errp);
}

void rapid_analysis_partial_delta(SHA1_HASH_TYPE *root_hash, Error **errp)
{
    ram_rapid_destroy();
    ram_rapid_delta_init(NULL, root_hash, errp);
}

void rapid_analysis_partial_cleanup(void)
{
    ram_rapid_destroy();
    ram_mig_init();
    memory_channel_free_pool();
}

static bool rapid_analysis_handle_sys_read(CPUState *cs, uint32_t fd, ram_addr_t buf, size_t count)
{
    RSaveTreeClass *rst_class = RSAVE_TREE_GET_CLASS(global_rst);
    return rst_class->write_stream_data(global_rst, cs, fd, buf, count);
}

bool rapid_analysis_handle_syscall(CPUState *cpu , uint64_t number, ...)
{
    va_list registers;
    bool ret;

    va_start(registers, number);

    /* Check if first argument (syscall number register) is read syscall number */
    uint64_t rax = va_arg(registers, uint64_t);
    uint64_t rdi = va_arg(registers, uint64_t);
    uint64_t rsi = va_arg(registers, uint64_t);
    uint64_t rdx = va_arg(registers, uint64_t);

    /* TODO: make more robust, add SYS_READ macro for diffrent arch's */
    switch (rax) {
        case 0:
            ret = rapid_analysis_handle_sys_read(cpu,
                        (uint32_t)  rdi,
                        (ram_addr_t)rsi,
                        (size_t)    rdx );
            return ret;
        default:
            break;
    }

    return false;
}

void rapid_analysis_set_error(uint32_t error_id_in, uint64_t error_loc_in, const char *error_text_in)
{
    if (!error_text)
    {
        error_text = g_new0(char, sizeof(ERROR_TEXT));
    }
    
    error_id = error_id_in;
    error_loc = error_loc_in;
    strncpy(error_text, error_text_in, sizeof(ERROR_TEXT) -1);
}

void rapid_analysis_clear_error(void)
{
    error_id = ERROR_STATE_NONE;
    error_loc = 0;

    if (error_text)
    {
        memset(error_text, 0, sizeof(ERROR_TEXT));
    }
}

bool rapid_analysis_has_error(void)
{
    return error_id != ERROR_STATE_NONE;
}

uint32_t rapid_analysis_get_error_id(void)
{
    return error_id;
}

uint64_t rapid_analysis_get_error_loc(void)
{
    return error_loc;
}

const char *rapid_analysis_get_error_text(void)
{
    return error_text;
}
