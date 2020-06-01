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
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/help_option.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/sockets.h"
#include "monitor/qdev.h"
#include "migration/snapshot.h"
#include "rsave-tree.h"
#include "hw/boards.h"
#include "qemu/thread.h"
#include "racomms/interface.h"
#include "racomms/messages.h"
#include "sysemu/sysemu.h"
#include "ra.h"

#define CURRENT_VERSION       (1)
#define INITIAL_BUFFER_SIZE   (256)
#define RACOMMS_MAX_SEND_SIZE (65536)
#define RACOMMS_MIN_SEND_SIZE (4096)

struct CommsQueue {
    uint8_t id;
    int fd;
    size_t readloc;
    size_t buffloc;
    size_t buffsize;
    uint8_t *buffer;

    QemuMutex work_list_mutex;
    QTAILQ_HEAD(,CommsWorkItem) work_list;
    QemuEvent work_arrived_event;

    QemuMutex results_list_mutex;
    QTAILQ_HEAD(,CommsResultsItem) results_list;
};

static bool racomms_active = false;
static CommsQueue *queue = NULL;

static void racomms_read_message(void *opaque);
static void racomms_write_message(void *opaque);

CommsQueue *get_comms_queue(uint8_t queue_num)
{
    return queue;
}

void queue_push_work(CommsQueue *q, CommsWorkItem *work)
{
    qemu_mutex_lock(&q->work_list_mutex);
    QTAILQ_INSERT_TAIL(&q->work_list, work, next);
    qemu_event_set(&queue->work_arrived_event);
    qemu_mutex_unlock(&q->work_list_mutex);
}

CommsWorkItem *queue_pop_work(CommsQueue *q)
{
    CommsWorkItem *work;
    qemu_mutex_lock(&q->work_list_mutex);
    work = QTAILQ_FIRST(&q->work_list);

    while(!work)
    {
        qemu_event_reset(&q->work_arrived_event);
        qemu_mutex_unlock(&q->work_list_mutex);

        qemu_event_wait(&q->work_arrived_event);

        qemu_mutex_lock(&q->work_list_mutex);
        work = QTAILQ_FIRST(&q->work_list);
    }

    QTAILQ_REMOVE(&q->work_list, work, next);
    qemu_mutex_unlock(&q->work_list_mutex);
    return work;
}

bool queue_has_work(CommsQueue *q)
{
    CommsWorkItem *work = QTAILQ_FIRST(&q->work_list);
    return work != NULL;
}


static void queue_purge_work(CommsQueue *q)
{
    CommsWorkItem *work;
    qemu_mutex_lock(&q->work_list_mutex);
    work = QTAILQ_FIRST(&q->work_list);

    while(work)
    {
        QTAILQ_REMOVE(&q->work_list, work, next);
        racomms_free_work(work);
        work = QTAILQ_FIRST(&q->work_list);
    }

    qemu_mutex_unlock(&q->work_list_mutex);
}

void queue_push_results(CommsQueue *q, CommsResultsItem *results)
{
    qemu_mutex_lock(&q->results_list_mutex);
    QTAILQ_INSERT_TAIL(&q->results_list, results, next);
    qemu_mutex_unlock(&q->results_list_mutex);
}

CommsResultsItem *queue_pop_results(CommsQueue *q)
{
    CommsResultsItem *result;
    qemu_mutex_lock(&q->results_list_mutex);
    result = QTAILQ_FIRST(&q->results_list);
    QTAILQ_REMOVE(&q->results_list, result, next);
    qemu_mutex_unlock(&q->results_list_mutex);
    return result;
}

static void queue_purge_results(CommsQueue *q)
{
    CommsResultsItem *result;
    qemu_mutex_lock(&q->results_list_mutex);
    result = QTAILQ_FIRST(&q->results_list);

    rapid_analysis_end_work(NULL, false);

    while(result)
    {
        g_free(result->msg);
        QTAILQ_REMOVE(&q->results_list, result, next);
        g_free(result);
        result = QTAILQ_FIRST(&q->results_list);
    }

    qemu_mutex_unlock(&q->results_list_mutex);
}

static void *queue_dup_buffer(CommsQueue *q)
{
    return g_memdup(q->buffer, q->buffsize);
}

static void queue_reset(CommsQueue *q)
{
    q->buffloc = 0;
    q->readloc = 0;
}

static void queue_cleanup(CommsQueue *q)
{
    qemu_set_fd_handler(q->fd, NULL, NULL, NULL);
    closesocket(q->fd);
    g_free(q->buffer);
    g_free(q);
}

static void queue_error(CommsQueue *q, const char *msg, ...)
{
    va_list v;
    if( msg ) {
        va_start(v, msg);
        vfprintf(stderr, msg, v);
        va_end(v);
    }
    queue_cleanup(q);
}

void racomms_queue_start(uint8_t id, int ctrlfd, Error **errp)
{
    if( !racomms_active ) {
        racomms_active = true;
        queue = g_new0(CommsQueue, 1);
        queue->id = id;
        queue->buffsize = INITIAL_BUFFER_SIZE;
        queue->buffer = g_malloc0(INITIAL_BUFFER_SIZE);
        QTAILQ_INIT(&queue->work_list);
        QTAILQ_INIT(&queue->results_list);
        qemu_event_init(&queue->work_arrived_event, false);
        qemu_mutex_init(&queue->work_list_mutex);
        qemu_mutex_init(&queue->results_list_mutex);
        queue_reset(queue);
        if( ctrlfd > 0 ) {
            queue->fd = ctrlfd;
            qemu_set_nonblock(queue->fd);
            qemu_set_fd_handler(queue->fd, racomms_read_message, racomms_write_message, queue);
        }
    }
}

void racomms_queue_stop(void)
{
    if( racomms_active ) {
        racomms_active = false;
        queue_cleanup(queue);
        qemu_event_destroy(&queue->work_arrived_event);
        qemu_mutex_destroy(&queue->work_list_mutex);
        qemu_mutex_destroy(&queue->results_list_mutex);
    }
}

static CommsMessage *racomms_create_msg(MESSAGE_TYPE msg_id, size_t size)
{
    CommsMessage *r = g_malloc0(size);
    if( !r ) {
        return NULL;
    }
    r->version = CURRENT_VERSION;
    r->msg_id = msg_id;
    r->has_next_message = 0;
    r->size = size;
    return r;
}

static void *add_msg_entry(CommsMessage **msg, size_t size)
{
    CommsMessage *r = g_realloc(*msg, (*msg)->size + size);
    if( !r ) {
        return NULL;
    }
    *msg = r;
    void *entry_base = (((uint8_t*)r) + r->size);
    r->size += size;
    return entry_base;
}

CommsMessage *racomms_create_config_request_msg(uint8_t queue)
{
    CommsMessage *msg = racomms_create_msg(MSG_REQUEST_CONFIG, sizeof(CommsMessage) + sizeof(CommsRequestConfigMsg));
    if( !msg ) {
        return NULL;
    }
    CommsRequestConfigMsg *rmsg = (CommsRequestConfigMsg*)(msg + 1);
    rmsg->queue = queue;
    rmsg->valid_settings = 0;
    rmsg->report_mask = 0;
    return msg;
}

void racomms_msg_config_request_put_ReportMask(CommsMessage *msg, JOB_REPORT_TYPE req_flags)
{
    CommsRequestConfigMsg *rmsg = (CommsRequestConfigMsg*)(msg + 1);
    rmsg->valid_settings |= CONFIG_JOB_REPORT_MASK;
    rmsg->report_mask = req_flags;
}

void racomms_msg_config_request_put_SessionTimeout(CommsMessage *msg, uint64_t timeout)
{
    CommsRequestConfigMsg *rmsg = (CommsRequestConfigMsg*)(msg + 1);
    rmsg->valid_settings |= CONFIG_JOB_TIMEOUT_MASK;
    rmsg->timeout = timeout;
}

CommsMessage *racomms_create_config_response_msg(uint8_t queue)
{
    CommsMessage *msg = racomms_create_msg(MSG_RESPONSE_CONFIG, sizeof(CommsMessage) + sizeof(CommsResponseConfigMsg));
    if( !msg ) {
        return NULL;
    }
    CommsResponseConfigMsg *rmsg = (CommsResponseConfigMsg*)(msg + 1);
    rmsg->queue = queue;
    rmsg->report_mask = 0;
    return msg;
}

CommsMessage *racomms_create_job_add_msg(uint8_t queue, int32_t job_id, SHA1_HASH_TYPE base_hash, JOB_FLAG_TYPE flags)
{
    CommsMessage *msg = racomms_create_msg(MSG_REQUEST_JOB_ADD, sizeof(CommsMessage) + sizeof(CommsRequestJobAddMsg));
    if( !msg ) {
        return NULL;
    }
    CommsRequestJobAddMsg *rmsg = (CommsRequestJobAddMsg*)(msg + 1);
    rmsg->queue = queue;
    rmsg->job_id = job_id;
    rmsg->flags = flags;
    memcpy(rmsg->base_hash, base_hash, sizeof(SHA1_HASH_TYPE));
    return msg;
}

CommsMessage *racomms_msg_job_add_put_ExitInsnCountConstraint(CommsMessage *msg, uint64_t insn_limit)
{
    CommsRequestJobAddExitInsnCountConstraint *rmsg = add_msg_entry(&msg, sizeof(CommsRequestJobAddExitInsnCountConstraint));
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_ADD_EXIT_INSN_COUNT;
    rmsg->insn_limit = insn_limit;
    return msg;
}

CommsMessage *racomms_msg_job_add_put_ExitInsnRangeConstraint(CommsMessage *msg, uint64_t offset, uint32_t size)
{
    CommsRequestJobAddExitInsnRangeConstraint *rmsg = add_msg_entry(&msg, sizeof(CommsRequestJobAddExitInsnRangeConstraint));
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_ADD_EXIT_INSN_RANGE;
    rmsg->offset = offset;
    rmsg->size = size;
    return msg;
}

CommsMessage *racomms_msg_job_add_put_ExitExceptionContrainst(CommsMessage *msg, uint64_t mask)
{
    CommsRequestJobAddExitExceptionConstraint *rmsg = add_msg_entry(&msg, sizeof(CommsRequestJobAddExitExceptionConstraint));
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_ADD_EXIT_EXCEPTION;
    rmsg->mask = mask;
    return msg;
}

CommsMessage *racomms_msg_job_add_put_RegisterSetup(CommsMessage *msg, uint8_t id, NAME_TYPE name, uint8_t size, uint8_t *value)
{
    CommsRequestJobAddRegisterSetup *rmsg = add_msg_entry(&msg, sizeof(CommsRequestJobAddRegisterSetup) + size - 1);
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_ADD_REGISTER;
    rmsg->id = id;
    memcpy(rmsg->name, name, sizeof(NAME_TYPE));
    rmsg->size = size;
    memcpy(rmsg->value, value, size);
    return msg;
}

CommsMessage *racomms_msg_job_add_put_MemorySetup(CommsMessage *msg, uint64_t offset, uint32_t size, const uint8_t *value, MEMORY_FLAGS flags)
{
    CommsRequestJobAddMemorySetup *rmsg = add_msg_entry(&msg, sizeof(CommsRequestJobAddMemorySetup) + size - 1);
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_ADD_MEMORY;
    rmsg->flags = flags;
    rmsg->offset = offset;
    rmsg->size = size;
    memcpy(rmsg->value, value, size);
    return msg;
}

CommsMessage *racomms_msg_job_add_put_StreamSetup(CommsMessage *msg, uint32_t fileno, uint32_t size, uint8_t *value)
{
    CommsRequestJobAddStreamSetup *rmsg = add_msg_entry(&msg, sizeof(CommsRequestJobAddStreamSetup) + size - 1);
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_ADD_STREAM;
    rmsg->fileno = fileno;
    rmsg->size = size;
    memcpy(rmsg->value, value, size);
    return msg;
}

CommsMessage *racomms_msg_job_add_put_TimeoutSetup(CommsMessage *msg, uint64_t timeout)
{
    CommsRequestJobAddTimeoutSetup *rmsg = add_msg_entry(&msg, sizeof(CommsRequestJobAddTimeoutSetup));
    if( !rmsg ) {
        return NULL;
    }    
    rmsg->entry_type = JOB_ADD_TIMEOUT;
    rmsg->timeout = timeout;
    return msg;
}

CommsMessage *racomms_create_job_report_request_msg(uint8_t queue, int32_t job_id, SHA1_HASH_TYPE hash, JOB_REPORT_TYPE req_flags)
{
    CommsMessage *msg = racomms_create_msg(MSG_REQUEST_JOB_REPORT, sizeof(CommsMessage) + sizeof(CommsRequestJobReportMsg));
    if( !msg ) {
        return NULL;
    }
    CommsRequestJobReportMsg *rmsg = (CommsRequestJobReportMsg*)(msg + 1);
    rmsg->report_mask = req_flags;
    rmsg->job_id = job_id;
    rmsg->queue = queue;
    memcpy(rmsg->job_hash, hash, sizeof(SHA1_HASH_TYPE));
    return msg;
}

CommsMessage *racomms_create_job_report_response_msg(uint8_t queue, int32_t job_id, SHA1_HASH_TYPE job_hash)
{
    CommsMessage *msg = racomms_create_msg(MSG_RESPONSE_REPORT, sizeof(CommsMessage) + sizeof(CommsResponseJobReportMsg));
    if( !msg ) {
        return NULL;
    }
    CommsResponseJobReportMsg *rmsg = (CommsResponseJobReportMsg*)(msg + 1);
    rmsg->job_id = job_id;
    memcpy(rmsg->job_hash, job_hash, sizeof(SHA1_HASH_TYPE));
    rmsg->queue = queue;
    rmsg->num_insns = 0;
    return msg;
}

void racomms_msg_job_report_put_InstructionCount(CommsMessage *msg, uint64_t icount)
{
    CommsResponseJobReportMsg *rmsg = (CommsResponseJobReportMsg*)(msg + 1);
    rmsg->num_insns = icount;
}

CommsMessage *racomms_msg_job_report_put_ProcessorEntry(CommsMessage *msg, uint8_t cpu_id, NAME_TYPE cpu_name)
{
    CommsResponseJobReportProcessorEntry *rmsg = add_msg_entry(&msg, sizeof(CommsResponseJobReportProcessorEntry));
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_REPORT_PROCESSOR;
    rmsg->cpu_id = cpu_id;
    memset(rmsg->cpu_name, 0, sizeof(NAME_TYPE));
    memcpy(rmsg->cpu_name, cpu_name, sizeof(NAME_TYPE) - 1);
    return msg;
}

CommsMessage *racomms_msg_job_report_put_RegisterEntry(CommsMessage *msg, uint8_t id, NAME_TYPE name, uint8_t size, uint8_t *value)
{
    CommsResponseJobReportRegisterEntry *rmsg = add_msg_entry(&msg, sizeof(CommsResponseJobReportRegisterEntry) + size - 1);
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_REPORT_REGISTER;
    rmsg->id = id;
    rmsg->size = size;
    memcpy(rmsg->name, name, sizeof(NAME_TYPE));
    memcpy(rmsg->value, value, size);
    return msg;
}

CommsMessage *racomms_msg_job_report_put_MemoryEntry(CommsMessage *msg, uint64_t offset, uint32_t size, uint8_t *value, JOB_REPORT_TYPE mem_type)
{
    if( mem_type != JOB_REPORT_VIRTUAL_MEMORY &&
        mem_type != JOB_REPORT_PHYSICAL_MEMORY ){
        return NULL;
    }

    CommsResponseJobReportMemoryEntry *rmsg = add_msg_entry(&msg, sizeof(CommsResponseJobReportMemoryEntry) + size - 1);
    if( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = mem_type;
    rmsg->offset = offset;
    rmsg->size = size;
    memcpy(rmsg->value, value, size);
    return msg;
}

CommsMessage *racomms_msg_job_report_put_Exception(CommsMessage *msg, uint64_t exception_mask)
{
    CommsResponseJobReportExceptionEntry *rmsg = add_msg_entry(&msg, sizeof(CommsResponseJobReportExceptionEntry));
    if ( !rmsg )
    {
        return NULL;
    }
    rmsg->entry_type = JOB_REPORT_EXCEPTION;
    rmsg->exception_mask = exception_mask;
    return msg;
}

CommsMessage *racomms_msg_job_report_put_Error(CommsMessage *msg, uint32_t error_id, uint64_t error_loc, const char *error_text)
{
    CommsResponseJobReportErrorEntry *rmsg = add_msg_entry(&msg, sizeof(CommsResponseJobReportErrorEntry));
    if ( !rmsg ) {
        return NULL;
    }
    rmsg->entry_type = JOB_REPORT_ERROR;
    rmsg->error_id = error_id;
    rmsg->error_loc = error_loc;
    strncpy(rmsg->error_text, error_text, sizeof(ERROR_TEXT) - 1);
    return msg;
}

CommsMessage *racomms_create_purge_queue_msg(uint8_t queue, PURGE_ACTION_TYPE action)
{
    CommsMessage *msg = racomms_create_msg(MSG_REQUEST_JOB_PURGE, sizeof(CommsMessage) + sizeof(CommsRequestJobPurgeMsg));
    if( !msg ) {
        return NULL;
    }
    CommsRequestJobPurgeMsg *rmsg = (CommsRequestJobPurgeMsg*)(msg + 1);
    rmsg->queue = queue;
    rmsg->action = action;
    return msg;
}

CommsMessage *racomms_create_quit_msg(QUIT_ACTION_TYPE how)
{
    CommsMessage *msg = racomms_create_msg(MSG_REQUEST_QUIT, sizeof(CommsMessage) + sizeof(CommsRequestQuitMsg));
    if( !msg ) {
        return NULL;
    }
    CommsRequestQuitMsg *rmsg = (CommsRequestQuitMsg*)(msg + 1);
    rmsg->how = how;
    return msg;
}

CommsMessage *racomms_create_rapid_save_tree_request_msg(uint8_t queue, int32_t job_id)
{
    CommsMessage *msg = racomms_create_msg(MSG_REQUEST_RST, sizeof(CommsMessage) + sizeof(CommsRequestRapidSaveTreeMsg));
    if( !msg ) {
        return NULL;
    }
    CommsRequestRapidSaveTreeMsg *rmsg = (CommsRequestRapidSaveTreeMsg*)(msg + 1);
    rmsg->queue = queue;
    rmsg->job_id = job_id;
    return msg;
}

CommsMessage *racomms_create_rapid_save_tree_response_msg(uint8_t queue, int32_t job_id)
{
    CommsMessage *msg = racomms_create_msg(MSG_RESPONSE_RST, sizeof(CommsMessage) + sizeof(CommsResponseRapidSaveTreeMsg));
    if( !msg ) {
        return NULL;
    }
    CommsResponseRapidSaveTreeMsg *rmsg = (CommsResponseRapidSaveTreeMsg*)(msg + 1);
    rmsg->queue = queue;
    rmsg->job_id = job_id;
    return msg;
}

CommsMessage *racomms_msg_rapid_save_tree_put_InstructionEntry(CommsMessage *msg, const char *insn_label)
{
    CommsResponseRapidSaveTreeInstructionEntry *rmsg = add_msg_entry(&msg, sizeof(CommsResponseRapidSaveTreeInstructionEntry));
    if( !rmsg ) {
        return NULL;
    }
    rmsg->num_nodes = 0;
    strncpy(rmsg->label, insn_label, sizeof(INSN_LABEL));
    return msg;
}

CommsMessage *racomms_msg_rapid_save_tree_put_NodeHeader(CommsMessage *msg, int64_t timestamp,
    uint64_t instruction_number, uint64_t cpu_exception_index, int32_t job_id)
{
    CommsResponseRapidSaveTreeNodeHeader *rmsg = add_msg_entry(&msg, sizeof(CommsResponseRapidSaveTreeNodeHeader));
    if( !rmsg ) {
        return NULL;
    }
    rmsg->num_indices = 0;
    rmsg->index_offset = 0;
    rmsg->state_offset = 0;
    rmsg->timestamp = timestamp;
    rmsg->instruction_number = instruction_number;
    rmsg->cpu_exception_index = cpu_exception_index;
    rmsg->job_id = job_id;
    return msg;
}

CommsMessage *racomms_msg_rapid_save_tree_put_NodeIndex(CommsMessage *msg, const char *index_label,
    uint32_t instance_id, uint32_t section_id, uint64_t offset)
{
    CommsResponseRapidSaveTreeNodeIndex *rmsg = add_msg_entry(&msg, sizeof(CommsResponseRapidSaveTreeNodeIndex));
    if( !rmsg ) {
        return NULL;
    }
    rmsg->instance_id = instance_id;
    rmsg->section_id = section_id;
    rmsg->offset = offset;
    strncpy(rmsg->label, index_label, sizeof(INDEX_LABEL));
    return msg;
}

CommsMessage *racomms_msg_rapid_save_tree_put_NodeState(CommsMessage *msg, uint32_t size)
{
    CommsResponseRapidSaveTreeNodeState *rmsg = add_msg_entry(&msg, sizeof(CommsResponseRapidSaveTreeNodeState) + size - 1);
    if( !rmsg ) {
        return NULL;
    }
    rmsg->size = size;
    return msg;
}

bool racomms_queue_add_job(CommsQueue *q, CommsMessage *msg)
{
    const char *start = (char*)msg;
    const char *end = start + msg->size;

    if(msg->msg_id != MSG_REQUEST_JOB_ADD){
        queue_error(q, "%s: wrong job msg received: %d (%s @ line %d)\n", msg->msg_id, __func__, strerror(errno), __LINE__);
        return false;
    }

    char *buffer = (char*)(msg + 1);
    CommsRequestJobAddMsg *job_msg = (CommsRequestJobAddMsg*)buffer;
    if(job_msg->queue != queue->id){
        queue_error(q, "%s: job add received for wrong queue: %d (%s @ line %d)\n", job_msg->queue, __func__, strerror(errno), __LINE__);
        return false;
    }
    buffer = (char*)(job_msg + 1);

    CommsWorkItem *work_item = g_new(CommsWorkItem, 1);
    work_item->msg = msg;
    QLIST_INIT(&work_item->entry_list);

    while(buffer < end) {
        JOB_ADD_TYPE e = *((JOB_ADD_TYPE *)buffer);

        WorkEntryItem *work_entry = g_new(WorkEntryItem, 1);
        work_entry->offset = (buffer - start);
        work_entry->entry_type = e;
        QLIST_INSERT_HEAD(&work_item->entry_list, work_entry, next);

        switch(e)
        {
            case JOB_ADD_EXIT_INSN_COUNT:
            {
                buffer += sizeof(CommsRequestJobAddExitInsnCountConstraint);
            }
                break;
            case JOB_ADD_EXIT_INSN_RANGE:
            {
                buffer += sizeof(CommsRequestJobAddExitInsnRangeConstraint);
            }
                break;
            case JOB_ADD_EXIT_EXCEPTION:
            {
                buffer += sizeof(CommsRequestJobAddExitExceptionConstraint);
            }
                break;
            case JOB_ADD_REGISTER:
            {
                CommsRequestJobAddRegisterSetup *entry = (CommsRequestJobAddRegisterSetup *)buffer;
                buffer += sizeof(CommsRequestJobAddRegisterSetup) + entry->size - 1;
            }
                break;
            case JOB_ADD_MEMORY:
            {
                CommsRequestJobAddMemorySetup *entry = (CommsRequestJobAddMemorySetup *)buffer;
                buffer += sizeof(CommsRequestJobAddMemorySetup) + entry->size - 1;
            }
                break;
            case JOB_ADD_STREAM:
            {
                CommsRequestJobAddStreamSetup *entry = (CommsRequestJobAddStreamSetup *)buffer;
                buffer += sizeof(CommsRequestJobAddStreamSetup) + entry->size - 1;
            }
                break;
            case JOB_ADD_TIMEOUT:
            {
                buffer += sizeof(CommsRequestJobAddTimeoutSetup);
            }
                break;
            default:
                queue_error(q, "%s: unknown job item type: %d (%s @ line %d)\n", e, __func__, strerror(errno), __LINE__);
                racomms_free_work(work_item);
                return false;
        }
    }

    if( buffer > end ){
        // Malformed job, we exceeded the size
        racomms_free_work(work_item);
        return false;
    }

    queue_push_work(q, work_item);
    return true;
}

static void racomms_write_message(void *opaque)
{
    CommsQueue *q = (CommsQueue*)opaque;
    CommsResultsItem *result, *next;
    size_t max_send_size = RACOMMS_MAX_SEND_SIZE;

    qemu_mutex_lock(&q->results_list_mutex);
    
    // Give the writers to the results list priority.
    QTAILQ_FOREACH_SAFE(result, &q->results_list, next, next)
    {
        size_t bytes_read = 0;
        uint8_t *raw_msg = (uint8_t*)result->msg;
        while( bytes_read < result->msg->size ) {
            size_t bytes_to_send = MIN(result->msg->size - bytes_read, max_send_size);
            ssize_t rc = write(q->fd, &raw_msg[bytes_read], bytes_to_send);
            if (rc < 0) {
                if( errno == EAGAIN ){
                    // Throttle the send size...
                    max_send_size = MAX(max_send_size/2, RACOMMS_MIN_SEND_SIZE);
                }else{
                    queue_error(q, "%s: failed to send msg %d @ line %d\n", __func__, result->msg->msg_id, __LINE__);
                    return;
                }
            }else{
                bytes_read += rc;
            }
        }
        g_free(result->msg);
        QTAILQ_REMOVE(&q->results_list, result, next);
        g_free(result);

        qemu_mutex_unlock(&q->results_list_mutex);
        // See if we have contention for the lock...
        if( qemu_mutex_trylock(&q->results_list_mutex) ){
            // We failed to grab the lock so bail for now...
            return;
        }
    }
    qemu_mutex_unlock(&q->results_list_mutex);
}

static void *read_all(CommsQueue *q, size_t read_size)
{
    if(q->buffsize < (q->buffloc + read_size)) {
        size_t new_size = q->buffloc + read_size;
        void *new_buffer = g_realloc(q->buffer, new_size);
        if( !new_buffer ){
            queue_error(q, "%s: failed to malloc size of %d @ line %d\n", __func__, new_size, __LINE__);
            return NULL;
        }
        q->buffer = (uint8_t*)new_buffer;
        q->buffsize = new_size;
    }

    size_t read_start = q->readloc;
    while(read_size > 0){
        int rc = read(q->fd, &q->buffer[q->buffloc], read_size);
        if (rc <= 0){
            if(rc < 0 && errno != EAGAIN) {
                queue_error(q, "%s: failed to receive data @ line %d\n", __func__, __LINE__);
            }
            return NULL;
        }else{
            q->buffloc += rc;
            read_size -= rc;
        }
    }

    q->readloc = q->buffloc;

    return &q->buffer[read_start];
}

static void racomms_read_message(void *opaque)
{
    CommsQueue *q = (CommsQueue*)opaque;
    CommsMessage *header = NULL;

    // Reset for initial message
    queue_reset( queue );

    // Read all messages in the queue
    while((header = read_all(q, sizeof(CommsMessage))) != NULL ) {
        const MESSAGE_TYPE header_msg_id = header->msg_id;
        const uint64_t header_size = header->size;

        // Do we need to realloc to hold the entire message?
        if( q->buffsize < header_size) {
            void *new_buffer = g_realloc(q->buffer, header_size);
            if( !new_buffer ){
                queue_error(q, "%s: failed to malloc size of %d @ line %d\n", __func__, header_size, __LINE__);
                return;
            }
            header = new_buffer;
            q->buffer = new_buffer;
            q->buffsize = header_size;
        }

        switch(header_msg_id)
        {
            case MSG_REQUEST_CONFIG:
            {
                CommsRequestConfigMsg *msg = read_all(q, sizeof(CommsRequestConfigMsg));
            
                rapid_analysis_set_configuration(msg, q);
            }
                break;
            case MSG_REQUEST_RST:
            {
                CommsRequestRapidSaveTreeMsg *msg = read_all(q, sizeof(CommsRequestRapidSaveTreeMsg));
                if( !msg ){
                    queue_error(q, "%s: read: %s @ line %d\n", __func__, strerror(errno), __LINE__);
                    return;
                }

                rapid_analysis_send_tree(msg, q);
            }
                break;
            case MSG_REQUEST_JOB_ADD:
            {
                const size_t job_size = header_size - sizeof(CommsMessage);
                CommsRequestJobAddMsg *job = read_all(q, job_size);
                if( !job ){
                    queue_error(q, "%s: read: %s @ line %d\n", __func__, strerror(errno), __LINE__);
                    return;
                }

                CommsMessage *dup_msg = queue_dup_buffer(q);
                if( !dup_msg ){
                    queue_error(q, "%s: unable to duplicate message: %s @ line %d\n", __func__, strerror(errno), __LINE__);
                    return;
                }

                racomms_queue_add_job(q, dup_msg);
            }
                break;
            case MSG_REQUEST_JOB_PURGE:
            {
                CommsRequestJobPurgeMsg *msg = read_all(q, sizeof(CommsRequestJobPurgeMsg));
                if( !msg ){
                    queue_error(q, "%s: read: %s @ line %d\n", __func__, strerror(errno), __LINE__);
                    return;
                }

                if( msg->action == PURGE_DROP_RESULTS ) {
                    queue_purge_results(q);
                    queue_purge_work(q);
                }else if( msg->action == PURGE_SEND_RESULTS ) {
                    queue_purge_work(q);
                }
            }
                break;
            case MSG_REQUEST_JOB_REPORT:
            {
                CommsRequestJobReportMsg *msg = read_all(q, sizeof(CommsRequestJobReportMsg));
                if( !msg ){
                    queue_error(q, "%s: read: %s @ line %d\n", __func__, strerror(errno), __LINE__);
                    return;
                }

                CommsWorkItem *work_item = g_new(CommsWorkItem, 1);
                QLIST_INIT(&work_item->entry_list);
                CommsMessage *dup_msg = queue_dup_buffer(q);
                if( !dup_msg ){
                    queue_error(q, "%s: unable to duplicate message: %s @ line %d\n", __func__, strerror(errno), __LINE__);
                    return;
                }
                work_item->msg = dup_msg;
                queue_push_work(q, work_item);
            }
                break;
            case MSG_REQUEST_QUIT:
            {
                CommsRequestQuitMsg *msg = read_all(q, sizeof(CommsRequestQuitMsg));
                if( !msg ){
                    queue_error(q, "%s: read: %s @ line %d\n", __func__, strerror(errno), __LINE__);
                    return;
                }

                if( msg->how == QUIT_CLEAN ){
                    CommsWorkItem *work_item = g_new(CommsWorkItem, 1);
                    QLIST_INIT(&work_item->entry_list);
                    CommsMessage *dup_msg = queue_dup_buffer(q);
                    if( !dup_msg ){
                        queue_error(q, "%s: unable to duplicate message: %s @ line %d\n", __func__, strerror(errno), __LINE__);
                        return;
                    }
                    work_item->msg = dup_msg;
                    queue_push_work(q, work_item);
                }else if( msg->how == QUIT_NOW ){
                    qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_UI);
                }else if( msg->how == QUIT_KILL ){
                    exit(0);
                }else{
                    queue_error(q, "%s: Unsupported quit action!\n", __func__);
                    return;
                }
            }
                break;
            default:
                queue_error(q, "%s: Unknown message received!\n", __func__);
                break;
        }

        // Reset for next message
        queue_reset( queue );
    }
}

void racomms_free_work(CommsWorkItem *work)
{
    WorkEntryItem *entry, *next_item;

    g_free(work->msg);

    QLIST_FOREACH_SAFE(entry, &work->entry_list, next, next_item) {
        QLIST_REMOVE(entry, next);
        g_free(entry);
    }

    g_free(work);
}
