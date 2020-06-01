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

#include <glib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "racomms/interface.h"
#include "racomms/messages.h"

#define READ_INTERVAL       (250)
#define CURRENT_VERSION     (1)
#define INITIAL_BUFFER_SIZE (256)


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

void string_to_hash(const char *str, SHA1_HASH_TYPE hash)
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

size_t read_message(char **buffer, size_t init_size, int sock_fd, CommsMessage *hdr)
{
    size_t current_size = 0;
    size_t total_read = 0;
    size_t body_size = hdr->size - sizeof(CommsMessage);
    if (*buffer == NULL)
    {
        *buffer = (char *) malloc(body_size);
        memset(*buffer, 0, body_size);
    }else if(body_size > init_size){
        void *new_buffer = realloc(*buffer, body_size);
        if(new_buffer == NULL){
            exit(1);
        }
        *buffer = new_buffer;
    }

    do
    {
        size_t to_read = body_size-total_read;
        if( to_read > READ_INTERVAL ){
            to_read = READ_INTERVAL;
        }
        ssize_t amt_read = read(sock_fd, &(*buffer)[total_read], to_read);
        if (amt_read < 0) {
            if( errno != EAGAIN ){
                exit(1);
            }
        }
        total_read += amt_read;
    } while(total_read < body_size);

    return total_read;
}

int parse_job_report(CommsResponseJobReportMsg *crjrm, size_t size, int (analyze_entry)(JOB_REPORT_TYPE, void*, void **, int *))
{
    void *record = NULL;
    int ret_val = FALSE;
    int continue_parsing = TRUE;

    /**
     * Messages can be thought of as bytes. So, we'll treat them as bytes
     * so that we can step through the entire message. Once we adjust the 
     * frame within the message, we can cast to the correct entry type.
     */
    char *buffer = (char *) crjrm;
    char *end = buffer + size;

    /**
     * This will help us know what type of entry we are looking at.
     */
    JOB_REPORT_TYPE report_type;

    /**
     * In this example, we don't care about data from the CommsResponseJobReportMsg.
     * It is like a header for the data that follows. So, we'll skip past it.
     */
    buffer += sizeof(CommsResponseJobReportMsg);

    /**
     * No we are at the begenning of our state data.
     * We can loop over it to determine state.
     */
    do
    {
        /**
         * We can cast the begenning of our buffer to report type. All
         * entries in the report start with type data for decoding.
         */
        report_type = *((JOB_REPORT_TYPE *)buffer);

        /**
         * Now we can decode the report entry
         */
        switch(report_type)
        {
            /**
             * We are prepared to process job entries of a given type.
             * If an unexpected type appears, then we will bail on the process.
             * In each case, we will cast the buffer to the job type, inspect the
             * results and move the buffer past the result.
             */
            case JOB_REPORT_PROCESSOR:
            {
                CommsResponseJobReportProcessorEntry *proc = (CommsResponseJobReportProcessorEntry *)buffer;
                buffer += sizeof(CommsResponseJobReportProcessorEntry);
                continue_parsing = analyze_entry(report_type, (void *) proc, &record, &ret_val);
            }
            break;
            case JOB_REPORT_REGISTER:
            {
                CommsResponseJobReportRegisterEntry *reg = (CommsResponseJobReportRegisterEntry *)buffer;
                /**
                 * In this case, we need to advance the buffer past the register data too.
                 */
                buffer += (sizeof(CommsResponseJobReportRegisterEntry) + reg->size - 1);
                continue_parsing = analyze_entry(report_type, (void *) reg, &record, &ret_val);
            }
            break;            
            case JOB_REPORT_VIRTUAL_MEMORY...JOB_REPORT_PHYSICAL_MEMORY:
            {
                CommsResponseJobReportMemoryEntry *mem = (CommsResponseJobReportMemoryEntry *)buffer;
                /**
                 * In this case, we need to advance the buffer past the memory data too.
                 */
                buffer += (sizeof(CommsResponseJobReportMemoryEntry) + mem->size - 1);
                continue_parsing = analyze_entry(report_type, (void *) mem, &record, &ret_val);
            }
            break;
            case JOB_REPORT_ERROR:
            {
                CommsResponseJobReportErrorEntry *err = (CommsResponseJobReportErrorEntry *)buffer;
                buffer += sizeof(CommsResponseJobReportErrorEntry);
                continue_parsing = analyze_entry(report_type, (void *) err, &record, &ret_val);

            }
            break;
            case JOB_REPORT_EXCEPTION:
            {
                CommsResponseJobReportExceptionEntry *ee = (CommsResponseJobReportExceptionEntry *)buffer;
                buffer += sizeof(CommsResponseJobReportExceptionEntry);
                continue_parsing = analyze_entry(report_type, (void *) ee, &record, &ret_val);
            }
            break;
            default:
            {
                /**
                 * We have a problem, we will bail out now.
                 */
                continue_parsing = FALSE;
                analyze_entry(report_type, NULL, &record, &ret_val);
            }
            break;
        }
    
    } while(buffer != end && continue_parsing);

    /**
     * We want to make sure to free the record that
     * the callback was keeping.
     */
    if (record)
    {
        g_free(record);
    }

    /**
     * All done.
     */
    return ret_val;
}

