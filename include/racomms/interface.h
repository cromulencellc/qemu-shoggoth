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

#ifndef __RACOMMS_INTERFACE_H__
#define __RACOMMS_INTERFACE_H__

#include "qapi/qapi-types-sockets.h"
#include "racomms/messages.h"

typedef struct WorkEntryItem{
    uint32_t offset;
    JOB_ADD_TYPE entry_type;
    QLIST_ENTRY(WorkEntryItem) next;
} WorkEntryItem;

typedef struct CommsWorkItem{
    CommsMessage *msg;
    QLIST_HEAD(,WorkEntryItem) entry_list;
    QTAILQ_ENTRY(CommsWorkItem) next;
} CommsWorkItem;

typedef struct CommsResultsItem{
    CommsMessage *msg;
    QTAILQ_ENTRY(CommsResultsItem) next;
} CommsResultsItem;

typedef struct CommsQueue CommsQueue;

void queue_push_work(CommsQueue *q, CommsWorkItem *work);
CommsWorkItem *queue_pop_work(CommsQueue *q);
bool queue_has_work(CommsQueue *q);
void queue_push_results(CommsQueue *q, CommsResultsItem *results);
CommsResultsItem *queue_pop_results(CommsQueue *q);

bool racomms_queue_add_job(CommsQueue *q, CommsMessage *msg);
void racomms_free_work(CommsWorkItem *work);

void racomms_queue_start(uint8_t id, int ctrlfd, Error **errp);
void racomms_queue_stop(void);

CommsQueue *get_comms_queue(uint8_t queue_num);

CommsMessage *racomms_create_config_request_msg(uint8_t queue);
void racomms_msg_config_request_put_ReportMask(CommsMessage *msg, JOB_REPORT_TYPE req_flags);
void racomms_msg_config_request_put_SessionTimeout(CommsMessage *msg, uint64_t timeout);
CommsMessage *racomms_create_config_response_msg(uint8_t queue);

CommsMessage *racomms_create_job_add_msg(uint8_t queue, int32_t job_id, SHA1_HASH_TYPE base_hash, JOB_FLAG_TYPE flags);
CommsMessage *racomms_msg_job_add_put_ExitInsnCountConstraint(CommsMessage *msg, uint64_t insn_limit);
CommsMessage *racomms_msg_job_add_put_ExitInsnRangeConstraint(CommsMessage *msg, uint64_t offset, uint32_t size);
CommsMessage *racomms_msg_job_add_put_ExitExceptionContrainst(CommsMessage *msg, uint64_t mask);
CommsMessage *racomms_msg_job_add_put_RegisterSetup(CommsMessage *msg, uint8_t id, NAME_TYPE name, uint8_t size, uint8_t *value);
CommsMessage *racomms_msg_job_add_put_MemorySetup(CommsMessage *msg, uint64_t offset, uint32_t size, const uint8_t *value, MEMORY_FLAGS flags);
CommsMessage *racomms_msg_job_add_put_StreamSetup(CommsMessage *msg, uint32_t fileno, uint32_t size, uint8_t *value);
CommsMessage *racomms_msg_job_add_put_TimeoutSetup(CommsMessage *msg, uint64_t timeout);

CommsMessage *racomms_create_job_status_msg(uint8_t queue, int32_t job_id);

CommsMessage *racomms_create_job_report_request_msg(uint8_t queue, int32_t job_id, SHA1_HASH_TYPE hash, JOB_REPORT_TYPE req_flags);
CommsMessage *racomms_create_job_report_response_msg(uint8_t queue, int32_t job_id, SHA1_HASH_TYPE job_hash);
void          racomms_msg_job_report_put_InstructionCount(CommsMessage *msg, uint64_t icount);
CommsMessage *racomms_msg_job_report_put_ProcessorEntry(CommsMessage *msg, uint8_t cpu_id, NAME_TYPE cpu_name);
CommsMessage *racomms_msg_job_report_put_RegisterEntry(CommsMessage *msg, uint8_t id, NAME_TYPE name, uint8_t size, uint8_t *value);
CommsMessage *racomms_msg_job_report_put_MemoryEntry(CommsMessage *msg, uint64_t offset, uint32_t size, uint8_t *value, JOB_REPORT_TYPE mem_type);
CommsMessage *racomms_msg_job_report_put_Exception(CommsMessage *msg, uint64_t exception_mask);
CommsMessage *racomms_msg_job_report_put_Error(CommsMessage *msg, uint32_t error_id, uint64_t error_loc, const char *error_text);

CommsMessage *racomms_create_purge_queue_msg(uint8_t queue, PURGE_ACTION_TYPE action);

CommsMessage *racomms_create_quit_msg(QUIT_ACTION_TYPE how);

CommsMessage *racomms_create_rapid_save_tree_request_msg(uint8_t queue, int32_t job_id);
CommsMessage *racomms_create_rapid_save_tree_response_msg(uint8_t queue, int32_t job_id);
CommsMessage *racomms_msg_rapid_save_tree_put_InstructionEntry(CommsMessage *msg, const char *insn_label);
CommsMessage *racomms_msg_rapid_save_tree_put_NodeHeader(CommsMessage *msg, int64_t timestamp,
    uint64_t instruction_number, uint64_t cpu_exception_index, int32_t job_id);
CommsMessage *racomms_msg_rapid_save_tree_put_NodeIndex(CommsMessage *msg, const char *index_label,
    uint32_t instance_id, uint32_t section_id, uint64_t offset);
CommsMessage *racomms_msg_rapid_save_tree_put_NodeState(CommsMessage *msg, uint32_t size);

#endif
