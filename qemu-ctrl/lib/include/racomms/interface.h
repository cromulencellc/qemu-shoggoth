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

#include <stdint.h>
#include "racomms/messages.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 * 
 * 
 * @param str
 * @param hash
 */
void string_to_hash(const char *str, SHA1_HASH_TYPE hash);

/**
 * This function reads a message from the provided socket. The amount read from the
 * socket will be determined byt the size of mthe comms message provided. Some 
 * messages become quite large, so the socket may be read multiple times. 
 * 
 * @param buffer The buffer that will contain the information that was read.
 * @param init_size The initial size of the buffer.
 * @param sock_fd The fd for the socket to read from.
 * @param hdr The header for the message being read.
 * @return The total amount read.
 */
size_t read_message(char **buffer, size_t init_size, int sock_fd, CommsMessage *hdr);

/**
 * This function parses the job report message and passes each individual entry to the 
 * callback function. The callback function should process the message if need be and 
 * adjust the return value pointer (int *). The report type will disclose which type of 
 * report the void pointer can safley cast to. The callback will be given a void pointer
 * that it may set to keep track of data across runs. The callback should return a contunue
 * parsing signal of TRUE or FALSE.
 * 
 * @param crjrm The message
 * @param size The size of the message
 * @param analyze_entry The callback function (type, message, record, result)
 * @return success or failure of the test.
 */
int parse_job_report(CommsResponseJobReportMsg *crjrm, size_t size, int (analyze_entry)(JOB_REPORT_TYPE, void*, void **, int *));

#ifdef __cplusplus
}
#endif

#endif
