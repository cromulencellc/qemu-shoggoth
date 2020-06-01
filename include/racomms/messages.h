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

#ifndef __RACOMMS_MESSAGES_H__
#define __RACOMMS_MESSAGES_H__

#include "qapi/qapi-types-sockets.h"
#include "racomms/racomms-types.h"

#define MSG_OFFSET(msg, offset)  ((void*)(((uint8_t*)(msg))+offset))

typedef struct{
    MESSAGE_TYPE msg_id;
    uint8_t version;
    uint8_t has_next_message;
    uint8_t reserved1;
    uint32_t reserved2;
    uint64_t size;
} CommsMessage;

///////////////////////////////

typedef struct{
    uint8_t queue;
    JOB_REPORT_TYPE report_mask;
    uint16_t reserved1;
    uint32_t reserved2;
    CONFIG_VALID_SETTINGS valid_settings;
    uint64_t timeout;
} CommsRequestConfigMsg;

typedef struct{
    uint8_t queue;
    JOB_REPORT_TYPE report_mask;
    uint16_t reserved1;
    uint32_t reserved2;
    uint64_t timeout;
} CommsResponseConfigMsg;

///////////////////////////////

typedef struct{
    uint8_t queue;
    uint8_t reserved1;
    uint16_t reserved2;
    int32_t job_id;
    uint32_t num_insns;
    SHA1_HASH_TYPE job_hash;
} CommsResponseJobReportMsg;

typedef struct{
    JOB_REPORT_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    uint32_t reserved4;
    NAME_TYPE cpu_name;
    uint8_t cpu_id;
} CommsResponseJobReportProcessorEntry;

typedef struct{
    JOB_REPORT_TYPE entry_type;
    uint8_t id;
    uint8_t size;
    uint8_t reserved1;
    uint32_t reserved2;
    NAME_TYPE name;
    uint8_t value[1];
} CommsResponseJobReportRegisterEntry;

typedef struct{
    JOB_REPORT_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t size;
    uint64_t offset;
    uint32_t reserved3;
    uint16_t reserved4;
    uint8_t reserved5;
    uint8_t value[1];
} CommsResponseJobReportMemoryEntry;

typedef struct{
    JOB_REPORT_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    uint64_t exception_mask;
} CommsResponseJobReportExceptionEntry;

typedef struct{
    JOB_REPORT_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t error_id;
    ERROR_TEXT error_text;
    uint64_t error_loc;
} CommsResponseJobReportErrorEntry;

///////////////////////////////

typedef struct{
    uint8_t queue;
    JOB_FLAG_TYPE flags;
    uint16_t reserved1;
    int32_t job_id;
    SHA1_HASH_TYPE base_hash;
} CommsRequestJobAddMsg;

typedef struct{
    JOB_ADD_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    uint64_t insn_limit;
} CommsRequestJobAddExitInsnCountConstraint;

typedef struct{
    JOB_ADD_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t size;
    uint64_t offset;
} CommsRequestJobAddExitInsnRangeConstraint;

typedef struct{
    JOB_ADD_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    uint64_t mask;
} CommsRequestJobAddExitExceptionConstraint;

typedef struct{
    JOB_ADD_TYPE entry_type;
    uint8_t id;
    uint8_t size;
    NAME_TYPE name;
    uint8_t value[1];
} CommsRequestJobAddRegisterSetup;

typedef struct{
    JOB_ADD_TYPE entry_type;
    MEMORY_FLAGS flags;
    uint16_t reserved1;
    uint32_t size;
    uint64_t offset;
    uint32_t reserved2;
    uint16_t reserved3;
    uint8_t reserved4;
    uint8_t value[1];
} CommsRequestJobAddMemorySetup;

typedef struct{
    JOB_ADD_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t fileno;
    uint32_t size;
    uint16_t reserved3;
    uint8_t reserved4;
    uint8_t value[1];
} CommsRequestJobAddStreamSetup;

typedef struct{
    JOB_ADD_TYPE entry_type;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    uint64_t timeout;
} CommsRequestJobAddTimeoutSetup;

///////////////////////////////

typedef struct{
    uint8_t queue;
    PURGE_ACTION_TYPE action;
} CommsRequestJobPurgeMsg;

///////////////////////////////

typedef struct{
    uint8_t queue;
    JOB_REPORT_TYPE report_mask;
    uint16_t reserved1;
    int32_t job_id;
    SHA1_HASH_TYPE job_hash;
} CommsRequestJobReportMsg;

///////////////////////////////

typedef struct{
    QUIT_ACTION_TYPE how;
} CommsRequestQuitMsg;

///////////////////////////////

typedef struct{
    uint8_t queue;
    uint8_t reserved1;
    uint16_t reserved2;
    int32_t job_id;
} CommsRequestRapidSaveTreeMsg;

///////////////////////////////

typedef struct{
    uint8_t  queue;
    uint8_t reserved1;
    uint16_t reserved2;
    int32_t  job_id;
    uint64_t num_insns;
} CommsResponseRapidSaveTreeMsg;

typedef struct{
    INSN_LABEL label;
    uint64_t num_nodes;
} CommsResponseRapidSaveTreeInstructionEntry;

typedef struct{
    uint32_t index_offset;
    uint32_t state_offset;
    int32_t  job_id;
    uint32_t num_indices;
    int64_t  timestamp;
    uint64_t instruction_number;
    uint64_t cpu_exception_index;
} CommsResponseRapidSaveTreeNodeHeader;

typedef struct{
    INDEX_LABEL label;
    uint32_t instance_id;
    uint32_t section_id;
    uint64_t offset;
} CommsResponseRapidSaveTreeNodeIndex;

typedef struct{
    uint32_t size;
    uint16_t reserved1;
    uint8_t reserved2;
    uint8_t  state[1];
} CommsResponseRapidSaveTreeNodeState;

#endif
