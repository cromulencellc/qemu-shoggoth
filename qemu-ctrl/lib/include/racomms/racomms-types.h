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

#ifndef __RACOMMS_TYPES_H__
#define __RACOMMS_TYPES_H__

#include <stdint.h>

#define INVALID_TYPE ((uint8_t)-1)
#define INVALID_JOB ((int32_t)-1)

typedef uint32_t SHA1_HASH_TYPE[5]; //TODO: Can this be commonized?

typedef uint8_t NAME_TYPE[15];
typedef uint8_t INSN_LABEL[24];
typedef uint8_t INDEX_LABEL[32];
typedef uint8_t ERROR_TEXT[24];

typedef uint8_t PURGE_ACTION_TYPE;

#define PURGE_RESERVED     (60)
#define PURGE_DROP_RESULTS (PURGE_RESERVED+1)
#define PURGE_SEND_RESULTS (PURGE_RESERVED+2)

typedef uint8_t MESSAGE_TYPE;

#define MSG_RESERVED   (10)
#define MSG_REQUEST_CONFIG     (MSG_RESERVED+1)
#define MSG_REQUEST_RST        (MSG_RESERVED+2)
#define MSG_REQUEST_JOB_ADD    (MSG_RESERVED+3)
#define MSG_REQUEST_JOB_PURGE  (MSG_RESERVED+4)
#define MSG_REQUEST_JOB_REPORT (MSG_RESERVED+5)
#define MSG_REQUEST_QUIT       (MSG_RESERVED+6)

#define MSG_RESPONSE_CONFIG    (MSG_RESERVED+10)
#define MSG_RESPONSE_REPORT    (MSG_RESERVED+11)
#define MSG_RESPONSE_RST       (MSG_RESERVED+12)

typedef uint8_t JOB_ADD_TYPE;

#define JOB_ADD_RESERVED        (30)
#define JOB_ADD_REGISTER        (JOB_ADD_RESERVED+1)
#define JOB_ADD_MEMORY          (JOB_ADD_RESERVED+2)
#define JOB_ADD_EXIT_INSN_COUNT (JOB_ADD_RESERVED+3)
#define JOB_ADD_EXIT_INSN_RANGE (JOB_ADD_RESERVED+4)
#define JOB_ADD_EXIT_EXCEPTION  (JOB_ADD_RESERVED+5)
#define JOB_ADD_TIMEOUT         (JOB_ADD_RESERVED+6)
#define JOB_ADD_STREAM          (JOB_ADD_RESERVED+7)

typedef uint8_t JOB_FLAG_TYPE;

#define JOB_FLAG_CONTINUE       (1<<0)
#define JOB_FLAG_FORCE_SAVE     (1<<1)
#define JOB_FLAG_NO_EXECUTE     (1<<2)

typedef uint8_t JOB_REPORT_TYPE;

#define JOB_REPORT_PROCESSOR           (1<<0)
#define JOB_REPORT_REGISTER            (1<<1)
#define JOB_REPORT_VIRTUAL_MEMORY      (1<<2)
#define JOB_REPORT_PHYSICAL_MEMORY     (1<<3)
#define JOB_REPORT_ALL_PHYSICAL_MEMORY (1<<4)
#define JOB_REPORT_ALL_VIRTUAL_MEMORY  (1<<5)
#define JOB_REPORT_ERROR               (1<<6)
#define JOB_REPORT_EXCEPTION           (1<<7)

typedef uint64_t CONFIG_VALID_SETTINGS;

#define CONFIG_JOB_REPORT_MASK  (1<<0)
#define CONFIG_JOB_TIMEOUT_MASK (1<<1)

typedef uint8_t JOB_CONFIG_TYPE;

#define JOB_CONFIG_RESERVED    (50)
#define JOB_CONFIG_TIMEOUT     (JOB_CONFIG_RESERVED+1)

typedef uint8_t MEMORY_FLAGS;

#define MEMORY_VIRTUAL  (1)
#define MEMORY_PHYSICAL (2)

typedef uint8_t QUIT_ACTION_TYPE;

#define QUIT_RESERVED     (70)
#define QUIT_CLEAN        (QUIT_RESERVED+1)
#define QUIT_NOW          (QUIT_RESERVED+2)
#define QUIT_KILL         (QUIT_RESERVED+3)

// Error States
#define ERROR_STATE_NONE         0
#define ERROR_STATE_PROCESSOR_OP 1
#define ERROR_STATE_TIMEOUT      2

/**
 * These are strongly tied to QEMU internals.
 * Values of interest should be added here for
 * ease of use.
 */
#define X86_ILLEGAL_INSTRUCTION  (1 << 6)
#define X86_SEGMENT_FAULT        (1 << 11)

#endif
