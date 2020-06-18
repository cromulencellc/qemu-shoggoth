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

#ifndef __NET_CB_H__
#define __NET_CB_H__

#include "qemu/osdep.h"
#include "qemu-common.h"

void notify_receving_packet(uint8_t **pkt_buf, uint32_t *pkt_size);
void notify_sending_packet(uint8_t **pkt_buf, uint32_t *pkt_size);

bool is_recvpacket_instrumentation_enabled(void);
bool is_sendpacket_instrumentation_enabled(void);

#endif