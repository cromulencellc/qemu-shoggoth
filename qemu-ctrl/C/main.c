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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "racomms/messages.h"
#include "racomms/interface.h"
#include "errno.h"

#define READ_INTERVAL 250
#define error         printf
#define DUMMY {1909565552, 135073496, 3988139521, 3798846436, 446192858}
//#define DUMMY {0x5bf590f6, 0x13c6df2b, 0xc739bb49, 0xe039f3b2, 0x7a6f7669}
//#define DUMMY {0x967f0d89, 0xd4afa8a4, 0x00b5bd73, 0x92abc2e2, 0x949d8445}

uint64_t byte_swap_64(uint64_t b)
{
    return ((b & 0xFF00000000000000) >> 56) | ((b & 0xFF000000000000) >> 40) | 
            ((b & 0xFF0000000000) >> 24) | ((b & 0xFF00000000) >> 8) |
            ((b & 0xFF000000) << 8) | ((b & 0xFF0000) << 24) | 
            ((b & 0xFF00) << 40) | ((b & 0xFF) << 56);
}

uint32_t byte_swap_32(uint32_t b)
{
    return ((b & 0xFF000000) >> 24) | ((b & 0xFF0000) >> 8) | ((b & 0xFF00) << 8) | ((b & 0xFF) << 24);
}

uint16_t byte_swap_16(uint16_t b)
{
    return ((b & 0xFF00) >> 8) | ((b & 0xFF) << 8);
}

void print_comms_tree_message(char *in_buffer, size_t size)
{
    char *start = in_buffer;
    CommsResponseRapidSaveTreeMsg *msg = (CommsResponseRapidSaveTreeMsg*) in_buffer;

    printf("\nComms Tree Message:\n");
    printf("\tQueue Number: %d\n", msg->queue);
    printf("\tJob ID: %d\n", msg->job_id);
    printf("\t# Instructions: %lu\n", msg->num_insns);

    in_buffer += sizeof(CommsResponseRapidSaveTreeMsg);

    for(int i=0; i<msg->num_insns; i++)
    {
        CommsResponseRapidSaveTreeInstructionEntry *ti = (CommsResponseRapidSaveTreeInstructionEntry*)in_buffer;
        printf("\tInstruction Label: %s\n", ti->label);

        in_buffer += sizeof(CommsResponseRapidSaveTreeInstructionEntry);

        for(int j=0; j<ti->num_nodes; j++)
        {
            CommsResponseRapidSaveTreeNodeHeader *nh = (CommsResponseRapidSaveTreeNodeHeader*)in_buffer;
            printf("\t\tIndex Offset: %du\n", nh->index_offset);
            printf("\t\tState Offset: %du\n", nh->state_offset);
            printf("\t\tJob ID: %d\n", nh->job_id);
            printf("\t\tTimestamp: %ld\n", nh->timestamp);
            printf("\t\tInstruction Number: %lu\n", nh->instruction_number);
            printf("\t\tException Index: %ld\n", nh->cpu_exception_index);

            CommsResponseRapidSaveTreeNodeState *ns = (CommsResponseRapidSaveTreeNodeState*)(in_buffer + nh->state_offset);
            printf("\t\tState Size: %du\n", ns->size);

            CommsResponseRapidSaveTreeNodeIndex *ni = (CommsResponseRapidSaveTreeNodeIndex*)(in_buffer + nh->index_offset);
            for(int k=0; k<nh->num_indices; k++)
            {
                printf("\t\t\tState Index Name: %s\n", ni->label);
                if(!memcmp(ni->label, "cpu", 3) && ni->label[3] != '_'){
                    // We'll be using this to validate our python VMSD parser.
                    printf("\t\t\t\tRAX is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17])));
                    printf("\t\t\t\tRCX is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8])));
                    printf("\t\t\t\tRDX is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*2])));
                    printf("\t\t\t\tRBX is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*3])));
                    printf("\t\t\t\tRSP is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*4])));
                    printf("\t\t\t\tRBP is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*5])));
                    printf("\t\t\t\tRSI is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*6])));
                    printf("\t\t\t\tRDI is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*7])));
                    printf("\t\t\t\tR8 is  %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*8])));
                    printf("\t\t\t\tR9 is  %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*9])));
                    printf("\t\t\t\tR10 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*10])));
                    printf("\t\t\t\tR11 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*11])));
                    printf("\t\t\t\tR12 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*12])));
                    printf("\t\t\t\tR13 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*13])));
                    printf("\t\t\t\tR14 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*14])));
                    printf("\t\t\t\tR15 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*15])));

                    //VMSTATE_UINTTL(env.eip, X86CPU),
                    printf("\t\t\t\tEIP is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*16])));
                    //VMSTATE_UINTTL(env.eflags, X86CPU),
                    printf("\t\t\t\tEFLAGS is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+17+8*17])));
                    //VMSTATE_UINT32(env.hflags, X86CPU),
                    printf("\t\t\t\tHFLAGS is %X\n", byte_swap_32(*((uint32_t*)&ns->state[ni->offset+17+8*18])));

                    //VMSTATE_UINT16(env.fpuc, X86CPU),
                    printf("\t\t\t\tFPUC is %hX\n", byte_swap_16(*((uint16_t*)&ns->state[ni->offset+21+8*18])));
                    //VMSTATE_UINT16(env.fpus_vmstate, X86CPU),
                    printf("\t\t\t\tFPUS is %hX\n", byte_swap_16(*((uint16_t*)&ns->state[ni->offset+23+8*18])));
                    //VMSTATE_UINT16(env.fptag_vmstate, X86CPU),
                    printf("\t\t\t\tFPTAG is %hX\n", byte_swap_16(*((uint16_t*)&ns->state[ni->offset+25+8*18])));
                    //VMSTATE_UINT16(env.fpregs_format_vmstate, X86CPU),
                    printf("\t\t\t\tFPREGS FMT is %hX\n", byte_swap_16(*((uint16_t*)&ns->state[ni->offset+27+8*18])));

                    //VMSTATE_STRUCT_ARRAY(env.fpregs, X86CPU, 8, 0, vmstate_fpreg, FPReg),
                    printf("\t\t\t\tFPREGS0 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+29+8*18])));
                    printf("\t\t\t\tFPREGS1 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+29+8*19])));
                    printf("\t\t\t\tFPREGS2 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+29+8*20])));
                    printf("\t\t\t\tFPREGS3 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+29+8*21])));
                    printf("\t\t\t\tFPREGS4 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+29+8*22])));
                    printf("\t\t\t\tFPREGS5 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+29+8*23])));
                    printf("\t\t\t\tFPREGS6 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+29+8*24])));
                    printf("\t\t\t\tFPREGS7 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+29+8*25])));

                    //VMSTATE_SEGMENT_ARRAY(env.segs, X86CPU, 6),
                    //printf("\t\t\t\tSEGS is %lX\n", *((uint64_t*)&ns->state[ni->offset+29+8*26]));
                    //VMSTATE_SEGMENT(env.ldt, X86CPU),
                    //printf("\t\t\t\tLDT is %lX\n", *((uint64_t*)&ns->state[ni->offset+149+8*26]));
                    //VMSTATE_SEGMENT(env.tr, X86CPU),
                    //printf("\t\t\t\tTR is %lX\n", *((uint64_t*)&ns->state[ni->offset+169+8*26]));
                    //VMSTATE_SEGMENT(env.gdt, X86CPU),
                    //printf("\t\t\t\tGDT is %lX\n", *((uint64_t*)&ns->state[ni->offset+189+8*26]));
                    //VMSTATE_SEGMENT(env.idt, X86CPU),
                    //printf("\t\t\t\tIDT is %lX\n", *((uint64_t*)&ns->state[ni->offset+209+8*26]));

                    //VMSTATE_UINT32(env.sysenter_cs, X86CPU),
                    printf("\t\t\t\tSYS CS is %X\n", byte_swap_32(*((uint32_t*)&ns->state[ni->offset+245+8*26])));
                    //VMSTATE_UINTTL(env.sysenter_esp, X86CPU),
                    printf("\t\t\t\tSYS ESP is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+249+8*26])));
                    //VMSTATE_UINTTL(env.sysenter_eip, X86CPU),
                    printf("\t\t\t\tSYS EIP is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+249+8*27])));

                    //VMSTATE_UINTTL(env.cr[0], X86CPU),
                    printf("\t\t\t\tCR0 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+249+8*28])));
                    //VMSTATE_UINTTL(env.cr[2], X86CPU),
                    printf("\t\t\t\tCR2 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+249+8*29])));
                    //VMSTATE_UINTTL(env.cr[3], X86CPU),
                    printf("\t\t\t\tCR3 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+249+8*30])));
                    //VMSTATE_UINTTL(env.cr[4], X86CPU),
                    printf("\t\t\t\tCR4 is %lX\n", byte_swap_64(*((uint64_t*)&ns->state[ni->offset+249+8*31])));
                }
/*
                if(!memcmp(ni->label, "cpu", 3)){
                    for(int i=0; i<60; i++){
                        for(int j=0; j<60; j++){
                            printf("%02X", (int)ns->state[ni->offset+245+8*26+i*60+j]);
                        }
                        printf("\n");
                    }
                }
*/
                ni++;
            }

            in_buffer += (nh->state_offset + ns->size + sizeof(CommsResponseRapidSaveTreeNodeState) - 1);
        }
    }
}

void print_comms_report_message(char *in_buffer, size_t size)
{
    int count = 1;
    char *buffer = in_buffer;
    char *end = buffer + size;
    JOB_REPORT_TYPE report_type;

    printf("\nComms Report Message:\n");

    CommsResponseJobReportMsg *crjrin = (CommsResponseJobReportMsg*) buffer;
    printf("\tQueue Number: %d, ", crjrin->queue);
    printf("Instructions: %d, ", crjrin->num_insns);
    printf("Job ID: %d\n", crjrin->job_id);

    buffer += sizeof(CommsResponseJobReportMsg);    

    do
    {
        report_type = *((JOB_REPORT_TYPE *)buffer);

        switch (report_type)
        {
            case JOB_REPORT_PROCESSOR:
                {
                    CommsResponseJobReportProcessorEntry *proc = (CommsResponseJobReportProcessorEntry *)buffer;
                    printf("\tProcessor (%d): %s\n", proc->cpu_id, proc->cpu_name);
                    buffer += sizeof(CommsResponseJobReportProcessorEntry);
                }
                break;
            case JOB_REPORT_REGISTER:
                {
                    CommsResponseJobReportRegisterEntry *reg = (CommsResponseJobReportRegisterEntry *)buffer;
                    buffer += (sizeof(CommsResponseJobReportRegisterEntry) + reg->size - 1);

                    switch(reg->size)
                    {
                        //case 16:
                        //    printf("%s (uint128_t): %lx\n", reg->name, *((uint128_t *)reg->value));
                        //    break;
                        case 8:
                            printf("\t%s (%x): %lx\n", reg->name, reg->id, *((uint64_t *)reg->value));
                            break;
                        case 4:
                            printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint32_t *)reg->value));
                            break;
                        case 2:
                            printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint16_t *)reg->value));
                            break;
                        case 1:
                            printf("\t%s (%x): %x\n", reg->name, reg->id, *((uint8_t *)reg->value));
                            break;
                        default:
                            printf("\t%s (%x): %x\n", reg->name, reg->id, reg->size);
                            break;
                    }
                }
                break;
            case JOB_REPORT_VIRTUAL_MEMORY...JOB_REPORT_PHYSICAL_MEMORY:
                {
                    CommsResponseJobReportMemoryEntry *mem = (CommsResponseJobReportMemoryEntry *)buffer;
                    buffer += (sizeof(CommsResponseJobReportMemoryEntry) + mem->size - 1);

                    printf("\t%lx (%xh B): %lx...\n", mem->offset, mem->size, *((uint64_t *)mem->value));
                }
                break;
            case JOB_REPORT_ERROR:
                {
                    CommsResponseJobReportErrorEntry *err = (CommsResponseJobReportErrorEntry *)buffer;
                    buffer += sizeof(CommsResponseJobReportErrorEntry);

                    printf("\tError %x [%lx]: %s\n", err->error_id, err->error_loc, err->error_text);
                }
                break;
            case JOB_REPORT_EXCEPTION:
                {
                    CommsResponseJobReportExceptionEntry *ee = (CommsResponseJobReportExceptionEntry *)buffer;
                    buffer += sizeof(CommsResponseJobReportExceptionEntry);

                    printf("\tException Mask: %lx\n", ee->exception_mask);
                }
                break;
            default:
                printf("\n\tUnknown Report Type: %d\n", report_type);
                printf("\tEnding Report Here.\n");
                count = 0;
                break;
        }

    } while(buffer < end && count);

    printf("End Report\n");
}

int main(int argc, char *argv[])
{
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[256];
    SHA1_HASH_TYPE dummy = DUMMY;

    struct sockaddr_in serv_addr, cli_addr;
    int n;
    if (argc < 2) {
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }
    if (argc == 3) {
        string_to_hash(argv[2], dummy);	
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
                sizeof(serv_addr)) < 0) 
        error("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, 
            (struct sockaddr *) &cli_addr, 
            &clilen);
    if (newsockfd < 0) 
        error("ERROR on accept");
    bzero(buffer,256);

    CommsMessage *out, *in;

    out = racomms_create_job_add_msg(1, 1, dummy, 0);

    const uint8_t *d = "\x90\x90\x90\x90\x90\xcc";
    out = racomms_msg_job_add_put_MemorySetup(out, 0x7FFFF7FE0000, strlen(d), d, MEMORY_VIRTUAL);

    printf("Sending job add request of %lu bytes!\n", out->size);
    n = write(newsockfd,out,out->size);
    if (n != out->size) error("ERROR writing to socket");
    g_free(out);

    printf("Request %d sent!\n", 1);
    n = read(newsockfd,buffer,sizeof(CommsMessage));
    if (n != sizeof(CommsMessage)) error("ERROR reading from socket");
    in = (CommsMessage*)buffer;
    printf("msg_id = %d\n", in->msg_id);
    printf("size = %lu\n", in->size);
    printf("version = %d\n", in->version);
    printf("Has Next = %d\n", in->has_next_message);
   
    char *result = NULL;
    size_t result_size = read_message(&result, 0, newsockfd, in);
    printf("Read total size of %lu bytes\n", (unsigned long)(result_size+sizeof(CommsMessage)));
    print_comms_report_message(result, result_size);
    free(result);

    printf("All Done!\n");

    out = racomms_create_quit_msg(QUIT_CLEAN);
    printf("Sending quit request of %lu bytes!\n", out->size);
    n = write(newsockfd,out,out->size);
    if (n != out->size) error("ERROR writing to socket");
    g_free(out);

    close(newsockfd);
    close(sockfd);
    return 0;
}

