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

/**
 * This code tests an execution buffer. C source for this executable looks like this.
 * 
 *    #include <stdio.h>
 *    #include <stdlib.h>
 *    #include <memory.h>
 *    #include <fcntl.h>
 *    #include <sys/mman.h>
 ​*
 *    int main(int argc, char *argv[])
 *    {
 *​
 *  	void *m = mmap(NULL, 1<<16, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
 *  	printf("main() is at %lX\n", (unsigned long)main);
 *  	printf("execbuf is at %lX\n", (unsigned long)m);
 *  	printf("Press any key to continue...\n");
 *  	getchar();
 *  	((char*)m)[0] = '\xC3';
 *  	void (*exec_me)(void) = m;
 *  	exec_me();
 *  	printf("I returned!\n");
 *    	return 0;
 *    }
​ *
 * We use getchar as a pause point to interrupt QEMU and insert a breakpoint. We will also have insight into 
 * addresses. We know where main starts so we can place a breakpoint at exec_me(). We will also know the 
 * address of the exec buffer; so, we can insert code into the buffer.
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

#define TEST_TIMEOUT_VAL        (50)

/**
 * Exceptions not currently in RA Comms.
 */
#define X86_GPF                 (1 << 13)
#define X86_PAGE                (1 << 14)
#define X86_TRAP                (1 << 3)

/**
 * Registers not currently in RA Comms.
 */
#define RAX                     (0)
#define RCX                     (1)

/**
 * Code for the exe buffer
 * /

/**
 * mov dword ptr [0], 5
 */
#define TEST_INVALID_WRITE_1    "\xc7\x04\x00\x00\x00\x00\x05\x00\x00\x00"

/**
 * mov rax, 0
 * mov dword [rax], 5
 */
#define TEST_INVALID_WRITE_2    "\48\xc7\xc0\x00\x00\x00\x00\xc7\x00\x05\x00\x00\x00"

/**
 * mov rax, 99 
 * int3 
 * mov rcx, 399
 */
#define TEST_CODE_BP            "\x48\xc7\xc0\x63\x00\x00\x00\xcc\x48\xc7\xc1\x8f\x01\x00\x00"


#define ERROR(...)              { \
                                    printf(__VA_ARGS__); \
                                    printf("\n"); \
                                    return -1; \
                                }

/**
 * This is an example of a test case. In this test case I am looking to see if
 * we have a segmentation fault. If that happens, we can stop looking.
 */
int test1(JOB_REPORT_TYPE report_type, void* message, void **record, int *ret_val)
{
    int continue_looking = TRUE;
    /**
     * For this test, we only care about the exception.
     */
    if (report_type == JOB_REPORT_EXCEPTION)
    {
        /**
         * We found it. Now we want to know what type.
         */
        CommsResponseJobReportExceptionEntry *ee = (CommsResponseJobReportExceptionEntry *) message;
        if ((ee->exception_mask & X86_PAGE) | (ee->exception_mask & X86_GPF))
        {
            /**
             * We have found a segfault. 
             * We found what we wanted and we can stop looking.
             */
            *ret_val = TRUE;
            continue_looking = FALSE;
        }
    }
    /**
     * All done
     */
    return continue_looking;
}

/**
 * This is the record that
 * we'll use for the 3rd test.
 */
typedef struct Test3Record {
    uint8_t rax_found;
    uint8_t rax_satisfied;
    uint8_t rcx_found;
    uint8_t rcx_satisfied;
    uint8_t trap_found;
} Test3Record;

/**
 * This test case will be more complicated. We want to see register values
 * at specific values and we want to see a specific exception.
 */
int test3(JOB_REPORT_TYPE report_type, void* message,  void **record, int *ret_val)
{
    int continue_looking = TRUE;
    
    /**
     * If we don't have record space yet, make it.
     */
    if (!*record)
    {
        *record = g_new0(Test3Record, 1);
    }

    /**
     * We know now that there is memory for the record.
     * We'll cast that memory to something useful.
     */
    Test3Record *rec = (Test3Record *) *record;

    /**
     * Now we can check the report data.
     */
    if (report_type == JOB_REPORT_EXCEPTION)
    {
        /**
         * We found it. Now we want to know what type.
         */
        CommsResponseJobReportExceptionEntry *ee = (CommsResponseJobReportExceptionEntry *) message;
        if (ee->exception_mask & X86_TRAP)
        {
            /**
             * We have found a trap. We can mark it.
             */
            rec->trap_found = TRUE;
        }
    }
    else if (report_type == JOB_REPORT_REGISTER)
    {
        /**
         * We found a register entry. We can check for an expected state.
         */
        CommsResponseJobReportRegisterEntry *reg = (CommsResponseJobReportRegisterEntry *) message;
        
        /**
         * Determine the register that we have found. We only care about
         * RAX and RCX, we can ignore the rest.
         */
        if (reg->id == RAX && !rec->rax_found)
        {
            /**
             * We will indicate that we found RAX.
             */
            rec->rax_found = TRUE;
            
            /**
             * We'll test if RAX is as we expected.
             */
            uint64_t rax_data = 99;
            rec->rax_satisfied = memcmp(reg->value, &rax_data ,sizeof(reg->size)) == 0;

            /**
             * If RAX was not as we expected, no need to continue.
             */
            if (!rec->rax_satisfied)
            {
                continue_looking = FALSE;
                *ret_val = FALSE;
            }
        }
        else if (reg->id == RCX && !rec->rcx_found)
        {
            /**
             * We will indicate that we found RCX.
             */
            rec->rcx_found = TRUE;
            
            /**
             * We'll test if RCX is as we expected.
             */
            uint64_t rcx_data = 0;
            rec->rcx_satisfied = memcmp(reg->value, &rcx_data ,sizeof(reg->size)) == 0;

            /**
             * If RCX was not as we expected, no need to continue.
             */
            if (!rec->rcx_satisfied)
            {
                continue_looking = FALSE;
                *ret_val = FALSE;
            }            
        }
    }  

    /**
     * Now we check exit conditions
     */
    if (rec->rax_found && rec->rcx_found && rec->trap_found)
    {
        /**
         * We have found all the info needed to actually 
         * do our test. We failed out if RAX or RCX was not what 
         * we wanted, so we can assume they are fine. So, in this
         * case we are successful. We can stop looking.
         */
        continue_looking = FALSE;
        *ret_val = TRUE;
    }

    /**
     * All done.
     */
    return continue_looking;
}

int main(int argc, char *argv[])
{
    /**
     * The following code is set up code.
     * 
     * We will parse arguments and start a server.
     * Once QEMU connects, we will begin the command 
     * and control portion.
     */

    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[256];
    SHA1_HASH_TYPE dummy;

    struct sockaddr_in serv_addr, cli_addr;
    int n;
    if (argc < 2) {
        ERROR("ERROR, no port provided\n");
    }
    if (argc == 3) {
	string_to_hash(argv[2], dummy);	
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        ERROR("ERROR opening socket");
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
                sizeof(serv_addr)) < 0) 
        ERROR("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, 
            (struct sockaddr *) &cli_addr, 
            &clilen);
    if (newsockfd < 0) 
        ERROR("ERROR on accept");
    bzero(buffer,256);

    if (!dummy) ERROR("ERROR No hash set.");

    /**
     * Now starts the command and control code.
     * 
     * Sending messages to QEMU will cause a response; so,
     * we'll send a request to QEMU then wait on a response. 
     * The steps we are using to configure QEMU then jobs
     * are as follows.
     * 
     * Step 1: configure QEMU 
     *         a: Timeout when an operation takes too long.
     *            In our example, we're using 50 milliseconds
     *         b: Return interesting data from the test.
     *            In our example, we want proscessor info, register info,
     *            memory info, and exception info.
     *         c: We can parse the configuration response to verify
     *            that QEMU is configured as we expect.
     * Step 2: configure a job
     *         a: add memory adjustments (if any)
     *            In all of our examples, we are adding code into the code
     *            buffer located at 0x7FFFF7FE0000
     *         b: add register adjustments (if any)
     *            In our last example we are setting the state of RAX and RCX
     *         c: add exit on exception constraints
     *            In our first two examples, we expect a seg fault.
     *            In our third example we expect a trap.
     *            In all examples, we quit on an illegal op
     *         d: We can parse the work response for state info and make
     *            informed decisions.
     */ 
    CommsMessage *out, *in;

    /**
     * Here we are creating a config request.
     * We are adding to the config request timeout info and
     * requesting specific data to be returned from the job.
     */
    out = racomms_create_config_request_msg(1);
    racomms_msg_config_request_put_SessionTimeout(out, TEST_TIMEOUT_VAL);
    racomms_msg_config_request_put_ReportMask(out, JOB_REPORT_PROCESSOR | JOB_REPORT_REGISTER | JOB_REPORT_PHYSICAL_MEMORY | JOB_REPORT_EXCEPTION);

    /**
     * Now we write the request to the socket.
     */
    n = write(newsockfd,out,out->size);
    if (n != out->size) ERROR("ERROR writing to socket");
    g_free(out);

    /**
     * Now we read the response back from QEMU.
     * Here we are reading the base message to determine
     * what QEMU has responded with. 
     */
    n = read(newsockfd,buffer,sizeof(CommsMessage));
    if (n != sizeof(CommsMessage)) ERROR("ERROR reading from socket");
    in = (CommsMessage*)buffer;

    /**
     * We can errorcheck the return before assuming we
     * knew what QEMU returned.
     */
    if (in->msg_id != MSG_RESPONSE_CONFIG) ERROR("ERROR in response from QEMU");
    
    /**
     * We can now assume that QEMU is sending the response we expected.
     * we will read the response and can do additional error checking
     * if so desired.
     */
    n = read(newsockfd,buffer,sizeof(CommsResponseConfigMsg));
    if (n != sizeof(CommsResponseConfigMsg)) ERROR("ERROR reading from socket");
    CommsResponseConfigMsg *crcin = (CommsResponseConfigMsg*)buffer;

    /**
     * Here is an example of error checking. Lets say the timeout is critical,
     * we'll error out if QEMU didn't accept our timeout value.
     */
    if (crcin->timeout != TEST_TIMEOUT_VAL) ERROR("There was an error setting the timeout");

    /**
     * Now we will configure a job. We are running against 
     * the exec_me example. In this job we are going to attempt
     * to dereference a null pointer.
     * 
     * So, first we create the job.
     */
    out = racomms_create_job_add_msg(1, 1, dummy, 0);

    /**
     * Now, we want to write the code into the exec buffer.
     * We'll do that by telling QEMU to set the memory as follows.
     */
    out = racomms_msg_job_add_put_MemorySetup(out, 
                                              0x7FFFF7FE0000, 
                                              sizeof(TEST_INVALID_WRITE_1) - 1, 
                                              (uint8_t *) TEST_INVALID_WRITE_1, 
                                              MEMORY_VIRTUAL);

    /**
     * Now, we will set the exit exception constraint. This stops the test
     * if one of the given exceptions occour. The parameter is a mask. We'll stop
     * execution if we generate an illegal instruction. 
     */
    out = racomms_msg_job_add_put_ExitExceptionContrainst(out, X86_ILLEGAL_INSTRUCTION | X86_PAGE | X86_GPF);

    /**
     * Now we write the request to the socket.
     */
    n = write(newsockfd,out,out->size);
    if (n != out->size) ERROR("ERROR writing to socket");
    g_free(out);

    /**
     * Now we read the response back from QEMU.
     * Here we are reading the base message to determine
     * what QEMU has responded with. 
     */
    n = read(newsockfd,buffer,sizeof(CommsMessage));
    if (n != sizeof(CommsMessage)) ERROR("ERROR reading from socket");
    in = (CommsMessage*)buffer;

    /**
     * We can now error check.
     */
    if (in->msg_id != MSG_RESPONSE_REPORT) ERROR("ERROR in response from QEMU");

    /**
     * QEMU is now running the job. We'll wait on QEMU to respond. 
     * Reading the message is a bit involved so, that code is placed
     * in a different function.
     */
    char *result = NULL;
    size_t result_size = read_message(&result, 0, newsockfd, in);
    CommsResponseJobReportMsg *crjrm = (CommsResponseJobReportMsg *) result;

    /**
     * Now we check for a segmentation fault by stepping through the 
     * message. We'll put that in its own function for reusability. We
     * expect an exception, namely, X86_PAGE. If the error doesn't happen
     * we'll exit.
     */
    if (!parse_job_report(crjrm, result_size, test1)) ERROR("Expected a seg fault and it wasn't detected");
    free(result);
    
    /**
     * Now we will configure a different job. We are running against 
     * the exec_me example again. In this job we are going to attempt
     * to dereference a null pointer; but, in a different way.
     * 
     * So, we'll follow the same steps.
     */
    out = racomms_create_job_add_msg(1, 1, dummy, 0);

    /**
     * Now, we want to write the code into the exec buffer.
     * We'll do that by telling QEMU to set the memory as follows.
     */
    out = racomms_msg_job_add_put_MemorySetup(out, 
                                              0x7FFFF7FE0000, 
                                              sizeof(TEST_INVALID_WRITE_2) - 1, 
                                              (uint8_t *) TEST_INVALID_WRITE_2, 
                                              MEMORY_VIRTUAL);

    /**
     * Now, we will set the exit exception constraint. This stops the test
     * if one of the given exceptions occour. The parameter is a mask. We'll stop
     * execution if we generate an illegal instruction. 
     */
    out = racomms_msg_job_add_put_ExitExceptionContrainst(out, X86_ILLEGAL_INSTRUCTION | X86_PAGE | X86_GPF);

    /**
     * Now we write the request to the socket.
     */
    n = write(newsockfd,out,out->size);
    if (n != out->size) ERROR("ERROR writing to socket");
    g_free(out);

    /**
     * Now we read the response back from QEMU.
     * Here we are reading the base message to determine
     * what QEMU has responded with. 
     */
    n = read(newsockfd,buffer,sizeof(CommsMessage));
    if (n != sizeof(CommsMessage)) ERROR("ERROR reading from socket");
    in = (CommsMessage*)buffer;

    /**
     * We can now error check.
     */
    if (in->msg_id != MSG_RESPONSE_REPORT) ERROR("ERROR in response from QEMU");

    /**
     * QEMU is now running the job. We'll wait on QEMU to respond. 
     * Reading the message is a bit involved so, that code is placed
     * in a different function.
     */
    result = NULL;
    result_size = read_message(&result, 0, newsockfd, in);
    crjrm = (CommsResponseJobReportMsg *) result;

    /**
     * Now we check for a segmentation fault by stepping through the 
     * message. We'll put that in its own function for reusability. We
     * expect an exception, namely, X86_PAGE. If the error doesn't happen
     * we'll exit.
     */
    if (!parse_job_report(crjrm, result_size, test1)) ERROR("Expected a seg fault and it wasn't detected");
    free(result);

    /**
     * We are going to configure our last job. In this job we are going to 
     * attempt to insert a breakpoint. We expect the code following the 
     * breakpoint not execute. We'll test this by setting a register 
     * before and after the breakpoint. We expect to see the pre-breakpoint
     * register set.
     * 
     * So, first we create the job.
     */
    out = racomms_create_job_add_msg(1, 1, dummy, 0);

    /**
     * Now, we want to write the code into the exec buffer.
     * We'll do that by telling QEMU to set the memory as follows.
     */
    out = racomms_msg_job_add_put_MemorySetup(out, 
                                              0x7FFFF7FE0000, 
                                              sizeof(TEST_CODE_BP) - 1, 
                                              (uint8_t *) TEST_CODE_BP, 
                                              MEMORY_VIRTUAL);

    /**
     * We'll set up the register data. We'll need some data from QEMU to make this work.
     * From QEMU, we need to know the following:
     *     RAX = 0
     *     RCX = 1 
     * In the future, these values will be available from RA Comms
     */
    NAME_TYPE rax;
    strcpy(rax, "rax");
    NAME_TYPE rcx;
    strcpy(rcx, "rcx");
    uint64_t rax_data = 0;
    uint64_t rcx_data = 0;
    out = racomms_msg_job_add_put_RegisterSetup(out, RAX, rax, 8, (uint8_t *) &rax_data );
    out = racomms_msg_job_add_put_RegisterSetup(out, RCX, rcx, 8, (uint8_t *) &rcx_data );

    /**
     * Now, we will set the exit exception constraint. This stops the test
     * if one of the given exceptions occour. The parameter is a mask. We'll stop
     * execution if we generate an illegal instruction. 
     */
    out = racomms_msg_job_add_put_ExitExceptionContrainst(out, X86_ILLEGAL_INSTRUCTION | X86_PAGE | X86_TRAP);

    /**
     * Now we write the request to the socket.
     */
    n = write(newsockfd,out,out->size);
    if (n != out->size) ERROR("ERROR writing to socket");
    g_free(out);

    /**
     * Now we read the response back from QEMU.
     * Here we are reading the base message to determine
     * what QEMU has responded with. 
     */
    n = read(newsockfd,buffer,sizeof(CommsMessage));
    if (n != sizeof(CommsMessage)) ERROR("ERROR reading from socket");
    in = (CommsMessage*)buffer;

    /**
     * We can now error check.
     */
    if (in->msg_id != MSG_RESPONSE_REPORT) ERROR("ERROR in response from QEMU");

    /**
     * QEMU is now running the job. We'll wait on QEMU to respond. 
     * Reading the message is a bit involved so, that code is placed
     * in a different function.
     */
    result = NULL;
    result_size = read_message(&result, 0, newsockfd, in);
    crjrm = (CommsResponseJobReportMsg *) result;    

    /**
     * Now we check for a trap by stepping through the 
     * message. We'll put that in its own function for reusability. We
     * expect an exception, namely, X86_TRAP. If the error doesn't happen
     * we'll exit.
     */
    if (!parse_job_report(crjrm, result_size, test3)) ERROR("ERROR No trap detected ot registers were not set");
    free(result);

    /**
     * We can shutdown QEMU by doing the following.
     */
    out = racomms_create_quit_msg(QUIT_CLEAN);
    n = write(newsockfd,out,out->size);
    if (n != out->size) ERROR("ERROR writing to socket");
    g_free(out);

    /**
     * Normal socket cleanup
     */
    close(newsockfd);
    close(sockfd);
    return 0;
}

