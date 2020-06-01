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
 *  Daniel Reyes
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 * 
 * The creation of this code was funded by the US Government.
 */

/*
 * RA-AFL: QEMU RA Plugin
 *
 * This is NOT an integration of AFL inside Shoggoth rapid analysis engine. It is instead a
 * fuzzer implementation that makes use of fuzzing strategies and mutations used in AFL. Please
 * refer to `https://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html` for
 * more information on strategies used.
 */

// This is the interface to QEMU
#include "plugin/plugin-object.h"
#include "qemu/qemu-plugin.h"
#include "qom/object_interfaces.h"
#include "qapi/qmp/qpointer.h"
#include "qapi/qmp/qlist.h"

static void str_to_hash(const char *, SHA1_HASH_TYPE);

// These macros define object operations
#define TYPE_AFL "afl-plugin"

#define AFL(obj)                                    \
    OBJECT_CHECK(AflPlugin, (obj), TYPE_AFL)
#define AFL_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(AflPluginClass, klass, TYPE_AFL)
#define AFL_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(AflPluginClass, obj, TYPE_AFL)

// This is for opts
#define AFL_OPTS  ("afl")

#define BIN (0x7fffffffffff - 0x555555555000) / 655
// Object type data
typedef struct AflPlugin AflPlugin;
typedef struct AflPluginClass AflPluginClass;
typedef struct FuzzerState FuzzerState;
typedef struct TestCase TestCase;

// Fuzzer enums and structs

enum WalkingBits {
    SINGLE_FLIP = (255 >> 7),
    DOUBLE_FLIP = (255 >> 6),
    QUAD_FLIP   = (255 >> 4),
    BYTE_FLIP   = (255 >> 0)
};

enum StageFlags {
    STAGE_BITFLIP    = (1 << 0),
    STAGE_ARITHMETIC = (1 << 1),
    STAGE_KNOWN_INTS = (1 << 2),
    STAGE_HAVOC      = (1 << 3),
};

struct TestCase
{
    int id;
    const char *filename;

    size_t input_len;
    uint8_t *input;

    bool being_fuzzed;
};


struct FuzzerState
{
    unsigned char stage;
    unsigned char walk_amount;
    bool tried_all_ints;

    unsigned int crashes;
    unsigned int unique_crashes;

    unsigned int runs;

    unsigned char step;
    unsigned int offset;
    unsigned int instruction_count;

    unsigned int bin_hit[656];

    char *mutated_input;
    TestCase *testcase;
};

/* Object setup: define properties */
struct AflPlugin
{
    PluginObject obj;

    CommsQueue *ra_queue;
    SHA1_HASH_TYPE fresh_state;

    const char *fileno;
    const char *outpath;
    QList *testcases;
    FuzzerState fuzzer;
};

/* Object setup: define methods */
struct AflPluginClass
{
    PluginObjectClass parent;

    void (*fuzz)(AflPlugin *aflp, FuzzerState *fs, TestCase *tc);
    void (*run_testcase)(AflPlugin *aflp, FuzzerState *fs, TestCase *tc, int fd);
    bool (*next_stage)(FuzzerState *fs);
    void (*update_console)(AflPlugin *aflp, CommsMessage *msg);
};

/* Utils functions */


static void str_to_hash(const char *str, SHA1_HASH_TYPE hash)
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

static inline void walking_bit_flip(char *input, uint64_t offset, uint8_t step, uint8_t nbits)
{
    input[offset] ^= (nbits << step);
}

static inline void simple_arithmatic(char *input, uint64_t offset)
{
    signed int difference = rand() % 71 + (-35);
    input[offset] += difference;
}

/* TODO: needs to be fixed, indexing is not correct */
static inline void known_ints(char *input, uint64_t offset)
{
    short cond = rand() % 3;
    char one_byte[] = {-1, 255};
    short two_byte[] = {1024, 2048};
    int four_byte[] = {INT_MAX, INT_MAX-1, INT_MIN, INT_MIN+1};

    /* 1 byte known ints */
    if (cond == 0) {
        input[offset] = one_byte[rand() % 2];
    }
    /* 2 byte known ints */
    else if (cond == 1) {
            input[offset] = two_byte[rand() % 2];

    }
    /* 4 byte known ints */
    else if (cond == 2) {
        if (offset != 0)
            input[offset] = four_byte[rand() % 4];
    }
}

static void havoc(char *input, int size)
{
    for (int i=0; i < size; i++) {
        input[i] = rand() % 255;
    }
}

/* mutate testcase input, run, check for change, add mutated testcase to queue if intresting */
static void fuzz(AflPlugin *aflp, FuzzerState *fuzzer, TestCase *tc)
{
    AflPluginClass *afl_klass = AFL_GET_CLASS(aflp);

    switch (fuzzer->stage)
    {
    case STAGE_BITFLIP:
        walking_bit_flip(fuzzer->mutated_input, fuzzer->offset, fuzzer->step, fuzzer->walk_amount);
        break;
    case STAGE_ARITHMETIC:
        simple_arithmatic(fuzzer->mutated_input, fuzzer->offset); /* Implmentation of this stage can be imporoved */
        break;
    case STAGE_KNOWN_INTS:
        known_ints(fuzzer->mutated_input, fuzzer->offset);
        break;
    case STAGE_HAVOC:
        havoc(fuzzer->mutated_input, fuzzer->testcase->input_len);
        break;
    }

    fuzzer->instruction_count = 0;
    afl_klass->run_testcase(aflp, fuzzer, tc, atoi(aflp->fileno));
}

/* execute function, loads mutated input into memory, and execute testcase */
static void run_testcase(AflPlugin *aflp, FuzzerState *fs, TestCase *tc, int fd)
{
    CommsMessage *out = racomms_create_job_add_msg(1, fs->runs, aflp->fresh_state, 0);
    out = racomms_msg_job_add_put_StreamSetup(out,
                                        fd,
                                        tc->input_len,
                                        (uint8_t *)fs->mutated_input);

    aflp->ra_queue = get_comms_queue(0);
    racomms_queue_add_job(aflp->ra_queue, out);
}

/* Returns 0 if switched to next stage, and 1 if stayed on current stage */
static bool next_stage(FuzzerState *fs)
{
    if (fs->stage == STAGE_BITFLIP && fs->walk_amount != BYTE_FLIP) {
        if (fs->walk_amount == SINGLE_FLIP)
            fs->walk_amount = DOUBLE_FLIP;
        else if (fs->walk_amount == DOUBLE_FLIP)
            fs->walk_amount = QUAD_FLIP;
        else
            fs->walk_amount = BYTE_FLIP;

        return 1;
    }
    else if (fs->stage == STAGE_HAVOC) {
        return 1;
    }

    fs->stage = fs->stage << 1;

    return 0;
}

static void write_test_case(AflPlugin *aflp, FuzzerState *fs, TestCase *tc)
{
    char outpath[4096];
    char outfile[512];
    FILE *fd;

    memset(outpath, 0, 4096);
    strcpy(outpath, aflp->outpath);
    sprintf(outfile, "%d", tc->id);

    strcat(outpath, outfile);
    fd = fopen(outpath, "w");
    fwrite(fs->mutated_input, 1, tc->input_len, fd);

    fclose(fd);
}

static void update_report_console(AflPlugin *aflp, CommsMessage *msg)
{
    FuzzerState *fuzzer = &(aflp->fuzzer);
    TestCase *tc = fuzzer->testcase;
    const char *stage;

    if (fuzzer->stage == STAGE_BITFLIP)
        stage = "bitflip";
    else if (fuzzer->stage == STAGE_ARITHMETIC)
        stage = "simple arithmatic";
    else if (fuzzer->stage == STAGE_KNOWN_INTS)
        stage = "known integers";

    int count = 1;
    JOB_REPORT_TYPE report_type;

    CommsResponseJobReportMsg *crjrin = (CommsResponseJobReportMsg *)(msg+1);

    char *buffer = (char *)crjrin;
    char *end = buffer + (msg->size - sizeof(CommsMessage));

    buffer += sizeof(CommsResponseJobReportMsg);

   do
    {
        report_type = *((JOB_REPORT_TYPE *)buffer);

        switch (report_type)
        {
            case JOB_REPORT_PROCESSOR:
               {
                    // CommsResponseJobReportProcessorEntry *proc = (CommsResponseJobReportProcessorEntry *)buffer;
                    // printf("\tProcessor (%d): %s\n", proc->cpu_id, proc->cpu_name);
                    buffer += sizeof(CommsResponseJobReportProcessorEntry);
                }
                break;
            case JOB_REPORT_EXCEPTION:
                {
                    CommsResponseJobReportExceptionEntry *ee = (CommsResponseJobReportExceptionEntry *)buffer;
                    buffer += sizeof(CommsResponseJobReportExceptionEntry);

                    if(ee->exception_mask & (1<<13)){
                        fuzzer->crashes++;
                        write_test_case(aflp, fuzzer, tc);
                    }
                }
                break;
            default:
                count = 0;
                break;
        }

    } while(buffer < end && count);

    printf("\t\tAFL Report Console\n");

    printf("Fuzz job: %d\n", fuzzer->runs);
    printf("Mutation stage: %s\n", stage);
    printf("Instructions executed: %d\n", fuzzer->instruction_count);

    printf("Crashes: %d\n", fuzzer->crashes);
    printf("Unique crashes: %d\n", fuzzer->unique_crashes);

}

static JOB_REPORT_TYPE afl_get_ra_report_type(void *opaque)
{
    return JOB_REPORT_EXCEPTION | JOB_REPORT_PROCESSOR;
}

/* If final state is intresting, add mutated testcase to queue to be fuzzed */
static void afl_on_ra_stop(void *opaque, CommsResultsItem *work_results)
{
    AflPlugin *aflp = AFL(opaque);
    AflPluginClass *afl_klass = AFL_GET_CLASS(opaque);

    FuzzerState *fuzzer = &(aflp->fuzzer);
    TestCase *tc = fuzzer->testcase;

    CommsMessage *msg = work_results->msg;
    afl_klass->update_console(aflp, msg);

    switch (fuzzer->stage)
    {
    case STAGE_BITFLIP:
        if (fuzzer->walk_amount == BYTE_FLIP || fuzzer->step >= 7) {
            fuzzer->step = 0;
            fuzzer->offset++;
        }
        else if (fuzzer->step < 7) {
            fuzzer->step++;
        }
        break;
    case STAGE_ARITHMETIC:
        // preform around 20 excve's per byte... impliment can be improved
        if (rand() % 20 == 0)
            fuzzer->offset++;
        break;
    case STAGE_KNOWN_INTS:
        if (fuzzer->tried_all_ints)
            fuzzer->offset++;
        break;
    case STAGE_HAVOC:
        // perorm around 100 havoc executions, stage likly dosnt produce and time on next testcase
        if (rand() % 100 == 0) {
            tc->being_fuzzed = 0;
        }
        break;
    }
    if (fuzzer->offset >= tc->input_len) {
        fuzzer->offset = 0;
        afl_klass->next_stage(&(aflp->fuzzer));
    }

    fuzzer->runs++;
}

static void afl_on_ra_start(void *opaque, CommsWorkItem *work)
{
    AflPlugin *aflp = AFL(opaque);
    FuzzerState *fuzzer = &(aflp->fuzzer);

    fuzzer->instruction_count = 0;
}

static void afl_on_ra_idle(void *opaque)
{
    AflPlugin *aflp = AFL(opaque);
    AflPluginClass *afl_klass = AFL_GET_CLASS(opaque);

    FuzzerState *fs = &(aflp->fuzzer);

    if (! fs->testcase->being_fuzzed) {
        free(fs->mutated_input);
        free(fs->testcase->input);

        fs->stage = STAGE_BITFLIP;
        fs->walk_amount = SINGLE_FLIP;

        QPointer *this_qptr  = qobject_to(QPointer, qlist_pop(aflp->testcases));
        TestCase *this_testcase = qpointer_get_pointer(this_qptr);

        fs->testcase->id = fs->runs;
        fs->testcase = this_testcase;
        fs->testcase->being_fuzzed = 1;

        fs->mutated_input = malloc(fs->testcase->input_len);
    }

    memcpy(fs->mutated_input, fs->testcase->input, fs->testcase->input_len);
    afl_klass->fuzz(aflp, fs, fs->testcase);
}

static void afl_on_execute_instruction(void *opaque,  uint64_t vaddr, void *addr)
{
    AflPlugin *aflp = AFL(opaque);
    FuzzerState *fs = &(aflp->fuzzer);

    uint64_t addr_min = 0x555555555000;
    uint64_t addr_max = 0x7fffffffffff;

    if (vaddr > addr_max || vaddr < addr_min) {
        return;
    }
    else {
        uint64_t hit = (vaddr - addr_min) / BIN;
        fs->bin_hit[hit]++;
        fs->instruction_count++;
    }
    fs->instruction_count++;
}

/* Plugin setup functions */

static void afl_set_callbacks(void *opaque, PluginCallbacks *callbacks)
{
    callbacks->on_execute_instruction = afl_on_execute_instruction;
    callbacks->get_ra_report_type = afl_get_ra_report_type;
    callbacks->on_ra_start = afl_on_ra_start;
    callbacks->on_ra_stop = afl_on_ra_stop;
    callbacks->on_ra_idle = afl_on_ra_idle;
}

static bool load_testcase_files(AflPlugin *aflp, const char *indir)
{
    char inpath[4096];
    char *infile;
    TestCase *tc = NULL;

    FILE *fp;
    DIR *d;
    struct dirent *dir;

    /* Setup provided testcases */
    memset(inpath, 0, 4096);
    strcpy(inpath, indir);

    d = opendir(inpath);
    if (!d) {
        printf("failed to open directory, does it exist?\n");
        exit(1);
    }

    while ((dir = readdir(d)) != NULL)
    {
        memset(inpath, 0, 4096);
        strcpy(inpath, indir);
        infile = dir->d_name;

        if (!strcmp(infile, "..") || !strcmp(infile, ".")) {
            continue;
        } else {
            fp = fopen(strcat(inpath, dir->d_name), "r"); /* make safe */
            tc = g_new0(TestCase, 1);

            fseek(fp, 0L, SEEK_END);
            tc->input_len = ftell(fp);
            fseek(fp, 0L, SEEK_SET);

            tc->input = malloc(tc->input_len);
            fread(tc->input, 1, tc->input_len, fp);

            tc->being_fuzzed = 0;

            qlist_append(aflp->testcases, qpointer_from_pointer((void *)tc, free));
            fclose(fp);
        }
    }
    closedir(d);

    return true;
}

/* Initialization of actual fuzzer */
static bool afl_init_plugin(void *opaque, const char *path, QemuOpts *opts)
{
    AflPlugin *aflp = AFL(opaque);
    FuzzerState *fuzzer = &(aflp->fuzzer);

    if (qemu_opt_get(opts, "i") == NULL || qemu_opt_get(opts, "hash") == NULL) {
        printf("[!] Error: Pleas specifiy testcase input directory (i) and rsave hash (hash)\n");
        exit(1);
    }

    /* read input testcases */
    load_testcase_files(aflp, qemu_opt_get(opts, "i"));

    /* grab first testcase in queue and prepare fuzzer to start */
    QPointer *this_qptr  = qobject_to(QPointer, qlist_pop(aflp->testcases));
    TestCase *this_testcase = qpointer_get_pointer(this_qptr);

    fuzzer->testcase = this_testcase;
    fuzzer->testcase->being_fuzzed = 1;
    fuzzer->mutated_input = malloc(fuzzer->testcase->input_len);

    fuzzer->stage = STAGE_BITFLIP;
    fuzzer->walk_amount = SINGLE_FLIP;

    aflp->fileno = qemu_opt_get(opts, "fd");
    aflp->outpath = qemu_opt_get(opts, "o");
    /* setup snapshot hash */
    // str_to_hash(qemu_opt_get(opts, "snapshot_hash");
    str_to_hash(qemu_opt_get(opts, "hash"), aflp->fresh_state);

    return true;
}

/* Object setup: initialize attributes */
static void afl_init_properties(Object *obj)
{
    AflPlugin *aflp = AFL(obj);
    FuzzerState *fuzzer = &(aflp->fuzzer);

    aflp->ra_queue = get_comms_queue(0);
    aflp->testcases = qlist_new();

    fuzzer->runs = 0;
}

/* Object setup: initialize methods */
static void afl_init_methods(ObjectClass *klass, void *class_data G_GNUC_UNUSED)
{
    PluginObjectClass *p_klass = PLUGIN_OBJECT_CLASS(klass);
    AflPluginClass *afl_klass = AFL_CLASS(klass);

    p_klass->init_plugin = afl_init_plugin;
    p_klass->set_callbacks = afl_set_callbacks;

    afl_klass->fuzz = fuzz;
    afl_klass->run_testcase = run_testcase;
    afl_klass->next_stage = next_stage;
    afl_klass->update_console = update_report_console;
}


/* deconstruct class if needed */
static void afl_finalize(Object *obj)
{
    AflPlugin *aflp = AFL(obj);

    qobject_unref(aflp->testcases);
    aflp->testcases = NULL;
}

// Object setup: Object info
static TypeInfo afl_info = {
    .parent = TYPE_PLUGIN_OBJECT,
    .name = TYPE_AFL,
    .instance_size = sizeof(AflPlugin),
    .instance_init = afl_init_properties,
    .instance_finalize = afl_finalize,
    .class_init = afl_init_methods,
    .class_size = sizeof(AflPluginClass)
};

// Setup options to configure the plugin
static QemuOptsList qemu_afl_opts = {
    .name = AFL_OPTS,
    .implied_opt_name = "config",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_afl_opts.head),
    .desc = {
        {
            .name = "config",
            .type = QEMU_OPT_STRING,
            .help = "Provides configuration for AFL",
        },
        {
            .name = "i",
            .type = QEMU_OPT_STRING,
            .help = "Input directory for testcases"
        },
        {
            .name = "o",
            .type = QEMU_OPT_STRING,
            .help = "Output directory for testcase results"
        },
        {
            .name = "hash",
            .type = QEMU_OPT_STRING,
            .help = "Initial state of RA session. This has to be a fuzzable state"
        },
        { // Figure out how to add replay
            .name = "replay",
            .type = QEMU_OPT_STRING,
            .help = "Replay specific testcase, provide input seed"
        },
        {
            .name = "fd",
            .type = QEMU_OPT_STRING,
            .help = "File descriptor to hijack"
        },
        { /* end of list */ }
    },
};

bool plugin_setup(void *plugin, const char *path)
{
    qemu_plugin_register_type(plugin, &afl_info);
    qemu_plugin_register_options(plugin, &qemu_afl_opts);

    return true;
}
