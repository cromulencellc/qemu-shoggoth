/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2011-2015 Red Hat Inc
 *
 * Authors:
 *  Juan Quintela <quintela@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include <zlib.h>
#include "qemu/cutils.h"
#include "qemu/bitops.h"
#include "qemu/bitmap.h"
#include "qemu/main-loop.h"
#include "qemu/pmem.h"
#include "xbzrle.h"
#include "ram.h"
#include "ram_xbzrle.h"
#include "ram_rapid.h"
#include "migration.h"
#include "socket.h"
#include "migration/register.h"
#include "migration/misc.h"
#include "qemu-file.h"
#include "postcopy-ram.h"
#include "migration/page_cache.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qapi/qapi-events-migration.h"
#include "qapi/qmp/qerror.h"
#include "trace.h"
#include "exec/ram_addr.h"
#include "exec/target_page.h"
#include "qemu/rcu_queue.h"
#include "migration/colo.h"
#include "migration/block.h"
#include "sysemu/sysemu.h"
#include "ra.h"
#include "qemu/uuid.h"
#include "savevm.h"
#include "qemu/iov.h"
#include "qemu/units.h"

bool ramblock_is_ignored(RAMBlock *block)
{
    return !qemu_ram_is_migratable(block) ||
           (migrate_ignore_shared() && qemu_ram_is_shared(block));
}

/* Should be holding either ram_list.mutex, or the RCU lock. */
#define RAMBLOCK_FOREACH_NOT_IGNORED(block)            \
    INTERNAL_RAMBLOCK_FOREACH(block)                   \
        if (ramblock_is_ignored(block)) {} else

#define RAMBLOCK_FOREACH_MIGRATABLE(block)             \
    INTERNAL_RAMBLOCK_FOREACH(block)                   \
        if (!qemu_ram_is_migratable(block)) {} else

#undef RAMBLOCK_FOREACH

int foreach_not_ignored_block(RAMBlockIterFunc func, void *opaque)
{
    RAMBlock *block;
    int ret = 0;

    rcu_read_lock();
    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        ret = func(block, opaque);
        if (ret) {
            break;
        }
    }
    rcu_read_unlock();
    return ret;
}

static NotifierWithReturnList precopy_notifier_list;

void precopy_infrastructure_init(void)
{
    notifier_with_return_list_init(&precopy_notifier_list);
}

void precopy_add_notifier(NotifierWithReturn *n)
{
    notifier_with_return_list_add(&precopy_notifier_list, n);
}

void precopy_remove_notifier(NotifierWithReturn *n)
{
    notifier_with_return_remove(n);
}

int precopy_notify(PrecopyNotifyReason reason, Error **errp)
{
    PrecopyNotifyData pnd;
    pnd.reason = reason;
    pnd.errp = errp;

    return notifier_with_return_list_notify(&precopy_notifier_list, &pnd);
}

void precopy_enable_free_page_optimization(void)
{
    if( is_rapid_analysis_active() ) { 
        return ram_rapid_precopy_enable_free_page_optimization();
    }

    return ram_xbzrle_precopy_enable_free_page_optimization();
}

uint64_t ram_bytes_remaining(void)
{
    if( is_rapid_analysis_active() ) { 
        return get_ram_rapid_dirty_pages() * TARGET_PAGE_SIZE;
    }

    return get_ram_dirty_pages() * TARGET_PAGE_SIZE;
}

MigrationStats ram_counters;

uint64_t ram_bytes_total(void)
{
    RAMBlock *block;
    uint64_t total = 0;

    rcu_read_lock();
    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        total += block->used_length;
    }
    rcu_read_unlock();
    return total;
}

uint64_t ram_bytes_total_ignored(void)
{
    RAMBlock *block;
    uint64_t total = 0;

    rcu_read_lock();
    RAMBLOCK_FOREACH_MIGRATABLE(block) {
        total += block->used_length;
    }
    rcu_read_unlock();
    return total;
}

/* Multiple fd's */

#define MULTIFD_MAGIC 0x11223344U
#define MULTIFD_VERSION 1

#define MULTIFD_FLAG_SYNC (1 << 0)

/* This value needs to be a multiple of qemu_target_page_size() */
#define MULTIFD_PACKET_SIZE (512 * KiB)

typedef struct {
    uint32_t magic;
    uint32_t version;
    unsigned char uuid[16]; /* QemuUUID */
    uint8_t id;
    uint8_t unused1[7];     /* Reserved for future use */
    uint64_t unused2[4];    /* Reserved for future use */
} __attribute__((packed)) MultiFDInit_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    /* maximum number of allocated pages */
    uint32_t pages_alloc;
    uint32_t pages_used;
    /* size of the next packet that contains pages */
    uint32_t next_packet_size;
    uint64_t packet_num;
    uint64_t unused[4];    /* Reserved for future use */
    char ramblock[256];
    uint64_t offset[];
} __attribute__((packed)) MultiFDPacket_t;

typedef struct {
    /* number of used pages */
    uint32_t used;
    /* number of allocated pages */
    uint32_t allocated;
    /* global number of generated multifd packets */
    uint64_t packet_num;
    /* offset of each page */
    ram_addr_t *offset;
    /* pointer to each page */
    struct iovec *iov;
    RAMBlock *block;
} MultiFDPages_t;

typedef struct {
    /* this fields are not changed once the thread is created */
    /* channel number */
    uint8_t id;
    /* channel thread name */
    char *name;
    /* channel thread id */
    QemuThread thread;
    /* communication channel */
    QIOChannel *c;
    /* sem where to wait for more work */
    QemuSemaphore sem;
    /* this mutex protects the following parameters */
    QemuMutex mutex;
    /* is this channel thread running */
    bool running;
    /* should this thread finish */
    bool quit;
    /* thread has work to do */
    int pending_job;
    /* array of pages to sent */
    MultiFDPages_t *pages;
    /* packet allocated len */
    uint32_t packet_len;
    /* pointer to the packet */
    MultiFDPacket_t *packet;
    /* multifd flags for each packet */
    uint32_t flags;
    /* size of the next packet that contains pages */
    uint32_t next_packet_size;
    /* global number of generated multifd packets */
    uint64_t packet_num;
    /* thread local variables */
    /* packets sent through this channel */
    uint64_t num_packets;
    /* pages sent through this channel */
    uint64_t num_pages;
    /* syncs main thread and channels */
    QemuSemaphore sem_sync;
}  MultiFDSendParams;

typedef struct {
    /* this fields are not changed once the thread is created */
    /* channel number */
    uint8_t id;
    /* channel thread name */
    char *name;
    /* channel thread id */
    QemuThread thread;
    /* communication channel */
    QIOChannel *c;
    /* this mutex protects the following parameters */
    QemuMutex mutex;
    /* is this channel thread running */
    bool running;
    /* array of pages to receive */
    MultiFDPages_t *pages;
    /* packet allocated len */
    uint32_t packet_len;
    /* pointer to the packet */
    MultiFDPacket_t *packet;
    /* multifd flags for each packet */
    uint32_t flags;
    /* global number of generated multifd packets */
    uint64_t packet_num;
    /* thread local variables */
    /* size of the next packet that contains pages */
    uint32_t next_packet_size;
    /* packets sent through this channel */
    uint64_t num_packets;
    /* pages sent through this channel */
    uint64_t num_pages;
    /* syncs main thread and channels */
    QemuSemaphore sem_sync;
} MultiFDRecvParams;

static int multifd_send_initial_packet(MultiFDSendParams *p, Error **errp)
{
    MultiFDInit_t msg;
    int ret;

    msg.magic = cpu_to_be32(MULTIFD_MAGIC);
    msg.version = cpu_to_be32(MULTIFD_VERSION);
    msg.id = p->id;
    memcpy(msg.uuid, &qemu_uuid.data, sizeof(msg.uuid));

    ret = qio_channel_write_all(p->c, (char *)&msg, sizeof(msg), errp);
    if (ret != 0) {
        return -1;
    }
    return 0;
}

static int multifd_recv_initial_packet(QIOChannel *c, Error **errp)
{
    MultiFDInit_t msg;
    int ret;

    ret = qio_channel_read_all(c, (char *)&msg, sizeof(msg), errp);
    if (ret != 0) {
        return -1;
    }

    msg.magic = be32_to_cpu(msg.magic);
    msg.version = be32_to_cpu(msg.version);

    if (msg.magic != MULTIFD_MAGIC) {
        error_setg(errp, "multifd: received packet magic %x "
                   "expected %x", msg.magic, MULTIFD_MAGIC);
        return -1;
    }

    if (msg.version != MULTIFD_VERSION) {
        error_setg(errp, "multifd: received packet version %d "
                   "expected %d", msg.version, MULTIFD_VERSION);
        return -1;
    }

    if (memcmp(msg.uuid, &qemu_uuid, sizeof(qemu_uuid))) {
        char *uuid = qemu_uuid_unparse_strdup(&qemu_uuid);
        char *msg_uuid = qemu_uuid_unparse_strdup((const QemuUUID *)msg.uuid);

        error_setg(errp, "multifd: received uuid '%s' and expected "
                   "uuid '%s' for channel %hhd", msg_uuid, uuid, msg.id);
        g_free(uuid);
        g_free(msg_uuid);
        return -1;
    }

    if (msg.id > migrate_multifd_channels()) {
        error_setg(errp, "multifd: received channel version %d "
                   "expected %d", msg.version, MULTIFD_VERSION);
        return -1;
    }

    return msg.id;
}

static MultiFDPages_t *multifd_pages_init(size_t size)
{
    MultiFDPages_t *pages = g_new0(MultiFDPages_t, 1);

    pages->allocated = size;
    pages->iov = g_new0(struct iovec, size);
    pages->offset = g_new0(ram_addr_t, size);

    return pages;
}

static void multifd_pages_clear(MultiFDPages_t *pages)
{
    pages->used = 0;
    pages->allocated = 0;
    pages->packet_num = 0;
    pages->block = NULL;
    g_free(pages->iov);
    pages->iov = NULL;
    g_free(pages->offset);
    pages->offset = NULL;
    g_free(pages);
}

static void multifd_send_fill_packet(MultiFDSendParams *p)
{
    MultiFDPacket_t *packet = p->packet;
    uint32_t page_max = MULTIFD_PACKET_SIZE / qemu_target_page_size();
    int i;

    packet->magic = cpu_to_be32(MULTIFD_MAGIC);
    packet->version = cpu_to_be32(MULTIFD_VERSION);
    packet->flags = cpu_to_be32(p->flags);
    packet->pages_alloc = cpu_to_be32(page_max);
    packet->pages_used = cpu_to_be32(p->pages->used);
    packet->next_packet_size = cpu_to_be32(p->next_packet_size);
    packet->packet_num = cpu_to_be64(p->packet_num);

    if (p->pages->block) {
        strncpy(packet->ramblock, p->pages->block->idstr, 256);
    }

    for (i = 0; i < p->pages->used; i++) {
        packet->offset[i] = cpu_to_be64(p->pages->offset[i]);
    }
}

static int multifd_recv_unfill_packet(MultiFDRecvParams *p, Error **errp)
{
    MultiFDPacket_t *packet = p->packet;
    uint32_t pages_max = MULTIFD_PACKET_SIZE / qemu_target_page_size();
    RAMBlock *block;
    int i;

    packet->magic = be32_to_cpu(packet->magic);
    if (packet->magic != MULTIFD_MAGIC) {
        error_setg(errp, "multifd: received packet "
                   "magic %x and expected magic %x",
                   packet->magic, MULTIFD_MAGIC);
        return -1;
    }

    packet->version = be32_to_cpu(packet->version);
    if (packet->version != MULTIFD_VERSION) {
        error_setg(errp, "multifd: received packet "
                   "version %d and expected version %d",
                   packet->version, MULTIFD_VERSION);
        return -1;
    }

    p->flags = be32_to_cpu(packet->flags);

    packet->pages_alloc = be32_to_cpu(packet->pages_alloc);
    /*
     * If we recevied a packet that is 100 times bigger than expected
     * just stop migration.  It is a magic number.
     */
    if (packet->pages_alloc > pages_max * 100) {
        error_setg(errp, "multifd: received packet "
                   "with size %d and expected a maximum size of %d",
                   packet->pages_alloc, pages_max * 100) ;
        return -1;
    }
    /*
     * We received a packet that is bigger than expected but inside
     * reasonable limits (see previous comment).  Just reallocate.
     */
    if (packet->pages_alloc > p->pages->allocated) {
        multifd_pages_clear(p->pages);
        p->pages = multifd_pages_init(packet->pages_alloc);
    }

    p->pages->used = be32_to_cpu(packet->pages_used);
    if (p->pages->used > packet->pages_alloc) {
        error_setg(errp, "multifd: received packet "
                   "with %d pages and expected maximum pages are %d",
                   p->pages->used, packet->pages_alloc) ;
        return -1;
    }

    p->next_packet_size = be32_to_cpu(packet->next_packet_size);
    p->packet_num = be64_to_cpu(packet->packet_num);

    if (p->pages->used) {
        /* make sure that ramblock is 0 terminated */
        packet->ramblock[255] = 0;
        block = qemu_ram_block_by_name(packet->ramblock);
        if (!block) {
            error_setg(errp, "multifd: unknown ram block %s",
                       packet->ramblock);
            return -1;
        }
    }

    for (i = 0; i < p->pages->used; i++) {
        ram_addr_t offset = be64_to_cpu(packet->offset[i]);

        if (offset > (block->used_length - TARGET_PAGE_SIZE)) {
            error_setg(errp, "multifd: offset too long " RAM_ADDR_FMT
                       " (max " RAM_ADDR_FMT ")",
                       offset, block->max_length);
            return -1;
        }
        p->pages->iov[i].iov_base = block->host + offset;
        p->pages->iov[i].iov_len = TARGET_PAGE_SIZE;
    }

    return 0;
}

struct {
    MultiFDSendParams *params;
    /* number of created threads */
    int count;
    /* array of pages to sent */
    MultiFDPages_t *pages;
    /* syncs main thread and channels */
    QemuSemaphore sem_sync;
    /* global number of generated multifd packets */
    uint64_t packet_num;
    /* send channels ready */
    QemuSemaphore channels_ready;
} *multifd_send_state;

/*
 * How we use multifd_send_state->pages and channel->pages?
 *
 * We create a pages for each channel, and a main one.  Each time that
 * we need to send a batch of pages we interchange the ones between
 * multifd_send_state and the channel that is sending it.  There are
 * two reasons for that:
 *    - to not have to do so many mallocs during migration
 *    - to make easier to know what to free at the end of migration
 *
 * This way we always know who is the owner of each "pages" struct,
 * and we don't need any loocking.  It belongs to the migration thread
 * or to the channel thread.  Switching is safe because the migration
 * thread is using the channel mutex when changing it, and the channel
 * have to had finish with its own, otherwise pending_job can't be
 * false.
 */

static void multifd_send_pages(void)
{
    int i;
    static int next_channel;
    MultiFDSendParams *p = NULL; /* make happy gcc */
    MultiFDPages_t *pages = multifd_send_state->pages;
    uint64_t transferred;

    qemu_sem_wait(&multifd_send_state->channels_ready);
    for (i = next_channel;; i = (i + 1) % migrate_multifd_channels()) {
        p = &multifd_send_state->params[i];

        qemu_mutex_lock(&p->mutex);
        if (!p->pending_job) {
            p->pending_job++;
            next_channel = (i + 1) % migrate_multifd_channels();
            break;
        }
        qemu_mutex_unlock(&p->mutex);
    }
    p->pages->used = 0;

    p->packet_num = multifd_send_state->packet_num++;
    p->pages->block = NULL;
    multifd_send_state->pages = p->pages;
    p->pages = pages;
    transferred = ((uint64_t) pages->used) * TARGET_PAGE_SIZE + p->packet_len;
    ram_counters.multifd_bytes += transferred;
    ram_counters.transferred += transferred;;
    qemu_mutex_unlock(&p->mutex);
    qemu_sem_post(&p->sem);
}

void multifd_queue_page(RAMBlock *block, ram_addr_t offset)
{
    MultiFDPages_t *pages = multifd_send_state->pages;

    if (!pages->block) {
        pages->block = block;
    }

    if (pages->block == block) {
        pages->offset[pages->used] = offset;
        pages->iov[pages->used].iov_base = block->host + offset;
        pages->iov[pages->used].iov_len = TARGET_PAGE_SIZE;
        pages->used++;

        if (pages->used < pages->allocated) {
            return;
        }
    }

    multifd_send_pages();

    if (pages->block != block) {
        multifd_queue_page(block, offset);
    }
}

static void multifd_send_terminate_threads(Error *err)
{
    int i;

    if (err) {
        MigrationState *s = migrate_get_current();
        migrate_set_error(s, err);
        if (s->state == MIGRATION_STATUS_SETUP ||
            s->state == MIGRATION_STATUS_PRE_SWITCHOVER ||
            s->state == MIGRATION_STATUS_DEVICE ||
            s->state == MIGRATION_STATUS_ACTIVE) {
            migrate_set_state(&s->state, s->state,
                              MIGRATION_STATUS_FAILED);
        }
    }

    for (i = 0; i < migrate_multifd_channels(); i++) {
        MultiFDSendParams *p = &multifd_send_state->params[i];

        qemu_mutex_lock(&p->mutex);
        p->quit = true;
        qemu_sem_post(&p->sem);
        qemu_mutex_unlock(&p->mutex);
    }
}

void multifd_save_cleanup(void)
{
    int i;

    if (!migrate_use_multifd()) {
        return;
    }
    multifd_send_terminate_threads(NULL);
    for (i = 0; i < migrate_multifd_channels(); i++) {
        MultiFDSendParams *p = &multifd_send_state->params[i];

        if (p->running) {
            qemu_thread_join(&p->thread);
        }
        socket_send_channel_destroy(p->c);
        p->c = NULL;
        qemu_mutex_destroy(&p->mutex);
        qemu_sem_destroy(&p->sem);
        qemu_sem_destroy(&p->sem_sync);
        g_free(p->name);
        p->name = NULL;
        multifd_pages_clear(p->pages);
        p->pages = NULL;
        p->packet_len = 0;
        g_free(p->packet);
        p->packet = NULL;
    }
    qemu_sem_destroy(&multifd_send_state->channels_ready);
    qemu_sem_destroy(&multifd_send_state->sem_sync);
    g_free(multifd_send_state->params);
    multifd_send_state->params = NULL;
    multifd_pages_clear(multifd_send_state->pages);
    multifd_send_state->pages = NULL;
    g_free(multifd_send_state);
    multifd_send_state = NULL;
}

void multifd_send_sync_main(void)
{
    int i;

    if (!migrate_use_multifd()) {
        return;
    }
    if (multifd_send_state->pages->used) {
        multifd_send_pages();
    }
    for (i = 0; i < migrate_multifd_channels(); i++) {
        MultiFDSendParams *p = &multifd_send_state->params[i];

        trace_multifd_send_sync_main_signal(p->id);

        qemu_mutex_lock(&p->mutex);

        p->packet_num = multifd_send_state->packet_num++;
        p->flags |= MULTIFD_FLAG_SYNC;
        p->pending_job++;
        qemu_mutex_unlock(&p->mutex);
        qemu_sem_post(&p->sem);
    }
    for (i = 0; i < migrate_multifd_channels(); i++) {
        MultiFDSendParams *p = &multifd_send_state->params[i];

        trace_multifd_send_sync_main_wait(p->id);
        qemu_sem_wait(&multifd_send_state->sem_sync);
    }
    trace_multifd_send_sync_main(multifd_send_state->packet_num);
}

static void *multifd_send_thread(void *opaque)
{
    MultiFDSendParams *p = opaque;
    Error *local_err = NULL;
    int ret;

    trace_multifd_send_thread_start(p->id);
    rcu_register_thread();

    if (multifd_send_initial_packet(p, &local_err) < 0) {
        goto out;
    }
    /* initial packet */
    p->num_packets = 1;

    while (true) {
        qemu_sem_wait(&p->sem);
        qemu_mutex_lock(&p->mutex);

        if (p->pending_job) {
            uint32_t used = p->pages->used;
            uint64_t packet_num = p->packet_num;
            uint32_t flags = p->flags;

            p->next_packet_size = used * qemu_target_page_size();
            multifd_send_fill_packet(p);
            p->flags = 0;
            p->num_packets++;
            p->num_pages += used;
            p->pages->used = 0;
            qemu_mutex_unlock(&p->mutex);

            trace_multifd_send(p->id, packet_num, used, flags,
                               p->next_packet_size);

            ret = qio_channel_write_all(p->c, (void *)p->packet,
                                        p->packet_len, &local_err);
            if (ret != 0) {
                break;
            }

            if (used) {
                ret = qio_channel_writev_all(p->c, p->pages->iov,
                                             used, &local_err);
                if (ret != 0) {
                    break;
                }
            }

            qemu_mutex_lock(&p->mutex);
            p->pending_job--;
            qemu_mutex_unlock(&p->mutex);

            if (flags & MULTIFD_FLAG_SYNC) {
                qemu_sem_post(&multifd_send_state->sem_sync);
            }
            qemu_sem_post(&multifd_send_state->channels_ready);
        } else if (p->quit) {
            qemu_mutex_unlock(&p->mutex);
            break;
        } else {
            qemu_mutex_unlock(&p->mutex);
            /* sometimes there are spurious wakeups */
        }
    }

out:
    if (local_err) {
        multifd_send_terminate_threads(local_err);
    }

    qemu_mutex_lock(&p->mutex);
    p->running = false;
    qemu_mutex_unlock(&p->mutex);

    rcu_unregister_thread();
    trace_multifd_send_thread_end(p->id, p->num_packets, p->num_pages);

    return NULL;
}

static void multifd_new_send_channel_async(QIOTask *task, gpointer opaque)
{
    MultiFDSendParams *p = opaque;
    QIOChannel *sioc = QIO_CHANNEL(qio_task_get_source(task));
    Error *local_err = NULL;

    if (qio_task_propagate_error(task, &local_err)) {
        migrate_set_error(migrate_get_current(), local_err);
        multifd_save_cleanup();
    } else {
        p->c = QIO_CHANNEL(sioc);
        qio_channel_set_delay(p->c, false);
        p->running = true;
        qemu_thread_create(&p->thread, p->name, multifd_send_thread, p,
                           QEMU_THREAD_JOINABLE);

        atomic_inc(&multifd_send_state->count);
    }
}

int multifd_save_setup(void)
{
    int thread_count;
    uint32_t page_count = MULTIFD_PACKET_SIZE / qemu_target_page_size();
    uint8_t i;

    if (!migrate_use_multifd()) {
        return 0;
    }
    thread_count = migrate_multifd_channels();
    multifd_send_state = g_malloc0(sizeof(*multifd_send_state));
    multifd_send_state->params = g_new0(MultiFDSendParams, thread_count);
    atomic_set(&multifd_send_state->count, 0);
    multifd_send_state->pages = multifd_pages_init(page_count);
    qemu_sem_init(&multifd_send_state->sem_sync, 0);
    qemu_sem_init(&multifd_send_state->channels_ready, 0);

    for (i = 0; i < thread_count; i++) {
        MultiFDSendParams *p = &multifd_send_state->params[i];

        qemu_mutex_init(&p->mutex);
        qemu_sem_init(&p->sem, 0);
        qemu_sem_init(&p->sem_sync, 0);
        p->quit = false;
        p->pending_job = 0;
        p->id = i;
        p->pages = multifd_pages_init(page_count);
        p->packet_len = sizeof(MultiFDPacket_t)
                      + sizeof(ram_addr_t) * page_count;
        p->packet = g_malloc0(p->packet_len);
        p->name = g_strdup_printf("multifdsend_%d", i);
        socket_send_channel_create(multifd_new_send_channel_async, p);
    }
    return 0;
}

struct {
    MultiFDRecvParams *params;
    /* number of created threads */
    int count;
    /* syncs main thread and channels */
    QemuSemaphore sem_sync;
    /* global number of generated multifd packets */
    uint64_t packet_num;
} *multifd_recv_state;

static void multifd_recv_terminate_threads(Error *err)
{
    int i;

    if (err) {
        MigrationState *s = migrate_get_current();
        migrate_set_error(s, err);
        if (s->state == MIGRATION_STATUS_SETUP ||
            s->state == MIGRATION_STATUS_ACTIVE) {
            migrate_set_state(&s->state, s->state,
                              MIGRATION_STATUS_FAILED);
        }
    }

    for (i = 0; i < migrate_multifd_channels(); i++) {
        MultiFDRecvParams *p = &multifd_recv_state->params[i];

        qemu_mutex_lock(&p->mutex);
        /* We could arrive here for two reasons:
           - normal quit, i.e. everything went fine, just finished
           - error quit: We close the channels so the channel threads
             finish the qio_channel_read_all_eof() */
        qio_channel_shutdown(p->c, QIO_CHANNEL_SHUTDOWN_BOTH, NULL);
        qemu_mutex_unlock(&p->mutex);
    }
}

int multifd_load_cleanup(Error **errp)
{
    int i;
    int ret = 0;

    if (!migrate_use_multifd()) {
        return 0;
    }
    multifd_recv_terminate_threads(NULL);
    for (i = 0; i < migrate_multifd_channels(); i++) {
        MultiFDRecvParams *p = &multifd_recv_state->params[i];

        if (p->running) {
            qemu_thread_join(&p->thread);
        }
        object_unref(OBJECT(p->c));
        p->c = NULL;
        qemu_mutex_destroy(&p->mutex);
        qemu_sem_destroy(&p->sem_sync);
        g_free(p->name);
        p->name = NULL;
        multifd_pages_clear(p->pages);
        p->pages = NULL;
        p->packet_len = 0;
        g_free(p->packet);
        p->packet = NULL;
    }
    qemu_sem_destroy(&multifd_recv_state->sem_sync);
    g_free(multifd_recv_state->params);
    multifd_recv_state->params = NULL;
    g_free(multifd_recv_state);
    multifd_recv_state = NULL;

    return ret;
}

void multifd_recv_sync_main(void)
{
    int i;

    if (!migrate_use_multifd()) {
        return;
    }
    for (i = 0; i < migrate_multifd_channels(); i++) {
        MultiFDRecvParams *p = &multifd_recv_state->params[i];

        trace_multifd_recv_sync_main_wait(p->id);
        qemu_sem_wait(&multifd_recv_state->sem_sync);
        qemu_mutex_lock(&p->mutex);
        if (multifd_recv_state->packet_num < p->packet_num) {
            multifd_recv_state->packet_num = p->packet_num;
        }
        qemu_mutex_unlock(&p->mutex);
    }
    for (i = 0; i < migrate_multifd_channels(); i++) {
        MultiFDRecvParams *p = &multifd_recv_state->params[i];

        trace_multifd_recv_sync_main_signal(p->id);
        qemu_sem_post(&p->sem_sync);
    }
    trace_multifd_recv_sync_main(multifd_recv_state->packet_num);
}

static void *multifd_recv_thread(void *opaque)
{
    MultiFDRecvParams *p = opaque;
    Error *local_err = NULL;
    int ret;

    trace_multifd_recv_thread_start(p->id);
    rcu_register_thread();

    while (true) {
        uint32_t used;
        uint32_t flags;

        ret = qio_channel_read_all_eof(p->c, (void *)p->packet,
                                       p->packet_len, &local_err);
        if (ret == 0) {   /* EOF */
            break;
        }
        if (ret == -1) {   /* Error */
            break;
        }

        qemu_mutex_lock(&p->mutex);
        ret = multifd_recv_unfill_packet(p, &local_err);
        if (ret) {
            qemu_mutex_unlock(&p->mutex);
            break;
        }

        used = p->pages->used;
        flags = p->flags;
        trace_multifd_recv(p->id, p->packet_num, used, flags,
                           p->next_packet_size);
        p->num_packets++;
        p->num_pages += used;
        qemu_mutex_unlock(&p->mutex);

        if (used) {
            ret = qio_channel_readv_all(p->c, p->pages->iov,
                                        used, &local_err);
            if (ret != 0) {
                break;
            }
        }

        if (flags & MULTIFD_FLAG_SYNC) {
            qemu_sem_post(&multifd_recv_state->sem_sync);
            qemu_sem_wait(&p->sem_sync);
        }
    }

    if (local_err) {
        multifd_recv_terminate_threads(local_err);
    }
    qemu_mutex_lock(&p->mutex);
    p->running = false;
    qemu_mutex_unlock(&p->mutex);

    rcu_unregister_thread();
    trace_multifd_recv_thread_end(p->id, p->num_packets, p->num_pages);

    return NULL;
}

int multifd_load_setup(void)
{
    int thread_count;
    uint32_t page_count = MULTIFD_PACKET_SIZE / qemu_target_page_size();
    uint8_t i;

    if (!migrate_use_multifd()) {
        return 0;
    }
    thread_count = migrate_multifd_channels();
    multifd_recv_state = g_malloc0(sizeof(*multifd_recv_state));
    multifd_recv_state->params = g_new0(MultiFDRecvParams, thread_count);
    atomic_set(&multifd_recv_state->count, 0);
    qemu_sem_init(&multifd_recv_state->sem_sync, 0);

    for (i = 0; i < thread_count; i++) {
        MultiFDRecvParams *p = &multifd_recv_state->params[i];

        qemu_mutex_init(&p->mutex);
        qemu_sem_init(&p->sem_sync, 0);
        p->id = i;
        p->pages = multifd_pages_init(page_count);
        p->packet_len = sizeof(MultiFDPacket_t)
                      + sizeof(ram_addr_t) * page_count;
        p->packet = g_malloc0(p->packet_len);
        p->name = g_strdup_printf("multifdrecv_%d", i);
    }
    return 0;
}

bool multifd_recv_all_channels_created(void)
{
    int thread_count = migrate_multifd_channels();

    if (!migrate_use_multifd()) {
        return true;
    }

    return thread_count == atomic_read(&multifd_recv_state->count);
}

/*
 * Try to receive all multifd channels to get ready for the migration.
 * - Return true and do not set @errp when correctly receving all channels;
 * - Return false and do not set @errp when correctly receiving the current one;
 * - Return false and set @errp when failing to receive the current channel.
 */
bool multifd_recv_new_channel(QIOChannel *ioc, Error **errp)
{
    MultiFDRecvParams *p;
    Error *local_err = NULL;
    int id;

    id = multifd_recv_initial_packet(ioc, &local_err);
    if (id < 0) {
        multifd_recv_terminate_threads(local_err);
        error_propagate_prepend(errp, local_err,
                                "failed to receive packet"
                                " via multifd channel %d: ",
                                atomic_read(&multifd_recv_state->count));
        return false;
    }

    p = &multifd_recv_state->params[id];
    if (p->c != NULL) {
        error_setg(&local_err, "multifd: received id '%d' already setup'",
                   id);
        multifd_recv_terminate_threads(local_err);
        error_propagate(errp, local_err);
        return false;
    }
    p->c = ioc;
    object_ref(OBJECT(ioc));
    /* initial packet */
    p->num_packets = 1;

    p->running = true;
    qemu_thread_create(&p->thread, p->name, multifd_recv_thread, p,
                       QEMU_THREAD_JOINABLE);
    atomic_inc(&multifd_recv_state->count);
    return atomic_read(&multifd_recv_state->count) ==
           migrate_multifd_channels();
}

/**
 * ram_pagesize_summary: calculate all the pagesizes of a VM
 *
 * Returns a summary bitmap of the page sizes of all RAMBlocks
 *
 * For VMs with just normal pages this is equivalent to the host page
 * size. If it's got some huge pages then it's the OR of all the
 * different page sizes.
 */
uint64_t ram_pagesize_summary(void)
{
    RAMBlock *block;
    uint64_t summary = 0;

    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        summary |= block->page_size;
    }

    return summary;
}

uint64_t ram_get_total_transferred_pages(void)
{
    if( is_rapid_analysis_active() ) { 
        return ram_rapid_get_total_transferred_pages();
    }

    return ram_xbzrle_get_total_transferred_pages();
}

/**
 * ram_save_queue_pages: queue the page for transmission
 *
 * A request from postcopy destination for example.
 *
 * Returns zero on success or negative on error
 *
 * @rbname: Name of the RAMBLock of the request. NULL means the
 *          same that last one.
 * @start: starting address from the start of the RAMBlock
 * @len: length (in bytes) to send
 */
int ram_save_queue_pages(const char *rbname, ram_addr_t start, ram_addr_t len)
{
    if( is_rapid_analysis_active() ) { 
        return ram_rapid_save_queue_pages(rbname, start, len);
    }

    return ram_xbzrle_save_queue_pages(rbname, start, len);
}

void ram_acct_update_position(QEMUFile *f, size_t size, bool zero)
{
    uint64_t pages = size / TARGET_PAGE_SIZE;

    if (zero) {
        ram_counters.duplicate += pages;
    } else {
        ram_counters.normal += pages;
        ram_counters.transferred += size;
        qemu_update_position(f, size);
    }
}

void ram_postcopy_migrated_memory_release(MigrationState *ms)
{
    struct RAMBlock *block;

    RAMBLOCK_FOREACH_NOT_IGNORED(block) {
        unsigned long *bitmap = block->bmap;
        unsigned long range = block->used_length >> TARGET_PAGE_BITS;
        unsigned long run_start = find_next_zero_bit(bitmap, range, 0);

        while (run_start < range) {
            unsigned long run_end = find_next_bit(bitmap, range, run_start + 1);
            ram_discard_range(block->idstr, run_start << TARGET_PAGE_BITS,
                              (run_end - run_start) << TARGET_PAGE_BITS);
            run_start = find_next_zero_bit(bitmap, range, run_end + 1);
        }
    }
}

int ramblock_recv_bitmap_test(RAMBlock *rb, void *host_addr)
{
    return test_bit(ramblock_recv_bitmap_offset(host_addr, rb),
                    rb->receivedmap);
}

bool ramblock_recv_bitmap_test_byte_offset(RAMBlock *rb, uint64_t byte_offset)
{
    return test_bit(byte_offset >> TARGET_PAGE_BITS, rb->receivedmap);
}

void ramblock_recv_bitmap_set(RAMBlock *rb, void *host_addr)
{
    set_bit_atomic(ramblock_recv_bitmap_offset(host_addr, rb), rb->receivedmap);
}

void ramblock_recv_bitmap_set_range(RAMBlock *rb, void *host_addr,
                                    size_t nr)
{
    bitmap_set_atomic(rb->receivedmap,
                      ramblock_recv_bitmap_offset(host_addr, rb),
                      nr);
}

#define  RAMBLOCK_RECV_BITMAP_ENDING  (0x0123456789abcdefULL)

/*
 * Format: bitmap_size (8 bytes) + whole_bitmap (N bytes).
 *
 * Returns >0 if success with sent bytes, or <0 if error.
 */
int64_t ramblock_recv_bitmap_send(QEMUFile *file, const char *block_name)
{
    RAMBlock *block = qemu_ram_block_by_name(block_name);
    unsigned long *le_bitmap, nbits;
    uint64_t size;

    if (!block) {
        error_report("%s: invalid block name: %s", __func__, block_name);
        return -1;
    }

    nbits = block->used_length >> TARGET_PAGE_BITS;

    /*
     * Make sure the tmp bitmap buffer is big enough, e.g., on 32bit
     * machines we may need 4 more bytes for padding (see below
     * comment). So extend it a bit before hand.
     */
    le_bitmap = bitmap_new(nbits + BITS_PER_LONG);

    /*
     * Always use little endian when sending the bitmap. This is
     * required that when source and destination VMs are not using the
     * same endianess. (Note: big endian won't work.)
     */
    bitmap_to_le(le_bitmap, block->receivedmap, nbits);

    /* Size of the bitmap, in bytes */
    size = DIV_ROUND_UP(nbits, 8);

    /*
     * size is always aligned to 8 bytes for 64bit machines, but it
     * may not be true for 32bit machines. We need this padding to
     * make sure the migration can survive even between 32bit and
     * 64bit machines.
     */
    size = ROUND_UP(size, 8);

    qemu_put_be64(file, size);
    qemu_put_buffer(file, (const uint8_t *)le_bitmap, size);
    /*
     * Mark as an end, in case the middle part is screwed up due to
     * some "misterious" reason.
     */
    qemu_put_be64(file, RAMBLOCK_RECV_BITMAP_ENDING);
    qemu_fflush(file);

    g_free(le_bitmap);

    if (qemu_file_get_error(file)) {
        return qemu_file_get_error(file);
    }

    return size + sizeof(size);
}

/**
 * postcopy_chuck_hostpages: discrad any partially sent host page
 *
 * Utility for the outgoing postcopy code.
 *
 * Discard any partially sent host-page size chunks, mark any partially
 * dirty host-page size chunks as all dirty.  In this case the host-page
 * is the host-page for the particular RAMBlock, i.e. it might be a huge page
 *
 * Returns zero on success
 *
 * @ms: current migration state
 * @block: block we want to work with
 */
int postcopy_chunk_hostpages(MigrationState *ms, RAMBlock *block)
{
    PostcopyDiscardState *pds =
        postcopy_discard_send_init(ms, block->idstr);

    if( is_rapid_analysis_active() ) { 
        /* First pass: Discard all partially sent host pages */
        ram_rapid_postcopy_chunk_hostpages_pass(ms, true, block, pds);
        /*
        * Second pass: Ensure that all partially dirty host pages are made
        * fully dirty.
        */
        ram_rapid_postcopy_chunk_hostpages_pass(ms, false, block, pds);
    }else{
        /* First pass: Discard all partially sent host pages */
        ram_xbzrle_postcopy_chunk_hostpages_pass(ms, true, block, pds);
        /*
        * Second pass: Ensure that all partially dirty host pages are made
        * fully dirty.
        */
        ram_xbzrle_postcopy_chunk_hostpages_pass(ms, false, block, pds);
    }

    postcopy_discard_send_finish(ms, pds);
    return 0;
}

/**
 * ram_postcopy_send_discard_bitmap: transmit the discard bitmap
 *
 * Returns zero on success
 *
 * Transmit the set of pages to be discarded after precopy to the target
 * these are pages that:
 *     a) Have been previously transmitted but are now dirty again
 *     b) Pages that have never been transmitted, this ensures that
 *        any pages on the destination that have been mapped by background
 *        tasks get discarded (transparent huge pages is the specific concern)
 * Hopefully this is pretty sparse
 *
 * @ms: current migration state
 */
int ram_postcopy_send_discard_bitmap(MigrationState *ms)
{
    if( is_rapid_analysis_active() ) { 
        return ram_rapid_postcopy_send_discard_bitmap(ms);
    }

    return ram_xbzrle_postcopy_send_discard_bitmap(ms);
}

/**
 * ram_discard_range: discard dirtied pages at the beginning of postcopy
 *
 * Returns zero on success
 *
 * @rbname: name of the RAMBlock of the request. NULL means the
 *          same that last one.
 * @start: RAMBlock starting page
 * @length: RAMBlock size
 */
int ram_discard_range(const char *rbname, uint64_t start, size_t length)
{
    int ret = -1;

    trace_ram_discard_range(rbname, start, length);

    rcu_read_lock();
    RAMBlock *rb = qemu_ram_block_by_name(rbname);

    if (!rb) {
        error_report("ram_discard_range: Failed to find block '%s'", rbname);
        goto err;
    }

    /*
     * On source VM, we don't need to update the received bitmap since
     * we don't even have one.
     */
    if (rb->receivedmap) {
        bitmap_clear(rb->receivedmap, start >> qemu_target_page_bits(),
                     length >> qemu_target_page_bits());
    }

    ret = ram_block_discard_range(rb, start, length);

err:
    rcu_read_unlock();

    return ret;
}

static void ram_dirty_bitmap_reload_notify(MigrationState *s)
{
    qemu_sem_post(&s->rp_state.rp_sem);
}

/*
 * Read the received bitmap, revert it as the initial dirty bitmap.
 * This is only used when the postcopy migration is paused but wants
 * to resume from a middle point.
 */
int ram_dirty_bitmap_reload(MigrationState *s, RAMBlock *block)
{
    int ret = -EINVAL;
    QEMUFile *file = s->rp_state.from_dst_file;
    unsigned long *le_bitmap, nbits = block->used_length >> TARGET_PAGE_BITS;
    uint64_t local_size = DIV_ROUND_UP(nbits, 8);
    uint64_t size, end_mark;

    trace_ram_dirty_bitmap_reload_begin(block->idstr);

    if (s->state != MIGRATION_STATUS_POSTCOPY_RECOVER) {
        error_report("%s: incorrect state %s", __func__,
                     MigrationStatus_str(s->state));
        return -EINVAL;
    }

    /*
     * Note: see comments in ramblock_recv_bitmap_send() on why we
     * need the endianess convertion, and the paddings.
     */
    local_size = ROUND_UP(local_size, 8);

    /* Add paddings */
    le_bitmap = bitmap_new(nbits + BITS_PER_LONG);

    size = qemu_get_be64(file);

    /* The size of the bitmap should match with our ramblock */
    if (size != local_size) {
        error_report("%s: ramblock '%s' bitmap size mismatch "
                     "(0x%"PRIx64" != 0x%"PRIx64")", __func__,
                     block->idstr, size, local_size);
        ret = -EINVAL;
        goto out;
    }

    size = qemu_get_buffer(file, (uint8_t *)le_bitmap, local_size);
    end_mark = qemu_get_be64(file);

    ret = qemu_file_get_error(file);
    if (ret || size != local_size) {
        error_report("%s: read bitmap failed for ramblock '%s': %d"
                     " (size 0x%"PRIx64", got: 0x%"PRIx64")",
                     __func__, block->idstr, ret, local_size, size);
        ret = -EIO;
        goto out;
    }

    if (end_mark != RAMBLOCK_RECV_BITMAP_ENDING) {
        error_report("%s: ramblock '%s' end mark incorrect: 0x%"PRIu64,
                     __func__, block->idstr, end_mark);
        ret = -EINVAL;
        goto out;
    }

    /*
     * Endianess convertion. We are during postcopy (though paused).
     * The dirty bitmap won't change. We can directly modify it.
     */
    bitmap_from_le(block->bmap, le_bitmap, nbits);

    /*
     * What we received is "received bitmap". Revert it as the initial
     * dirty bitmap for this ramblock.
     */
    bitmap_complement(block->bmap, block->bmap, nbits);

    trace_ram_dirty_bitmap_reload_complete(block->idstr);

    /*
     * We succeeded to sync bitmap for current ramblock. If this is
     * the last one to sync, we need to notify the main send thread.
     */
    ram_dirty_bitmap_reload_notify(s);

    ret = 0;
out:
    g_free(le_bitmap);
    return ret;
}

/**
 * ram_postcopy_incoming_init: allocate postcopy data structures
 *
 * Returns 0 for success and negative if there was one error
 *
 * @mis: current migration incoming state
 *
 * Allocate data structures etc needed by incoming migration with
 * postcopy-ram. postcopy-ram's similarly names
 * postcopy_ram_incoming_init does the work.
 */
int ram_postcopy_incoming_init(MigrationIncomingState *mis)
{
    return postcopy_ram_incoming_init(mis);
}

/**
 * ram_handle_zero_page: handle the zero page case
 *
 * If a page (or a whole RDMA chunk) has been
 * determined to be zero, then zap it.
 *
 * @host: host address for the zero page
 * @ch: what the page is filled from.  We only support zero
 * @size: size of the zero page
 */
void ram_handle_zero_page(void *host, uint8_t ch, uint64_t size)
{
    if (ch != 0 || !buffer_is_zero(host, size)) {
        memset(host, ch, size);
    }
}

/*
 * 'expected' is the value you expect the bitmap mostly to be full
 * of; it won't bother printing lines that are all this value.
 * If 'todump' is null the migration bitmap is dumped.
 */
void ram_debug_dump_bitmap(unsigned long *todump, bool expected,
                           unsigned long pages)
{
    int64_t cur;
    int64_t linelen = 128;
    char linebuf[129];

    for (cur = 0; cur < pages; cur += linelen) {
        int64_t curb;
        bool found = false;
        /*
         * Last line; catch the case where the line length
         * is longer than remaining ram
         */
        if (cur + linelen > pages) {
            linelen = pages - cur;
        }
        for (curb = 0; curb < linelen; curb++) {
            bool thisbit = test_bit(cur + curb, todump);
            linebuf[curb] = thisbit ? '1' : '.';
            found = found || (thisbit != expected);
        }
        if (found) {
            linebuf[curb] = '\0';
            fprintf(stderr,  "0x%08" PRIx64 " : %s\n", cur, linebuf);
        }
    }
}

/*
 * This function clears bits of the free pages reported by the caller from the
 * migration dirty bitmap. @addr is the host address corresponding to the
 * start of the continuous guest free pages, and @len is the total bytes of
 * those pages.
 */
void qemu_guest_free_page_hint(void *addr, size_t len)
{
    RAMBlock *block;
    ram_addr_t offset;
    size_t used_len, start, npages;
    MigrationState *s = migrate_get_current();

    /* This function is currently expected to be used during live migration */
    if (!migration_is_setup_or_active(s->state)) {
        return;
    }

    for (; len > 0; len -= used_len, addr += used_len) {
        block = qemu_ram_block_from_host(addr, false, &offset);
        if (unlikely(!block || offset >= block->used_length)) {
            /*
             * The implementation might not support RAMBlock resize during
             * live migration, but it could happen in theory with future
             * updates. So we add a check here to capture that case.
             */
            error_report_once("%s unexpected error", __func__);
            return;
        }

        if (len <= block->used_length - offset) {
            used_len = len;
        } else {
            used_len = block->used_length - offset;
        }

        start = offset >> TARGET_PAGE_BITS;
        npages = used_len >> TARGET_PAGE_BITS;

        if( is_rapid_analysis_active() ) { 
            return ram_rapid_update_dirty_pages(block, start, npages);
        }

        return ram_xbzrle_update_dirty_pages(block, start, npages);
    }
}
