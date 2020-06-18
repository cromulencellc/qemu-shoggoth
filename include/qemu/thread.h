#ifndef QEMU_THREAD_H
#define QEMU_THREAD_H

#include "qemu/processor.h"
#include "qemu/atomic.h"

typedef struct QemuCond QemuCond;
typedef struct QemuSemaphore QemuSemaphore;
typedef struct QemuEvent QemuEvent;
typedef struct QemuLockCnt QemuLockCnt;
typedef struct QemuThread QemuThread;
typedef struct QemuThreadData QemuThreadData;
typedef struct QemuThreadBase QemuThreadBase;

struct QemuThreadBase {
    QemuThreadData *thread_data;
};

extern __thread QemuThread *current_thread;

#ifdef _WIN32
#include "qemu/thread-win32.h"
#else
#include "qemu/thread-posix.h"
#endif

/* include QSP header once QemuMutex, QemuCond etc. are defined */
#include "qemu/qsp.h"

#define QEMU_THREAD_JOINABLE 0
#define QEMU_THREAD_DETACHED 1

struct QemuGlobalMutex {
    QemuMutex *transition_lock;
    QemuMutex *access_lock;
    QemuMutex *lock;
    QemuThread *owner;
    int ref;
};

void qemu_mutex_init(QemuMutex *mutex);
void qemu_mutex_destroy(QemuMutex *mutex);
int qemu_mutex_trylock_impl(QemuMutex *mutex, const char *file, const int line);
void qemu_mutex_lock_impl(QemuMutex *mutex, const char *file, const int line);
void qemu_mutex_unlock_impl(QemuMutex *mutex, const char *file, const int line);

typedef void (*QemuMutexLockFunc)(QemuMutex *m, const char *f, int l);
typedef int (*QemuMutexTrylockFunc)(QemuMutex *m, const char *f, int l);
typedef void (*QemuRecMutexLockFunc)(QemuRecMutex *m, const char *f, int l);
typedef int (*QemuRecMutexTrylockFunc)(QemuRecMutex *m, const char *f, int l);
typedef void (*QemuCondWaitFunc)(QemuCond *c, QemuMutex *m, const char *f,
                                 int l);

extern QemuMutexLockFunc qemu_bql_mutex_lock_func;
extern QemuMutexLockFunc qemu_mutex_lock_func;
extern QemuMutexTrylockFunc qemu_mutex_trylock_func;
extern QemuRecMutexLockFunc qemu_rec_mutex_lock_func;
extern QemuRecMutexTrylockFunc qemu_rec_mutex_trylock_func;
extern QemuCondWaitFunc qemu_cond_wait_func;

/* convenience macros to bypass the profiler */
#define qemu_mutex_lock__raw(m)                         \
        qemu_mutex_lock_impl(m, __FILE__, __LINE__)
#define qemu_mutex_trylock__raw(m)                      \
        qemu_mutex_trylock_impl(m, __FILE__, __LINE__)

#ifdef __COVERITY__
/*
 * Coverity is severely confused by the indirect function calls,
 * hide them.
 */
#define qemu_mutex_lock(m)                                              \
            qemu_mutex_lock_impl(m, __FILE__, __LINE__);
#define qemu_mutex_trylock(m)                                           \
            qemu_mutex_trylock_impl(m, __FILE__, __LINE__);
#define qemu_rec_mutex_lock(m)                                          \
            qemu_rec_mutex_lock_impl(m, __FILE__, __LINE__);
#define qemu_rec_mutex_trylock(m)                                       \
            qemu_rec_mutex_trylock_impl(m, __FILE__, __LINE__);
#define qemu_cond_wait(c, m)                                            \
            qemu_cond_wait_impl(c, m, __FILE__, __LINE__);
#else
#define qemu_mutex_lock(m) ({                                           \
            QemuMutexLockFunc _f = atomic_read(&qemu_mutex_lock_func);  \
            _f(m, __FILE__, __LINE__);                                  \
        })

#define qemu_mutex_trylock(m) ({                                        \
            QemuMutexTrylockFunc _f = atomic_read(&qemu_mutex_trylock_func); \
            _f(m, __FILE__, __LINE__);                                  \
        })

#define qemu_rec_mutex_lock(m) ({                                       \
            QemuRecMutexLockFunc _f = atomic_read(&qemu_rec_mutex_lock_func); \
            _f(m, __FILE__, __LINE__);                                  \
        })

#define qemu_rec_mutex_trylock(m) ({                            \
            QemuRecMutexTrylockFunc _f;                         \
            _f = atomic_read(&qemu_rec_mutex_trylock_func);     \
            _f(m, __FILE__, __LINE__);                          \
        })

#define qemu_cond_wait(c, m) ({                                         \
            QemuCondWaitFunc _f = atomic_read(&qemu_cond_wait_func);    \
            _f(c, m, __FILE__, __LINE__);                               \
        })
#endif

#define qemu_mutex_unlock(mutex) \
        qemu_mutex_unlock_impl(mutex, __FILE__, __LINE__)

static inline void (qemu_mutex_lock)(QemuMutex *mutex)
{
    qemu_mutex_lock(mutex);
}

static inline int (qemu_mutex_trylock)(QemuMutex *mutex)
{
    return qemu_mutex_trylock(mutex);
}

static inline void (qemu_mutex_unlock)(QemuMutex *mutex)
{
    qemu_mutex_unlock(mutex);
}

static inline void (qemu_rec_mutex_lock)(QemuRecMutex *mutex)
{
    qemu_rec_mutex_lock(mutex);
}

static inline int (qemu_rec_mutex_trylock)(QemuRecMutex *mutex)
{
    return qemu_rec_mutex_trylock(mutex);
}

/* Prototypes for other functions are in thread-posix.h/thread-win32.h.  */
void qemu_rec_mutex_init(QemuRecMutex *mutex);

void qemu_cond_init(QemuCond *cond);
void qemu_cond_destroy(QemuCond *cond);

/*
 * IMPORTANT: The implementation does not guarantee that pthread_cond_signal
 * and pthread_cond_broadcast can be called except while the same mutex is
 * held as in the corresponding pthread_cond_wait calls!
 */
void qemu_cond_signal(QemuCond *cond);
void qemu_cond_broadcast(QemuCond *cond);
void qemu_cond_wait_impl(QemuCond *cond, QemuMutex *mutex,
                         const char *file, const int line);

static inline void (qemu_cond_wait)(QemuCond *cond, QemuMutex *mutex)
{
    qemu_cond_wait(cond, mutex);
}

void qemu_sem_init(QemuSemaphore *sem, int init);
void qemu_sem_post(QemuSemaphore *sem);
void qemu_sem_wait(QemuSemaphore *sem);
int qemu_sem_timedwait(QemuSemaphore *sem, int ms);
void qemu_sem_destroy(QemuSemaphore *sem);

void qemu_event_init(QemuEvent *ev, bool init);
void qemu_event_set(QemuEvent *ev);
void qemu_event_reset(QemuEvent *ev);
void qemu_event_wait(QemuEvent *ev);
void qemu_event_destroy(QemuEvent *ev);

void qemu_thread_create(QemuThread *thread, const char *name,
                        void *(*start_routine)(void *),
                        void *arg, int mode);
void *qemu_thread_join(QemuThread *thread);
void qemu_thread_get_self(QemuThread *thread);
bool qemu_thread_is_self(QemuThread *thread);
void qemu_thread_exit(void *retval);
void qemu_thread_naming(bool enable);
const char *qemu_thread_name(QemuThread *thread);

void qemu_thread_register(QemuThread *thread, const char *name);

struct Notifier;
/**
 * qemu_thread_atexit_add:
 * @notifier: Notifier to add
 *
 * Add the specified notifier to a list which will be run via
 * notifier_list_notify() when this thread exits (either by calling
 * qemu_thread_exit() or by returning from its start_routine).
 * The usual usage is that the caller passes a Notifier which is
 * a per-thread variable; it can then use the callback to free
 * other per-thread data.
 *
 * If the thread exits as part of the entire process exiting,
 * it is unspecified whether notifiers are called or not.
 */
void qemu_thread_atexit_add(struct Notifier *notifier);
/**
 * qemu_thread_atexit_remove:
 * @notifier: Notifier to remove
 *
 * Remove the specified notifier from the thread-exit notification
 * list. It is not valid to try to remove a notifier which is not
 * on the list.
 */
void qemu_thread_atexit_remove(struct Notifier *notifier);

struct QemuSpin {
    int value;
};

static inline void qemu_spin_init(QemuSpin *spin)
{
    __sync_lock_release(&spin->value);
}

static inline void qemu_spin_lock(QemuSpin *spin)
{
    while (unlikely(__sync_lock_test_and_set(&spin->value, true))) {
        while (atomic_read(&spin->value)) {
            cpu_relax();
        }
    }
}

static inline bool qemu_spin_trylock(QemuSpin *spin)
{
    return __sync_lock_test_and_set(&spin->value, true);
}

static inline bool qemu_spin_locked(QemuSpin *spin)
{
    return atomic_read(&spin->value);
}

static inline void qemu_spin_unlock(QemuSpin *spin)
{
    __sync_lock_release(&spin->value);
}

struct QemuLockCnt {
#ifndef CONFIG_LINUX
    QemuMutex mutex;
#endif
    unsigned count;
};

/**
 * qemu_lockcnt_init: initialize a QemuLockcnt
 * @lockcnt: the lockcnt to initialize
 *
 * Initialize lockcnt's counter to zero and prepare its mutex
 * for usage.
 */
void qemu_lockcnt_init(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_destroy: destroy a QemuLockcnt
 * @lockcnt: the lockcnt to destruct
 *
 * Destroy lockcnt's mutex.
 */
void qemu_lockcnt_destroy(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_inc: increment a QemuLockCnt's counter
 * @lockcnt: the lockcnt to operate on
 *
 * If the lockcnt's count is zero, wait for critical sections
 * to finish and increment lockcnt's count to 1.  If the count
 * is not zero, just increment it.
 *
 * Because this function can wait on the mutex, it must not be
 * called while the lockcnt's mutex is held by the current thread.
 * For the same reason, qemu_lockcnt_inc can also contribute to
 * AB-BA deadlocks.  This is a sample deadlock scenario:
 *
 *            thread 1                      thread 2
 *            -------------------------------------------------------
 *            qemu_lockcnt_lock(&lc1);
 *                                          qemu_lockcnt_lock(&lc2);
 *            qemu_lockcnt_inc(&lc2);
 *                                          qemu_lockcnt_inc(&lc1);
 */
void qemu_lockcnt_inc(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_dec: decrement a QemuLockCnt's counter
 * @lockcnt: the lockcnt to operate on
 */
void qemu_lockcnt_dec(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_dec_and_lock: decrement a QemuLockCnt's counter and
 * possibly lock it.
 * @lockcnt: the lockcnt to operate on
 *
 * Decrement lockcnt's count.  If the new count is zero, lock
 * the mutex and return true.  Otherwise, return false.
 */
bool qemu_lockcnt_dec_and_lock(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_dec_if_lock: possibly decrement a QemuLockCnt's counter and
 * lock it.
 * @lockcnt: the lockcnt to operate on
 *
 * If the count is 1, decrement the count to zero, lock
 * the mutex and return true.  Otherwise, return false.
 */
bool qemu_lockcnt_dec_if_lock(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_lock: lock a QemuLockCnt's mutex.
 * @lockcnt: the lockcnt to operate on
 *
 * Remember that concurrent visits are not blocked unless the count is
 * also zero.  You can use qemu_lockcnt_count to check for this inside a
 * critical section.
 */
void qemu_lockcnt_lock(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_unlock: release a QemuLockCnt's mutex.
 * @lockcnt: the lockcnt to operate on.
 */
void qemu_lockcnt_unlock(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_inc_and_unlock: combined unlock/increment on a QemuLockCnt.
 * @lockcnt: the lockcnt to operate on.
 *
 * This is the same as
 *
 *     qemu_lockcnt_unlock(lockcnt);
 *     qemu_lockcnt_inc(lockcnt);
 *
 * but more efficient.
 */
void qemu_lockcnt_inc_and_unlock(QemuLockCnt *lockcnt);

/**
 * qemu_lockcnt_count: query a LockCnt's count.
 * @lockcnt: the lockcnt to query.
 *
 * Note that the count can change at any time.  Still, while the
 * lockcnt is locked, one can usefully check whether the count
 * is non-zero.
 */
unsigned qemu_lockcnt_count(QemuLockCnt *lockcnt);


#define qemu_global_mutex_lock(mutex) \
        qemu_global_mutex_lock_impl(mutex, __FILE__, __LINE__)
#define qemu_global_mutex_unlock(mutex) \
        qemu_global_mutex_unlock_impl(mutex, __FILE__, __LINE__)
#define qemu_global_mutex_force_unlock(mutex) \
        qemu_global_mutex_force_unlock_impl(mutex, __FILE__, __LINE__)

static inline void qemu_global_mutex_init(QemuGlobalMutex *mutex)
{
    mutex->ref = 0;
    mutex->owner = NULL;

    mutex->access_lock = g_new0(QemuMutex, 1);
    qemu_mutex_init(mutex->access_lock);
    mutex->transition_lock = g_new0(QemuMutex, 1);
    qemu_mutex_init(mutex->transition_lock);
    qemu_mutex_lock(mutex->transition_lock);

    mutex->lock = g_new0(QemuMutex, 1);
    qemu_mutex_init(mutex->lock);
}

static inline int qemu_global_mutex_lock_impl(QemuGlobalMutex *mutex, const char *file, const int line)
{
    int ref;

    // Serialize accesses of the owner and reference counter.
    qemu_mutex_lock(mutex->access_lock);
    if( mutex->ref != 0 ) {
        // Halt during transitions.
        qemu_mutex_lock(mutex->transition_lock);
        if( mutex->owner && qemu_thread_is_self(mutex->owner) ){
            ref = ++mutex->ref;
            qemu_mutex_unlock(mutex->transition_lock);
            qemu_mutex_unlock(mutex->access_lock);
            return ref;
        }
        qemu_mutex_unlock(mutex->transition_lock);
    }
    qemu_mutex_unlock(mutex->access_lock);
    
    // All lock requests will wait here until the reference counter is exhausted.
    qemu_mutex_lock_impl(mutex->lock, file, line);

    qemu_mutex_lock(mutex->access_lock);
    mutex->owner = current_thread;
    ref = ++mutex->ref;
    qemu_mutex_unlock(mutex->transition_lock);
    qemu_mutex_unlock(mutex->access_lock);
    // We've finished the transition so resume.

    return ref;
}

static inline void qemu_global_mutex_unlock_impl(QemuGlobalMutex *mutex, const char *file, const int line)
{
    qemu_mutex_lock(mutex->access_lock);
    qemu_mutex_lock(mutex->transition_lock);
    if( mutex->owner && qemu_thread_is_self(mutex->owner) ){
        mutex->ref--;
        if( mutex->ref == 0){
            mutex->owner = NULL;
            qemu_mutex_unlock_impl(mutex->lock, file, line);
        }else{
            qemu_mutex_unlock(mutex->transition_lock);
        }
    }else{
#ifdef DEBUG_GLOBAL_LOCK
        // We have an unmatched unlock...
        error_printf("Unmatched unlock of global mutex at %s (%d): ", file, line);
        if( mutex->owner ) error_printf("owner %s, ", qemu_thread_name(mutex->owner));
        error_printf("ref %d\n", mutex->ref);
#endif
        qemu_mutex_unlock(mutex->transition_lock);
    }
    qemu_mutex_unlock(mutex->access_lock);
}

static inline void qemu_global_mutex_force_unlock_impl(QemuGlobalMutex *mutex, const char *file, const int line)
{
    qemu_mutex_lock(mutex->access_lock);
    if( mutex->ref != 0 ) {
        // Halt during transitions.
        qemu_mutex_lock(mutex->transition_lock);
        if( mutex->owner && qemu_thread_is_self(mutex->owner) ){
            mutex->ref = 0;
            mutex->owner = NULL;
            qemu_mutex_unlock_impl(mutex->lock, file, line);
        }else{
#ifdef DEBUG_GLOBAL_LOCK
            // Trying to force unlock a mutex we do not own...
            error_printf("Attempted to force unlock unowned global mutex at %s (%d): ", file, line);
            if( mutex->owner ) error_printf("owner %s, ", qemu_thread_name(mutex->owner));
            error_printf("ref %d\n", mutex->ref);
#endif
            qemu_mutex_unlock(mutex->transition_lock);
        }
    }
    qemu_mutex_unlock(mutex->access_lock);
}

static inline void qemu_global_mutex_destroy(QemuGlobalMutex *mutex)
{
    qemu_mutex_destroy(mutex->access_lock);
    qemu_mutex_destroy(mutex->transition_lock);
    qemu_mutex_destroy(mutex->lock);
}

#define qemu_global_cond_wait(cond, mutex) \
        qemu_global_cond_wait_impl(cond, mutex, __FILE__, __LINE__)

static inline void qemu_global_cond_wait_impl(QemuCond *cond, QemuGlobalMutex *mutex, const char *file, const int line)
{
    int old_ref;
    QemuThread *old_owner;

    // Save off the lock owner and ref since and relinquish ownership of mutex.
    qemu_mutex_lock(mutex->access_lock);
    qemu_mutex_lock(mutex->transition_lock);
    old_ref = mutex->ref;
    old_owner = mutex->owner;
    mutex->ref = 0;
    mutex->owner = NULL;
    qemu_mutex_unlock(mutex->access_lock);

    // The wait will release the lock for us.
    qemu_cond_wait_impl(cond, mutex->lock, file, line);
    // Now we have it again.

    // The transition lock should already be locked.
    qemu_mutex_lock(mutex->access_lock);
    mutex->ref = old_ref;
    mutex->owner = old_owner;
    qemu_mutex_unlock(mutex->transition_lock);
    qemu_mutex_unlock(mutex->access_lock);
}

#endif
