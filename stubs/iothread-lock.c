#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/main-loop.h"

void qemu_mutex_lock_iothread(void)
{
}

void qemu_mutex_unlock_iothread(void)
{
}

void qemu_mutex_unlockall_iothread(void)
{
}

void qemu_cond_wait_iothread(QemuCond *cond)
{
}
