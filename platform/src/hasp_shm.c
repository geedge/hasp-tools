#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "hasp_log.h"

#define MAX_SHM_BUFF_SIZE 4096

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

struct hasp_shm
{
    pthread_mutex_t lock;
    void *buff;
    int size;
};

static void hasp_shm_lock_init(struct hasp_shm *shm)
{
    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&shm->lock, &ma);
}

struct hasp_shm *hasp_shm_new(const char *name)
{
    char path[256];
    char path_old[512];
    char path_new[512];

    int size = sizeof(struct hasp_shm) + MAX_SHM_BUFF_SIZE;
    int fd = shm_open(name, O_RDWR, 0777);
    if (fd < 0)
    {
        sprintf(path, "%s.%d", name, getpid());
        fd = shm_open(path, O_CREAT | O_RDWR, 0777);
        if (fd < 0)
        {
            LOG_INFO("hasp_shm: Unable create shared memory %s: fd %d, error %d: %s", name, fd, errno, strerror(errno));
            return NULL;
        }

        if (ftruncate(fd, size) < 0)
        {
            LOG_INFO("hasp_shm: Unable truncate file %s, error %d: %s", path, errno, strerror(errno));
            return NULL;
        }

        void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
        if (addr == NULL)
        {
            LOG_INFO("hasp_shm: Unable mmap memory for file %s, error %d: %s", path, errno, strerror(errno));
            return NULL;
        }

        memset(addr, 0, size);
        hasp_shm_lock_init((struct hasp_shm *)addr);
        munmap(addr, size);

        sprintf(path_old, "/dev/shm/%s", path);
        sprintf(path_new, "/dev/shm/%s", name);

        int r = link(path_old, path_new);
        LOG_INFO("hasp_shm: Create link(%s, %s): %d", path_old, path_new, r);
        unlink(path_old);

        fd = shm_open(name, O_RDWR, 0777);
        if (fd < 0)
        {
            LOG_INFO("hasp_shm: Unable create shared memory %s: fd %d, error %d: %s", name, fd, errno, strerror(errno));
            return NULL;
        }
    }

    struct hasp_shm *shm = (struct hasp_shm *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
    if (shm == NULL)
    {
        LOG_INFO("hasp_shm: Unable mmap memory for fd %d, error %d: %s", fd, errno, strerror(errno));
        return NULL;
    }

    shm->buff = (void *)shm + sizeof(struct hasp_shm);
    shm->size = MAX_SHM_BUFF_SIZE;

    return shm;
}

void hasp_shm_lock(struct hasp_shm *shm)
{
    if (pthread_mutex_lock(&shm->lock) == EOWNERDEAD)
    {
        pthread_mutex_consistent(&shm->lock);
        LOG_INFO("hasp_shm: Mutex lock mark consistent");
    }
}

void hasp_shm_unlock(struct hasp_shm *shm)
{
    pthread_mutex_unlock(&shm->lock);
}

void hasp_shm_write(struct hasp_shm *shm, char *data, int len)
{
    int wlen = MIN(shm->size, len);
    memset(shm->buff, 0, shm->size);
    memcpy(shm->buff, data, wlen);
}

void hasp_shm_read(struct hasp_shm *shm, char *buff, int size)
{
    int rlen = MIN(shm->size, size);
    memset(buff, 0, size);
    memcpy(buff, shm->buff, rlen);
}

void hasp_shm_free(struct hasp_shm *shm)
{
    munmap(shm, sizeof(struct hasp_shm) + MAX_SHM_BUFF_SIZE);
}
