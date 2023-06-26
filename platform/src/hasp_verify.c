#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "hasp_api.h"
#include "hasp_vcode.h"
#include "hasp_log.h"

#define DEFAULT_INTERVAL_S (30 * 60)
#define MAX_INTERVAL_S (24 * 60 * 60)

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define ATOMIC_READ(x) __atomic_fetch_add(x, 0, __ATOMIC_RELAXED)
#define ATOMIC_SET(x, y) __atomic_store_n(x, y, __ATOMIC_RELAXED)

static char *shm_key = "hasp_verify";

static uint64_t hasp_monitor_feature_id = 0;
static uint64_t hasp_monitor_interval = 0;

struct shm_data
{
    uint64_t feature_id;
    uint64_t status;
    uint64_t timestamp;
    uint64_t interval;
};

/******************************************************************************
 * Utils
 ******************************************************************************/

static uint64_t current_timestamp()
{
    struct timespec temp;
    clock_gettime(CLOCK_MONOTONIC, &temp);
    return temp.tv_sec;
}

/******************************************************************************
 * For Hasp Verify Master Process
 ******************************************************************************/

// return 0: error
// reutrn 1: succes
static int verify(uint64_t feature_id)
{
    int ret = 0;
    hasp_handle_t handle;
    hasp_status_t status = hasp_login(feature_id, (hasp_vendor_code_t)vendor_code, &handle);
    if (status == HASP_STATUS_OK)
    {
        ret = 1;
    }
    else
    {
        switch (status)
        {
        case HASP_STATUS_OK:
            LOG_INFO("hasp_monitor: Request was successfully completed");
            break;
        case HASP_HASP_NOT_FOUND:
            LOG_INFO("hasp_monitor: Required Sentinel protection key not found");
            break;
        case HASP_FEATURE_NOT_FOUND:
            LOG_INFO("hasp_monitor: Cannot find requested Feature");
            break;
        case HASP_FEATURE_TYPE_NOT_IMPL:
            LOG_INFO("hasp_monitor: Requested Feature type not available");
            break;
        case HASP_TMOF:
            LOG_INFO("hasp_monitor: Too many open login sessions");
            break;
        case HASP_INSUF_MEM:
            LOG_INFO("hasp_monitor: Out of memory");
            break;
        case HASP_INV_VCODE:
            LOG_INFO("hasp_monitor: Invalid Vendor Code");
            break;
        case HASP_NO_DRIVER:
            LOG_INFO("hasp_monitor: Driver not installed");
            break;
        case HASP_NO_VLIB:
            LOG_INFO("hasp_monitor: Vendor library cannot be found");
            break;
        case HASP_INV_VLIB:
            LOG_INFO("hasp_monitor: Vendor library cannot be loaded");
            break;
        case HASP_OLD_DRIVER:
            LOG_INFO("hasp_monitor: Driver too old");
            break;
        case HASP_UNKNOWN_VCODE:
            LOG_INFO("hasp_monitor: Vendor Code not recognized");
            break;
        case HASP_FEATURE_EXPIRED:
            LOG_INFO("hasp_monitor: Feature has expired");
            break;
        case HASP_TOO_MANY_USERS:
            LOG_INFO("hasp_monitor: Too many users currently connected");
            break;
        case HASP_OLD_LM:
            LOG_INFO("hasp_monitor: Sentinel License Manager version too old");
            break;
        case HASP_DEVICE_ERR:
            LOG_INFO("hasp_monitor: Input/Output error in Sentinel SL/SL-AdminMode/SL-UserMode secure storage, OR in case of a Sentinel HL key, USB communication error");
            break;
        case HASP_TIME_ERR:
            LOG_INFO("hasp_monitor: System time has been tampered with");
            break;
        case HASP_HARDWARE_MODIFIED:
            LOG_INFO("hasp_monitor: Sentinel SL key incompatible with machine hardware; Sentinel SL key is locked to different hardware");
            break;
        case HASP_TS_DETECTED:
            LOG_INFO("hasp_monitor: Program is running on a Terminal Server");
            break;
        case HASP_LOCAL_COMM_ERR:
            LOG_INFO("hasp_monitor: Communication error between API and local Sentinel License Manager");
            break;
        case HASP_REMOTE_COMM_ERR:
            LOG_INFO("hasp_monitor: Communication error between local and remote Sentinel License Manager");
            break;
        case HASP_OLD_VLIB:
            LOG_INFO("hasp_monitor: Vendor Library version too old");
            break;
        case HASP_CLONE_DETECTED:
            LOG_INFO("hasp_monitor: Cloned Sentinel SL storage detected. Feature unavailable");
            break;
        default:
            LOG_INFO("hasp_monitor: failed with status %u", status);
            break;
        }

        ret = 0;
    }

    hasp_logout(handle);

    return ret;
}

static int hasp_monitor_write(struct shm_data *data)
{
    char path[256];
    char path_old[512];
    char path_new[512];

    int size = sizeof(struct shm_data);
    int fd = shm_open(shm_key, O_RDWR, 0777);
    if (fd < 0)
    {
        LOG_INFO("hasp_monitor: Could not find shared file '%s', try create it", shm_key);

        sprintf(path, "%s.%d", shm_key, getpid());
        fd = shm_open(path, O_CREAT | O_RDWR, 0777);
        if (fd < 0)
        {
            LOG_INFO("hasp_monitor: Could not create shared file '%s', error %d: %s", shm_key, errno, strerror(errno));
            return -1;
        }

        if (ftruncate(fd, size) < 0)
        {
            LOG_INFO("hasp_monitor: Could not truncate shared file '%s', error %d: %s", path, errno, strerror(errno));
            shm_unlink(path);
            return -1;
        }

        void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
        if (addr == NULL)
        {
            LOG_INFO("hasp_monitor: Could not mmap shared file '%s', error %d: %s", path, errno, strerror(errno));
            shm_unlink(path);
            return -1;
        }

        memset(addr, 0, size);
        munmap(addr, size);

        sprintf(path_old, "/dev/shm/%s", path);
        sprintf(path_new, "/dev/shm/%s", shm_key);

        int r = link(path_old, path_new);
        if (r == -1)
        {
            LOG_INFO("hasp_monitor: Create link('%s', '%s'), error %d: %s", path_old, path_new, errno, strerror(errno));
        }
        else
        {
            LOG_INFO("hasp_monitor: Create link('%s', '%s') success", path_old, path_new);
        }
        unlink(path_old);

        fd = shm_open(shm_key, O_RDWR, 0777);
        if (fd < 0)
        {
            LOG_INFO("hasp_monitor: Could not open shared file '%s', error %d: %s", shm_key, errno, strerror(errno));
            return -1;
        }
    }
    else
    {
        LOG_INFO("hasp_monitor: Open shared file '%s' success", shm_key);
    }

    struct shm_data *shm = (struct shm_data *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
    if (shm == NULL)
    {
        LOG_INFO("hasp_monitor: Could not mmap shared file '%s', error %d: %s", shm_key, errno, strerror(errno));
        shm_unlink(shm_key);
        return -1;
    }

    ATOMIC_SET(&shm->feature_id, data->feature_id);
    ATOMIC_SET(&shm->status, data->status);
    ATOMIC_SET(&shm->timestamp, data->timestamp);
    ATOMIC_SET(&shm->interval, data->interval);

    /*
     * MAP_SHARED
     *
     * Share this mapping.
     * Updates to the mapping are visible to other processes that map this file, and are carried through to the underlying file.
     * The file may not actually be updated until msync(2) or munmap() is called.
     */
    munmap(shm, sizeof(struct shm_data));

    /*
     * Unlink the shared memory object.
     * Even if the peer process is still using the object, this is okay.
     * The object will be removed only after all open references are closed.
     */
    // shm_unlink(shm_key);

    return 0;
}

static void *hasp_monitor_cycle(void *arg)
{
    struct shm_data data;
    if (hasp_monitor_interval >= MAX_INTERVAL_S)
    {
        hasp_monitor_interval = MAX_INTERVAL_S;
    }

    if (hasp_monitor_interval == 0)
    {
        hasp_monitor_interval = DEFAULT_INTERVAL_S;
    }

    LOG_INFO("hasp_monitor: Feature ID: %ld, Interval: %ld s", hasp_monitor_feature_id, hasp_monitor_interval);

    while (1)
    {
        if (verify(hasp_monitor_feature_id) == 1)
        {
            memset(&data, 0, sizeof(data));
            data.feature_id = hasp_monitor_feature_id;
            data.status = 1;
            data.timestamp = current_timestamp();
            data.interval = hasp_monitor_interval;
            if (hasp_monitor_write(&data) == -1)
            {
                return NULL;
            }
            LOG_INFO("hasp_monitor: Set feature_id: %ld, timestamp: %ld, interval: %ld, status: %ld", data.feature_id, data.timestamp, data.interval, data.status);
        }

        sleep(hasp_monitor_interval);
    }

    return NULL;
}

void hasp_monitor(uint64_t feature_id, uint64_t interval)
{
    pthread_t tid;
    hasp_monitor_feature_id = feature_id;
    hasp_monitor_interval = interval;

    if (pthread_create(&tid, NULL, hasp_monitor_cycle, NULL) < 0)
    {
        LOG_INFO("hasp_monitor: Could not create hasp monitor thread, error %d: %s", errno, strerror(errno));
        exit(0);
    }

    pthread_join(tid, NULL);
}

/******************************************************************************
 * For Hasp Verify Slave Process
 ******************************************************************************/

static int hasp_verify_read(struct shm_data *data)
{
    memset(data, 0, sizeof(struct shm_data));
    int fd = shm_open(shm_key, O_RDONLY, 0644);
    if (fd < 0)
    {
        LOG_INFO("hasp_verify: Could not open shared file '%s', error %d: %s", shm_key, errno, strerror(errno));
        return -1;
    }

    int size = sizeof(struct shm_data);
    struct shm_data *addr = (struct shm_data *)mmap(NULL, size, PROT_READ, MAP_SHARED, fd, SEEK_SET);
    if (addr == NULL)
    {
        LOG_INFO("hasp_verify: Could not mmap shared file '%s', error %d: %s", shm_key, errno, strerror(errno));
        shm_unlink(shm_key);
        return -1;
    }

    data->feature_id = addr->feature_id;
    data->status = addr->status;
    data->timestamp = addr->timestamp;
    data->interval = addr->interval;

    /*
     * MAP_SHARED
     *
     * Share this mapping.
     * Updates to the mapping are visible to other processes that map this file, and are carried through to the underlying file.
     * The file may not actually be updated until msync(2) or munmap() is called.
     */
    munmap(addr, size);

    /*
     * Unlink the shared memory object.
     * Even if the peer process is still using the object, this is okay.
     * The object will be removed only after all open references are closed.
     */
    // shm_unlink(shm_key);

    return 0;
}

static void *hasp_verify_cycle(void *arg)
{
    struct shm_data data;
    uint64_t expect_feature_id = *(uint64_t *)arg;

    LOG_INFO("hasp_verify: Expect Feature ID: %ld", expect_feature_id);

    while (1)
    {
        if (hasp_verify_read(&data) == -1)
        {
            LOG_INFO("hasp_verify: Could not get shared data");
            exit(0);
        }

        LOG_INFO("hasp_verify: Get feature_id: %ld, timestamp: %ld, interval: %ld, status: %ld", data.feature_id, data.timestamp, data.interval, data.status);

        if (expect_feature_id != data.feature_id)
        {
            LOG_INFO("hasp_verify: Unexpected feature id");
            exit(0);
        }

        if (current_timestamp() - data.timestamp > data.interval * 2)
        {
            LOG_INFO("hasp_verify: Timestamp not updated for a long time");
            exit(0);
        }

        if (data.status == 0)
        {
            LOG_INFO("hasp_verify: Invalid authorization information");
            exit(0);
        }

        sleep(1);
    }

    free(arg);
    arg = NULL;
    return NULL;
}

void hasp_verify(uint64_t feature_id)
{
    pthread_t tid;
    uint64_t *hasp_verify_feature_id = (uint64_t *)calloc(1, sizeof(uint64_t));
    *hasp_verify_feature_id = feature_id;
    if (pthread_create(&tid, NULL, hasp_verify_cycle, hasp_verify_feature_id) < 0)
    {
        LOG_INFO("hasp_verify: Could not create hasp verify thread, error %d: %s", errno, strerror(errno));
        exit(0);
    }
}