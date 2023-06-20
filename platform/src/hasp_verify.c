#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "hasp_api.h"
#include "hasp_vcode.h"
#include "hasp_log.h"
#include "hasp_shm.h"

#define DEFAULT_INTERVAL_S (30 * 60)
#define MAX_INTERVAL_S (24 * 60 * 60)

static char *shm_key = "hasp_verify";

static uint64_t app_expect_feature_id = 0;

/******************************************************************************
 * Utils
 ******************************************************************************/

static uint64_t current_timestamp()
{
    struct timespec temp;
    clock_gettime(CLOCK_MONOTONIC, &temp);
    return temp.tv_sec;
}

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
            LOG_INFO("hasp_verify: Request was successfully completed");
            break;
        case HASP_HASP_NOT_FOUND:
            LOG_INFO("hasp_verify: Required Sentinel protection key not found");
            break;
        case HASP_FEATURE_NOT_FOUND:
            LOG_INFO("hasp_verify: Cannot find requested Feature");
            break;
        case HASP_FEATURE_TYPE_NOT_IMPL:
            LOG_INFO("hasp_verify: Requested Feature type not available");
            break;
        case HASP_TMOF:
            LOG_INFO("hasp_verify: Too many open login sessions");
            break;
        case HASP_INSUF_MEM:
            LOG_INFO("hasp_verify: Out of memory");
            break;
        case HASP_INV_VCODE:
            LOG_INFO("hasp_verify: Invalid Vendor Code");
            break;
        case HASP_NO_DRIVER:
            LOG_INFO("hasp_verify: Driver not installed");
            break;
        case HASP_NO_VLIB:
            LOG_INFO("hasp_verify: Vendor library cannot be found");
            break;
        case HASP_INV_VLIB:
            LOG_INFO("hasp_verify: Vendor library cannot be loaded");
            break;
        case HASP_OLD_DRIVER:
            LOG_INFO("hasp_verify: Driver too old");
            break;
        case HASP_UNKNOWN_VCODE:
            LOG_INFO("hasp_verify: Vendor Code not recognized");
            break;
        case HASP_FEATURE_EXPIRED:
            LOG_INFO("hasp_verify: Feature has expired");
            break;
        case HASP_TOO_MANY_USERS:
            LOG_INFO("hasp_verify: Too many users currently connected");
            break;
        case HASP_OLD_LM:
            LOG_INFO("hasp_verify: Sentinel License Manager version too old");
            break;
        case HASP_DEVICE_ERR:
            LOG_INFO("hasp_verify: Input/Output error in Sentinel SL/SL-AdminMode/SL-UserMode secure storage, OR in case of a Sentinel HL key, USB communication error");
            break;
        case HASP_TIME_ERR:
            LOG_INFO("hasp_verify: System time has been tampered with");
            break;
        case HASP_HARDWARE_MODIFIED:
            LOG_INFO("hasp_verify: Sentinel SL key incompatible with machine hardware; Sentinel SL key is locked to different hardware");
            break;
        case HASP_TS_DETECTED:
            LOG_INFO("hasp_verify: Program is running on a Terminal Server");
            break;
        case HASP_LOCAL_COMM_ERR:
            LOG_INFO("hasp_verify: Communication error between API and local Sentinel License Manager");
            break;
        case HASP_REMOTE_COMM_ERR:
            LOG_INFO("hasp_verify: Communication error between local and remote Sentinel License Manager");
            break;
        case HASP_OLD_VLIB:
            LOG_INFO("hasp_verify: Vendor Library version too old");
            break;
        case HASP_CLONE_DETECTED:
            LOG_INFO("hasp_verify: Cloned Sentinel SL storage detected. Feature unavailable");
            break;
        default:
            LOG_INFO("hasp_verify: failed with status %u", status);
            break;
        }

        ret = 0;
    }

    hasp_logout(handle);

    return ret;
}

static void write_status(uint64_t feature_id, uint64_t status, uint64_t timestamp, uint64_t interva)
{
    char buff[4096] = {0};
    struct hasp_shm *shm = hasp_shm_new(shm_key);
    snprintf(buff, sizeof(buff), "%ld\t%ld\t%ld\t%ld", feature_id, status, timestamp, interva);
    hasp_shm_write(shm, buff, strlen(buff));
    hasp_shm_free(shm);
}

static void read_status(char *buff, int size)
{
    struct hasp_shm *shm = hasp_shm_new(shm_key);
    hasp_shm_read(shm, buff, size);
    hasp_shm_free(shm);
}

/******************************************************************************
 * For Hasp Verify Master Process
 ******************************************************************************/

// APP 启动时若 licenses 无效则直接退出
// APP 启动后，每隔 interval 检查一次 licenses；如 2 * interval 时间内出现两次 licenses 无效则认为出现异常
void hasp_monitor(uint64_t feature_id, uint64_t interval)
{
    if (interval >= MAX_INTERVAL_S)
    {
        interval = MAX_INTERVAL_S;
    }

    if (interval == 0)
    {
        interval = DEFAULT_INTERVAL_S;
    }

    LOG_INFO("hasp_verify: Feature ID: %ld, Interval: %ld s", feature_id, interval);

    while (1)
    {
        if (verify(feature_id) == 1)
        {
            write_status(feature_id, 1, current_timestamp(), interval);
        }

        sleep(interval);
    }
}

/******************************************************************************
 * For Hasp Verify Slave Process
 ******************************************************************************/

void *hasp_verify_cycle(void *arg)
{
    char buff[4096] = {0};
    int size = sizeof(buff);

    uint64_t feature_id = 0;
    uint64_t status = 0;
    uint64_t timestamp = 0;
    uint64_t interva = 0;

    while (1)
    {
        read_status(buff, size);

        LOG_INFO("hasp_verify: Get data: %s", buff);

        if (strlen(buff) == 0)
        {
            LOG_INFO("hasp_verify: Could not get shared data");
            exit(0);
        }

        if (sscanf(buff, "%ld\t%ld\t%ld\t%ld", &feature_id, &status, &timestamp, &interva) != 4)
        {
            LOG_INFO("hasp_verify: Invalid shared data");
            exit(0);
        }

        if (app_expect_feature_id != feature_id)
        {
            LOG_INFO("hasp_verify: Unexpected feature id");
            exit(0);
        }

        if (current_timestamp() - timestamp > interva)
        {
            LOG_INFO("hasp_verify: Timestamp not updated for a long time");
            exit(0);
        }

        if (status == 0)
        {
            LOG_INFO("hasp_verify: Invalid authorization information");
            exit(0);
        }

        sleep(interva);
    }

    return NULL;
}

void hasp_verify(uint64_t feature_id)
{
    pthread_t tid;
    app_expect_feature_id = feature_id;
    LOG_INFO("hasp_verify: Feature ID: %ld", app_expect_feature_id);
    if (pthread_create(&tid, NULL, hasp_verify_cycle, NULL) < 0)
    {
        LOG_INFO("hasp_verify: Unable create hasp verify thread, error %d: %s", errno, strerror(errno));
        exit(0);
    }
}