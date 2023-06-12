#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "hasp_api.h"
#include "hasp_vcode.h"

#define LOG_STOUT(time, format, ...)                             \
    {                                                            \
        fprintf(stdout, "%s " format "\n", time, ##__VA_ARGS__); \
    }

#if ENABLD_LOG_FIEL
#define LOG_FILE(time, format, ...)                          \
    {                                                        \
        FILE *fp = fopen("licenses.log", "a+");              \
        if (fp == NULL)                                      \
        {                                                    \
            break;                                           \
        }                                                    \
        fprintf(fp, "%s " format "\n", time, ##__VA_ARGS__); \
        fflush(fp);                                          \
        fclose(fp);                                          \
    }
#else
#define LOG_FILE(time, format, ...)
#endif

#define LOG_INFO(format, ...)                      \
    do                                             \
    {                                              \
        char buffer[64] = {0};                     \
        local_time_string(buffer, sizeof(buffer)); \
        LOG_STOUT(buffer, format, ##__VA_ARGS__);  \
        LOG_FILE(buffer, format, ##__VA_ARGS__);   \
    } while (0)

#define DEFAULT_INTERVAL_S (30 * 60)

static uint64_t g_interval_s = 0;
static uint64_t g_feature_id = 0;

static void local_time_string(char *buff, int size)
{
    static unsigned char weekday_str[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static unsigned char month_str[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    time_t now;
    struct tm local_time;
    time(&now);
    if (NULL == (localtime_r(&now, &local_time)))
    {
        return;
    }
    snprintf(buff, size,
             "%s %s %d %02d:%02d:%02d %d",
             weekday_str[local_time.tm_wday],
             month_str[local_time.tm_mon],
             local_time.tm_mday,
             local_time.tm_hour,
             local_time.tm_min,
             local_time.tm_sec,
             local_time.tm_year + 1900);
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

// APP 启动时若 licenses 无效则直接退出
// APP 启动后，每隔 g_interval_s 检查一次 licenses；如 2 * g_interval_s 时间内出现两次 licenses 无效则退出
static void *thread_cycle(void *arg)
{
    uint64_t last_timestamp = 0;

    if (verify(g_feature_id) == 0)
    {
        exit(0);
    }

    while (1)
    {
        sleep(g_interval_s);

        if (verify(g_feature_id) == 1)
        {
            continue;
        }
        else
        {
            struct timespec current_ts;
            clock_gettime(CLOCK_MONOTONIC, &current_ts);

            if (last_timestamp == 0)
            {
                last_timestamp = current_ts.tv_sec;
                continue;
            }

            if (current_ts.tv_sec - last_timestamp < g_interval_s * 2)
            {
                exit(0);
            }
            else
            {
                last_timestamp = current_ts.tv_sec;
            }
        }
    }
}

void hasp_verify(uint64_t feature_id, uint64_t interval_s)
{
    pthread_t tid;

    g_feature_id = feature_id;
    if (interval_s == 0)
    {
        g_interval_s = DEFAULT_INTERVAL_S;
    }
    else
    {
        g_interval_s = interval_s;
    }

    LOG_INFO("hasp_verify: Feature ID: %ld, Check Interval %ld s", g_feature_id, g_interval_s);

    if (pthread_create(&tid, NULL, thread_cycle, NULL) < 0)
    {
        LOG_INFO("hasp_verify: unable to create thread, error %d: %s", errno, strerror(errno));
        exit(0);
    }
}