#ifndef _HASP_LOG_H
#define _HASP_LOG_H

#ifdef __cpluscplus
extern "C"
{
#endif

#include <time.h>
#include <stdio.h>

static inline int local_time_string(char *buff, int size)
{
    static unsigned char weekday_str[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static unsigned char month_str[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    time_t now;
    struct tm local_time;
    time(&now);
    if (NULL == (localtime_r(&now, &local_time)))
    {
        return 0;
    }
    return snprintf(buff, size,
                    "%s %s %d %02d:%02d:%02d %d",
                    weekday_str[local_time.tm_wday],
                    month_str[local_time.tm_mon],
                    local_time.tm_mday,
                    local_time.tm_hour,
                    local_time.tm_min,
                    local_time.tm_sec,
                    local_time.tm_year + 1900);
}

enum log_level
{
    LOG_LEVEL_DEBUG = 0x1,
    LOG_LEVEL_INFO = 0x2,
    LOG_LEVEL_ERROR = 0x4,
};

static int default_log_level = LOG_LEVEL_INFO;

#define LOG_LEVEL_SET_DEBUG()                \
    {                                        \
        default_log_level = LOG_LEVEL_DEBUG; \
    }

#define LOG_LEVEL_SET_INFO()                \
    {                                       \
        default_log_level = LOG_LEVEL_INFO; \
    }

#define LOG_LEVEL_SET_ERROR()                \
    {                                        \
        default_log_level = LOG_LEVEL_ERROR; \
    }

#define LOG_STDERR(level, format, ...)                                                                    \
    {                                                                                                     \
        char temp_buffer[128] = {0};                                                                      \
        local_time_string(temp_buffer, sizeof(temp_buffer));                                              \
        fprintf(stderr, "%s %s tid:%ld " format "\n", temp_buffer, level, pthread_self(), ##__VA_ARGS__); \
    }

#define LOG_DEBUG(format, ...)                            \
    do                                                    \
    {                                                     \
        if (default_log_level <= LOG_LEVEL_DEBUG)         \
        {                                                 \
            LOG_STDERR("[DEBUG]", format, ##__VA_ARGS__); \
        }                                                 \
    } while (0)

#define LOG_INFO(format, ...)                            \
    do                                                   \
    {                                                    \
        if (default_log_level <= LOG_LEVEL_INFO)         \
        {                                                \
            LOG_STDERR("[INFO]", format, ##__VA_ARGS__); \
        }                                                \
    } while (0)

#define LOG_ERROR(format, ...)                            \
    do                                                    \
    {                                                     \
        if (default_log_level <= LOG_LEVEL_ERROR)         \
        {                                                 \
            LOG_STDERR("[ERROR]", format, ##__VA_ARGS__); \
        }                                                 \
    } while (0)

#ifdef __cpluscplus
}
#endif

#endif
