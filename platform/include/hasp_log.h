#ifndef _HASP_LOG_H
#define _HASP_LOG_H

#ifdef __cpluscplus
extern "C"
{
#endif

#include <time.h>
#include <stdio.h>

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

#define LOG_STOUT(time, format, ...)                             \
    {                                                            \
        fprintf(stdout, "%s " format "\n", time, ##__VA_ARGS__); \
    }

#define LOG_INFO(format, ...)                      \
    do                                             \
    {                                              \
        char buffer[64] = {0};                     \
        local_time_string(buffer, sizeof(buffer)); \
        LOG_STOUT(buffer, format, ##__VA_ARGS__);  \
        LOG_FILE(buffer, format, ##__VA_ARGS__);   \
    } while (0)

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

#ifdef __cpluscplus
}
#endif

#endif
