#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "hasp_verify.h"

int main(int argc, char **argv)
{
    uint64_t interval_s = 0;
    uint64_t feature_id = 0;
    if (argc != 3)
    {
        fprintf(stdout, "Usage: %s [feature_id] [interval_s]\n", argv[0]);
        exit(0);
    }
    else
    {
        feature_id = atol(argv[1]);
        interval_s = atol(argv[2]);
    }

    hasp_verify(feature_id, interval_s);

    while (1)
    {
        sleep(1);
    }

    return 0;
}