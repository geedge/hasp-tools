#include <stdio.h>
#include <stdlib.h>

#include "hasp_verify.h"

int main(int argc, char **argv)
{
    uint64_t interval_s = 0;
    uint64_t feature_id = 0;
    if (argc == 2)
    {
        feature_id = atol(argv[1]);
        interval_s = atol(argv[2]);
    }
    else
    {
        feature_id = 100;
        interval_s = 30 * 60;
    }

    hasp_monitor(feature_id, interval_s);

    return 0;
}
