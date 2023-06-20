#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "hasp_verify.h"

int main(int argc, char **argv)
{
    uint64_t feature_id = 0;
    if (argc != 2)
    {
        fprintf(stdout, "Usage: %s [feature_id]\n", argv[0]);
        exit(0);
    }
    else
    {
        feature_id = atol(argv[1]);
    }

    hasp_verify(feature_id);

    while (1)
    {
        sleep(1);
    }

    return 0;
}