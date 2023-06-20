#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "hasp_verify.h"

static void usage(char *cmd)
{
    fprintf(stderr, "USAGE: %s [OPTIONS]\n", cmd);
    fprintf(stderr, "    -f     -- set feature id\n");
    fprintf(stderr, "    -h     -- show help\n");
}

int main(int argc, char **argv)
{
    int opt;
    uint64_t feature_id = 0;

    while ((opt = getopt(argc, argv, "f:h")) != -1)
    {
        switch (opt)
        {
        case 'f':
            feature_id = atoi(optarg);
            break;
        case 'h': /* fall through */
        default:
            usage(argv[0]);
            return 0;
        }
    }

    hasp_verify(feature_id);

    while (1)
    {
        sleep(1);
    }

    return 0;
}