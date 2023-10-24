#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
    uint64_t interval_s = 0;
    uint64_t feature_id = 100;

    while ((opt = getopt(argc, argv, "f:i:h")) != -1)
    {
        switch (opt)
        {
        case 'i':
            interval_s = atoi(optarg);
            break;
        case 'f':
            feature_id = atoi(optarg);
            break;
        case 'h': /* fall through */
        default:
            usage(argv[0]);
            return 0;
        }
    }

    hasp_monitor(feature_id, interval_s);

    return 0;
}
