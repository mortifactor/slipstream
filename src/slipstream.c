#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "slipstream.h"

static void usage(char const * sample_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s client listen_port slipstream_server_name slipstream_server_port domain_name\n", sample_name);
    fprintf(stderr, "    %s server listen_port cert key target_server_name target_server_port domain_name\n", sample_name);
    exit(1);
}

int get_port(char const* sample_name, char const* port_arg)
{
    int server_port = atoi(port_arg);
    if (server_port <= 0) {
        fprintf(stderr, "Invalid port: %s\n", port_arg);
        usage(sample_name);
    }

    return server_port;
}

int main(int argc, char** argv)
{
    int exit_code = 0;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    if (argc < 2) {
        usage(argv[0]);
    }
    else if (strcmp(argv[1], "client") == 0) {
        if (argc != 6) {
            usage(argv[0]);
        }
        else {
            int local_port = atoi(argv[2]);
            char const* resolver_addresses_filename = argv[3];
            const char* domain_name = argv[4];
            const char* cc_algo_id = argv[5];
            exit_code = picoquic_slipstream_client(local_port, resolver_addresses_filename, domain_name, cc_algo_id);
        }
    }
    else if (strcmp(argv[1], "server") == 0) {
        if (argc != 9) {
            usage(argv[0]);
        }
        else {
            int server_port = get_port(argv[0], argv[2]);
            int remote_port = get_port(argv[0], argv[6]);
            const char* domain_name = argv[7];
            const char* cc_algo_id = argv[8];
            exit_code = picoquic_slipstream_server(server_port, argv[3], argv[4], argv[5], remote_port, domain_name, cc_algo_id);
        }
    }
    else
    {
        usage(argv[0]);
    }

    exit(exit_code);
}