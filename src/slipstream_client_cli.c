#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <argp.h>
#include <picosocks.h>
#include "slipstream.h"

const char* argp_program_version = "slipstream-client 0.1";
const char* argp_program_bug_address = "github.com/EndPositive/slipstream";

/* Program documentation */
static char doc[] = "slipstream-client - A high-performance covert channel over DNS (client)\v";

/* A description of the arguments we accept. */
static char args_doc[] = "";

/* Client mode options */
static struct argp_option options[] = {
    {"tcp-listen-port", 'l', "PORT", 0, "Listen port (default: 5201)", 0},
    {"resolver",        'r', "RESOLVER", 0, "Slipstream server resolver address (e.g., 1.1.1.1 or 8.8.8.8:53). Can be specified multiple times. (Required)", 0},
    {"congestion-control", 'c', "ALGO", 0, "Congestion control algorithm (bbr, dcubic) (default: dcubic)", 0},
    {"gso",             'g', "BOOL", OPTION_ARG_OPTIONAL, "GSO enabled (true/false) (default: false). Use --gso or --gso=true to enable.", 0},
    {"domain",          'd', "DOMAIN", 0, "Domain name used for the covert channel (Required)", 0},
    {0} // End of options
};

/* Used by main to communicate with parse options. */
struct arguments {
    int listen_port;
    char* domain_name;
    struct st_address_t* resolver_addresses;
    size_t resolver_count;
    char* cc_algo_id;
    bool gso;
};

/* Client mode parser */
static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct arguments* arguments = state->input;

    switch (key) {
    case 'd':
        arguments->domain_name = arg;
        break;
    case 'l':
        arguments->listen_port = atoi(arg);
        if (arguments->listen_port <= 0 || arguments->listen_port > 65535) {
            argp_error(state, "Invalid TCP listen port number: %s", arg);
        }
        break;
    case 'r':
    {
        // Allocate or reallocate the resolver addresses array
        struct st_address_t* new_resolvers = realloc(arguments->resolver_addresses,
                                     (arguments->resolver_count + 1) * sizeof(struct st_address_t));
        if (!new_resolvers) {
            argp_error(state, "Memory allocation failed for resolver address");
            return ARGP_ERR_UNKNOWN; // Signal error
        }
        arguments->resolver_addresses = new_resolvers;

        char server_name[256]; // Increased size for FQDNs
        int server_port = 53; // Default DNS port

        // Try parsing with port first, then without
        if (sscanf(arg, "%255[^:]:%d", server_name, &server_port) < 1) {
            // If sscanf fails, maybe it's just an IP/hostname without port?
            strncpy(server_name, arg, sizeof(server_name) -1);
            server_name[sizeof(server_name)-1] = '\0'; // Ensure null termination
            // Keep default port 53
        }

        if (server_port <= 0 || server_port > 65535) {
            argp_error(state, "Invalid port number in resolver address: %s", arg);
        }

        int is_name = 0; // We don't use this flag downstream currently
        if (picoquic_get_server_address(server_name, server_port, &arguments->resolver_addresses[arguments->resolver_count].server_address, &is_name) != 0) {
            argp_error(state, "Cannot resolve resolver address '%s' port %d", server_name, server_port);
        }

        arguments->resolver_count++;
        break;
    }
    case 'c':
        // Consider adding validation for supported algorithms here
        arguments->cc_algo_id = arg;
        break;
    case 'g':
        // Handle optional argument for --gso
        if (arg == NULL || strcmp(arg, "true") == 0) {
             arguments->gso = true;
        } else if (strcmp(arg, "false") == 0) {
             arguments->gso = false;
        } else {
             argp_error(state, "Invalid boolean value for --gso: '%s'. Use 'true' or 'false'.", arg);
        }
        break;
    case ARGP_KEY_ARG:
        // No positional arguments expected
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// Define the argp structure for client
static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int main(int argc, char** argv) {
    int exit_code = 0;
    struct arguments arguments;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    /* Default values */
    memset(&arguments, 0, sizeof(arguments));
    arguments.listen_port = 5201; // Default TCP listen port
    arguments.cc_algo_id = "dcubic"; // Default CC algo
    arguments.gso = false;        // Default GSO state
    arguments.resolver_addresses = NULL;
    arguments.resolver_count = 0;

    // Ensure output buffers are flushed immediately (useful for debugging/logging)
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // Parse command line arguments
    error_t parse_err = argp_parse(&argp, argc, argv, 0, NULL, &arguments);
    if (parse_err) {
        // argp should have printed an error message already
        exit(1); // Exit if parsing failed
    }

    /* Check mandatory client arguments */
    bool client_args_ok = true;
    if (arguments.domain_name == NULL) {
        fprintf(stderr, "Client error: Missing required --domain option\n");
        client_args_ok = false;
    }
    if (arguments.resolver_count == 0) {
        fprintf(stderr, "Client error: Missing required --resolver option (at least one required)\n");
        client_args_ok = false;
    }

    if (!client_args_ok) {
        // Show specific client help message
         argp_help(&argp, stderr, ARGP_HELP_USAGE | ARGP_HELP_EXIT_ERR, "slipstream-client");
         // argp_help with ARGP_HELP_EXIT_ERR will exit, no need for exit(1) here
    }

    exit_code = picoquic_slipstream_client(
        arguments.listen_port,
        arguments.resolver_addresses,
        arguments.resolver_count,
        arguments.domain_name,
        arguments.cc_algo_id,
        arguments.gso
    );

    // Free allocated memory for resolver addresses
    free(arguments.resolver_addresses);

#ifdef _WINDOWS
    WSACleanup();
#endif

    exit(exit_code);
}
