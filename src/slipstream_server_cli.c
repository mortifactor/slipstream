#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <argp.h>
#include <picosocks.h>
#include "slipstream.h"

const char* argp_program_version = "slipstream-server 0.1";
const char* argp_program_bug_address = "github.com/EndPositive/slipstream";

/* Program documentation */
static char doc[] = "slipstream-server - A high-performance covert channel over DNS (server)\v";

/* A description of the arguments we accept. */
static char args_doc[] = "";

/* Server mode options */
static struct argp_option options[] = {
    {"dns-listen-port", 'l', "PORT", 0, "DNS listen port (default: 53)", 0},
    {"target-address",  'a', "ADDRESS", 0, "Target server address (default: 127.0.0.1:5201)", 0},
    {"cert",            'c', "CERT", 0, "Certificate file path (default: certs/cert.pem)", 0},
    {"key",             'k', "KEY", 0, "Private key file path (default: certs/key.pem)", 0},
    {"domain",          'd', "DOMAIN", 0, "Domain name this server is authoritative for (Required)", 0},
    {0} // End of options
};

/* Used by main to communicate with parse options. */
struct arguments {
    int listen_port;
    char* domain_name;
    char* cert_file;
    char* key_file;
    struct sockaddr_storage target_address;
};

/* Server mode parser */
static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct arguments* arguments = state->input;

    switch (key) {
    case 'd':
        arguments->domain_name = arg;
        break;
    case 'l':
        arguments->listen_port = atoi(arg);
        if (arguments->listen_port <= 0 || arguments->listen_port > 65535) {
            argp_error(state, "Invalid DNS listen port number: %s", arg);
        }
        break;
    case 'c':
        arguments->cert_file = arg;
        break;
    case 'k':
        arguments->key_file = arg;
        break;
    case 'a':
    {
        char server_name[256]; // Increased size for FQDNs
        int server_port = 5201; // Default upstream port

        // Try parsing with port first, then without
        if (sscanf(arg, "%255[^:]:%d", server_name, &server_port) < 1) {
            // If sscanf fails, maybe it's just an IP/hostname without port?
            strncpy(server_name, arg, sizeof(server_name) - 1);
            server_name[sizeof(server_name) - 1] = '\0'; // Ensure null termination
            // Keep default port 5201
        }

        if (server_port <= 0 || server_port > 65535) {
            argp_error(state, "Invalid port number in target address: %s", arg);
        }

        int is_name = 0;
        if (picoquic_get_server_address(server_name, server_port, &arguments->target_address, &is_name) != 0) {
            argp_error(state, "Cannot resolve target address '%s' port %d", server_name, server_port);
        }
        break;
    }
    case ARGP_KEY_ARG:
        // No positional arguments expected
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// Define the argp structure for server
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
    arguments.listen_port = 53; // Default DNS listen port
    arguments.cert_file = "certs/cert.pem"; // Default cert path
    arguments.key_file = "certs/key.pem";   // Default key path
    
    // Set default target address (127.0.0.1:5201)
    int is_name = 0;
    if (picoquic_get_server_address("127.0.0.1", 5201, &arguments.target_address, &is_name) != 0) {
        fprintf(stderr, "Failed to set default target address\n");
        exit(1);
    }

    // Ensure output buffers are flushed immediately
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // Parse command line arguments
    error_t parse_err = argp_parse(&argp, argc, argv, 0, NULL, &arguments);
    if (parse_err) {
        // argp should have printed an error message already
        exit(1); // Exit if parsing failed
    }

    /* Check mandatory server arguments */
    bool server_args_ok = true;
    if (arguments.domain_name == NULL) {
        fprintf(stderr, "Server error: Missing required --domain option\n");
        server_args_ok = false;
    }

    if (!server_args_ok) {
        argp_help(&argp, stderr, ARGP_HELP_USAGE | ARGP_HELP_EXIT_ERR, "slipstream-server");
    }

    exit_code = picoquic_slipstream_server(
        arguments.listen_port,
        arguments.cert_file,
        arguments.key_file,
        &arguments.target_address,
        arguments.domain_name
    );

#ifdef _WINDOWS
    WSACleanup();
#endif

    exit(exit_code);
}
