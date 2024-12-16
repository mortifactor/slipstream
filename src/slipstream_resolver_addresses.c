#include "slipstream_resolver_addresses.h"

#include <stdlib.h>
#include <string.h>

#include <picosocks.h>

#define MAX_IP_LENGTH 20
#define INITIAL_CAPACITY 10
#define MAX_LINE_LENGTH 50
#define DEFAULT_PORT 53

struct sockaddr_storage* read_resolver_addresses(const char *resolver_addresses_filename, size_t *count) {
    *count = 0;

    FILE *fp = fopen(resolver_addresses_filename, "r");
    if (!fp) {
        return NULL;
    }

    int capacity = INITIAL_CAPACITY;
    struct sockaddr_storage* server_address = calloc(capacity, sizeof(struct sockaddr_storage));
    if (!server_address) {
        fclose(fp);
        return NULL;
    }

    char line[MAX_LINE_LENGTH];
    int valid_addresses = 0;

    while (fgets(line, MAX_LINE_LENGTH, fp)) {
        // Remove newline
        line[strcspn(line, "\n")] = '\0';

        // Skip empty or whitespace-only lines
        if (strlen(line) == 0 || strspn(line, " \t") == strlen(line)) {
            continue;
        }

        // Resize array if needed
        if (valid_addresses == capacity) {
            capacity *= 2;
            struct sockaddr_storage* temp = realloc(server_address, capacity * sizeof(struct sockaddr_storage));
            if (!temp) {
                fprintf(stderr, "Memory allocation failed\n");
                free(server_address);
                fclose(fp);
                return NULL;
            }
            server_address = temp;
        }

        char server_name[MAX_IP_LENGTH];
        int server_port = DEFAULT_PORT;

        // Parse line for IP and optional port
        if (sscanf(line, "%s %d", server_name, &server_port) < 1) {
            continue;  // Invalid format
        }

        printf("Adding %s:%d\n", server_name, server_port);

        int is_name = 0;
        if (picoquic_get_server_address(server_name, server_port, &server_address[valid_addresses], &is_name) != 0) {
            fprintf(stderr, "Cannot get the IP address for <%s> port <%d>\n", server_name, server_port);
            continue;  // Skip invalid addresses instead of failing
        }
        valid_addresses++;
    }

    fclose(fp);
    *count = valid_addresses;

    // Trim excess memory if needed
    if (valid_addresses < capacity) {
        struct sockaddr_storage* temp = realloc(server_address, valid_addresses * sizeof(struct sockaddr_storage));
        if (temp) {
            server_address = temp;
        }
    }

    return server_address;
}
