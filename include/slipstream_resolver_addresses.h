#ifndef SLIPSTREAM_RESOLVERS_H
#define SLIPSTREAM_RESOLVERS_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>

typedef struct st_address_t {
    struct sockaddr_storage server_address;
    bool added;
} address_t;

struct st_address_t* read_resolver_addresses(const char *resolver_addresses_filename, size_t *count);

#endif //SLIPSTREAM_RESOLVERS_H
