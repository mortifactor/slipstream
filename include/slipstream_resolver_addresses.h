#ifndef SLIPSTREAM_RESOLVERS_H
#define SLIPSTREAM_RESOLVERS_H

#include <stdio.h>

struct sockaddr_storage* read_resolver_addresses(const char *resolver_addresses_filename, size_t *count);

#endif //SLIPSTREAM_RESOLVERS_H
