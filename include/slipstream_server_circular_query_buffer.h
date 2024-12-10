#ifndef SLIPSTREAM_SERVER_CIRCULAR_QUEUE_BUFFER_H
#define SLIPSTREAM_SERVER_CIRCULAR_QUEUE_BUFFER_H

#define SIZE 4096

#include "SPCDNS/src/dns.h"

typedef struct {
    dns_decoded_t queries[SIZE][DNS_DECODEBUF_4K];
    size_t tail;
    size_t head;
} circular_query_buffer_t;

dns_decoded_t* circular_query_buffer_get_write_slot(circular_query_buffer_t* buf);

dns_decoded_t* circular_query_buffer_get_read_slot(circular_query_buffer_t* buf);

size_t circular_query_buffer_get_size(circular_query_buffer_t* buf);

#endif // SLIPSTREAM_SERVER_CIRCULAR_QUEUE_BUFFER_H
