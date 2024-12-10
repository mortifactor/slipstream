#include <time.h>
#include "slipstream_server_circular_query_buffer.h"

#include "picoquic_utils.h"
#include "SPCDNS/src/dns.h"


// Get next available slot for writing
dns_decoded_t* circular_query_buffer_get_write_slot(circular_query_buffer_t* buf) {
    dns_decoded_t* slot = buf->queries[buf->head];

    // Move head forward
    buf->head = (buf->head + 1) % SIZE;

    // If we've caught up to tail, move tail forward
    if (buf->head == buf->tail) {
        buf->tail = (buf->tail + 1) % SIZE;
    }

    return slot;
}

// Get next available item for reading
dns_decoded_t* circular_query_buffer_get_read_slot(circular_query_buffer_t* buf) {
    // Check if buffer is empty
    if (buf->tail == buf->head) {
        return NULL;
    }

    dns_decoded_t* slot = buf->queries[buf->tail];
    buf->tail = (buf->tail + 1) % SIZE;

    return slot;
}

size_t circular_query_buffer_get_size(circular_query_buffer_t* buf) {
    if (buf->head >= buf->tail) {
        return buf->head - buf->tail;
    } else {
        return SIZE - buf->tail + buf->head;
    }
}