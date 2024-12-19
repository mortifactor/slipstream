#include <assert.h>
#include <picohash.h>
#include <string.h>
#include <stdlib.h>

#include "picoquic.h"
#include "picoquic_utils.h"
#include "slipstream_utils.h"
#include "slipstream_dns_request_buffer.h"


static uint64_t cnxid_to_cnxid_buffer_hash(const void* key) {
    const cnxid_to_cnxid_buffer_t* l_cid = key;
    return picoquic_connection_id_hash(&l_cid->cnx_id);
}

static int cnxid_to_cnxid_buffer_compare(const void* key1, const void* key2) {
    const cnxid_to_cnxid_buffer_t* l_cid1 = key1;
    const cnxid_to_cnxid_buffer_t* l_cid2 = key2;

    return picoquic_compare_connection_id(&l_cid1->cnx_id, &l_cid2->cnx_id);
}

void slipstream_dns_request_buffer_init(slipstream_dns_request_buffer_t* buffer) {
    memset(buffer, 0, sizeof(slipstream_dns_request_buffer_t));

    buffer->head = NULL;
    buffer->tail = NULL;

    for (int i = 0; i < GLOBAL_BUFFER_SIZE; i++) {
        slot_t* element = &buffer->slots[i];
        element->buffer_next = buffer->free;
        element->buffer_prev = NULL;
        buffer->free = element;
    }

    buffer->cnxid_to_cnxid_buffer = picohash_create(32, cnxid_to_cnxid_buffer_hash, cnxid_to_cnxid_buffer_compare);
}

slipstream_cnxid_dns_request_buffer_t* slipstream_dns_request_buffer_get_cnxid_buffer(
    slipstream_dns_request_buffer_t* buffer, picoquic_connection_id_t* initial_cnxid, bool create) {
    cnxid_to_cnxid_buffer_t key = {
        .cnx_id = *initial_cnxid,
        .cnxid_buffer = NULL
    };
    const picohash_item* item = picohash_retrieve(buffer->cnxid_to_cnxid_buffer, &key);
    if (item != NULL) {
        return ((cnxid_to_cnxid_buffer_t*)item->key)->cnxid_buffer;
    }
    if (!create) {
        return NULL;
    }

    char* initial_cnxid_str = picoquic_connection_id_to_string(initial_cnxid);
    DBG_PRINTF("creating new hash key for %s\n", initial_cnxid_str);
    free(initial_cnxid_str);

    cnxid_to_cnxid_buffer_t* new_key = malloc(sizeof(cnxid_to_cnxid_buffer_t));
    memcpy(&new_key->cnx_id, initial_cnxid, sizeof(picoquic_connection_id_t));

    new_key->cnxid_buffer = malloc(sizeof(slipstream_cnxid_dns_request_buffer_t));
    memset(new_key->cnxid_buffer, 0, sizeof(slipstream_cnxid_dns_request_buffer_t));
    if (new_key->cnxid_buffer == NULL) {
        fprintf(stderr, "error allocating memory for cnx buffer\n");
        return NULL;
    }

    if (picohash_insert(buffer->cnxid_to_cnxid_buffer, new_key) < 0) {
        free(new_key->cnxid_buffer);
        fprintf(stderr, "error adding a cnx buffer for a new cnx id\n");
        return NULL;
    }

    buffer->cnxid_buffers_len++;
    slipstream_cnxid_dns_request_buffer_t** cnxid_buffers = realloc(buffer->cnxid_buffers,
        buffer->cnxid_buffers_len * sizeof(slipstream_cnxid_dns_request_buffer_t*));
    if (cnxid_buffers == NULL) {
        return NULL;
    }
    buffer->cnxid_buffers = cnxid_buffers;
    buffer->cnxid_buffers[buffer->cnxid_buffers_len - 1] = new_key->cnxid_buffer;

    return new_key->cnxid_buffer;
}


void slipstream_dns_request_buffer_free_slot(slipstream_dns_request_buffer_t* buffer, slot_t* slot) {
    slipstream_cnxid_dns_request_buffer_t* cnxid_buffer = slot->cnxid_buffer;
    if (cnxid_buffer != NULL) {
        if (slot->cnxid_buffer_prev != NULL) {
            slot->cnxid_buffer_prev->cnxid_buffer_next = slot->cnxid_buffer_next;
        }

        if (slot->cnxid_buffer_next != NULL) {
            slot->cnxid_buffer_next->cnxid_buffer_prev = slot->cnxid_buffer_prev;
        }

        if (cnxid_buffer->head == slot) {
            cnxid_buffer->head = slot->cnxid_buffer_next;
        }

        if (cnxid_buffer->tail == slot) {
            cnxid_buffer->tail = slot->cnxid_buffer_prev;
        }

        slot->cnxid_buffer = NULL;
    }

    if (slot->buffer_prev != NULL) {
        slot->buffer_prev->buffer_next = slot->buffer_next;
    }

    if (slot->buffer_next != NULL) {
        slot->buffer_next->buffer_prev = slot->buffer_prev;
    }

    if (buffer->head == slot) {
        buffer->head = slot->buffer_next;
    }

    if (buffer->tail == slot) {
        buffer->tail = slot->buffer_prev;
    }

    if (buffer->free) {
        buffer->free->buffer_prev = slot;
    }
    slot->buffer_next = buffer->free;
    buffer->free = slot;
    slot->query_id = 0;
}

slot_t* slipstream_dns_request_buffer_get_write_slot(slipstream_dns_request_buffer_t* buffer) {
    if (!buffer->free) {
        return NULL;
    }

    // Get the first free element
    slot_t* slot = buffer->free;
    buffer->free = slot->buffer_next;

    // Add the element to the head of the global buffer
    slot->buffer_next = buffer->head;
    slot->buffer_prev = NULL;
    buffer->head = slot;
    if (slot->buffer_next != NULL) {
        slot->buffer_next->buffer_prev = slot;
    }

    // If the tail is NULL (first element), set it to the new element
    if (buffer->tail == NULL) {
        buffer->tail = slot;
    }

    return slot;
}

// TODO: what happens if we don't commit
void slipstream_dns_request_buffer_commit_slot_to_cnxid_buffer(slipstream_dns_request_buffer_t* buffer,
                                                               slipstream_cnxid_dns_request_buffer_t* cnxid_buffer,
                                                               slot_t* slot) {
    slot->cnxid_buffer = cnxid_buffer;

    // Add this slot to a specific cnxid buffer
    slot->cnxid_buffer_next = cnxid_buffer->head;
    slot->cnxid_buffer_prev = NULL;
    cnxid_buffer->head = slot;
    if (slot->cnxid_buffer_next != NULL) {
        slot->cnxid_buffer_next->cnxid_buffer_prev = slot;
    }

    // If the tail is NULL (first element), set it to the new element
    if (cnxid_buffer->tail == NULL) {
        cnxid_buffer->tail = slot;
    }
}

slot_t* slipstream_dns_request_buffer_get_read_slot(slipstream_dns_request_buffer_t* buffer,
                                                             slipstream_cnxid_dns_request_buffer_t* cnxid_buffer) {
    // Get the last element from the cnxid buffer
    slot_t* slot = cnxid_buffer->tail;
    if (!slot) {
        return NULL;
    }

    return slot;
}

// TODO: free up cnxid_buffer
