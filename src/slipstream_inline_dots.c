#include "slipstream_inline_dots.h"

size_t slipstream_inline_dotify(char * __restrict__ buf, size_t buflen, size_t len) {
    size_t dots = len / 57;  // Number of dots to insert
    size_t new_len = len + dots;

    // Check if result would exceed buffer
    if (new_len > buflen) {
        return -1;  // Error condition
    }

    // Start from the end and work backwards
    char *src = buf + len - 1;    // Points to last char of original string
    char *dst = buf + new_len - 1;  // Points to where last char will end up

    // Avoid modulo operation in tight loop
    size_t next_dot = len - (len % 57);
    size_t current_pos = len;

    // Move characters right-to-left, inserting dots
    while (current_pos > 0) {
        if (current_pos == next_dot) {
            *dst-- = '.';
            next_dot -= 57;
            current_pos--;
            continue;
        }
        *dst-- = *src--;
        current_pos--;
    }

    return new_len;
}

size_t slipstream_inline_undotify(char * __restrict__ buf, size_t len) {
    char *reader = buf;
    char *writer = buf;

    // For ~255 byte buffer with dots every ~50 chars
    // Simple loop is most efficient since dots are sparse
    while (len--) {
        char c = *reader++;
        if (c != '.') {
            *writer++ = c;
        }
    }

    return writer - buf;
}