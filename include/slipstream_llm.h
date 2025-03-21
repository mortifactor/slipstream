#ifndef SLIPSTREAM_LLM_H
#define SLIPSTREAM_LLM_H

#include <stdio.h>
#include <netinet/in.h>


typedef struct st_llm_connection_t llm_connection_t;

typedef struct st_llm_request_t llm_request_t;

ssize_t llm_create_connection(llm_connection_t** conn_p, int port);

ssize_t llm_encode(llm_connection_t* conn, char* dest, size_t dest_len, const char* src, size_t src_len);
ssize_t llm_decode(llm_connection_t* conn, char* dest, size_t dest_len, const char* src, size_t src_len);

#endif //SLIPSTREAM_LLM_H
