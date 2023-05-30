#ifndef __HTTP1RESPONSE__
#define __HTTP1RESPONSE__

#include "../connection/connection.h"
#include "../protocols/http1common.h"
#include "response.h"

typedef struct http1response_head {
    size_t size;
    char* data;
} http1response_head_t, http1response_string_t;

typedef struct http1response {
    response_t base;

    int status_code;
    int head_writed;
    http1_trunsfer_encoding_t transfer_encoding;
    http1_content_encoding_t content_encoding;

    http1_body_t body;
    http1_file_t file_;
    http1_header_t* header;
    http1_header_t* last_header;
    http1_ranges_t* ranges;

    connection_t* connection;
    z_stream* defstream;
    int defstream_init;

    void(*data)(struct http1response*, const char*);
    void(*datan)(struct http1response*, const char*, size_t);
    int(*header_add)(struct http1response*, const char*, const char*);
    int(*headern_add)(struct http1response*, const char*, size_t, const char*, size_t);
    int(*header_add_content_length)(struct http1response*, size_t);
    int(*header_add_content_type)(struct http1response*, const char*, size_t);
    int(*header_remove)(struct http1response*, const char*);
    int(*headern_remove)(struct http1response*, const char*, size_t);
    int(*file)(struct http1response*, const char*);
    int(*filen)(struct http1response*, const char*, size_t);
    void(*switch_to_websockets)(struct http1response*);
    http1response_string_t(*deflate)(struct http1response*, const char*, size_t, int);
} http1response_t;

http1response_t* http1response_create(connection_t*);

void http1response_default_response(http1response_t*, int);

http1response_head_t http1response_create_head(http1response_t*);

void http1response_redirect(http1response_t*, const char*, int);

int http1response_data_append(char*, size_t*, const char*, size_t);

http1response_string_t http1response_deflate(http1response_t*, const char*, size_t, int);

http1_ranges_t* http1response_init_ranges();

void http1response_free_ranges(http1_ranges_t*);

#endif
