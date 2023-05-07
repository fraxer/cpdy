#ifndef __HTTP1COMMON__
#define __HTTP1COMMON__

#include <stddef.h>
#include <zlib.h>

typedef struct http1_header {
    const char* key;
    const char* value;
    size_t key_length;
    size_t value_length;
    struct http1_header* next;
} http1_header_t;

typedef enum http1_version {
    HTTP1_VER_NONE = 0,
    HTTP1_VER_1_0,
    HTTP1_VER_1_1
} http1_version_e;

typedef struct http1_query {
    const char* key;
    const char* value;
    struct http1_query* next;
} http1_query_t;

typedef struct http1_body {
    size_t size;
    size_t pos;
    char* data;
} http1_body_t;

typedef struct http1_file {
    size_t size;
    size_t pos;
    int fd;
} http1_file_t;

typedef enum http1_content_encoding {
    CE_NONE = 0,
    CE_GZIP
} http1_content_encoding_t;

typedef enum http1_trunsfer_encoding {
    TE_NONE = 0,
    TE_CHUNKED,
    TE_GZIP
} http1_trunsfer_encoding_t;

typedef struct http1_ranges {
    ssize_t start;
    ssize_t end;
    ssize_t pos;
    struct http1_ranges* next;
} http1_ranges_t;

typedef struct http1_payloadpart {
    size_t offset;
    size_t size;
    char* field;

    struct http1_payloadpart* next;
} http1_payloadpart_t;

typedef struct http1_payloadfile {
    int payload_fd;
    size_t offset;
    size_t size;
    const char* rootdir;
    char* name;
    int(*save)(struct http1_payloadfile*, const char*, const char*);
    char*(*read)(struct http1_payloadfile*, size_t, size_t);
} http1_payloadfile_t;

typedef struct http1_payload {
    int fd;
    char* path;
    http1_payloadpart_t* part;
} http1_payload_t;

http1_header_t* http1_header_create(const char*, size_t, const char*, size_t);

void http1_header_free(http1_header_t*);

http1_query_t* http1_query_create(const char*, size_t, const char*, size_t);

void http1_query_free(http1_query_t*);

const char* http1_set_field(const char*, size_t);

#endif
