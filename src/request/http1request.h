#ifndef __HTTP1REQUEST__
#define __HTTP1REQUEST__

#include "../route/route.h"
#include "../connection/connection.h"
#include "../protocols/http1common.h"
#include "../jsmn/jsmn.h"
#include "request.h"

typedef struct http1request {
    request_t base;
    route_methods_e method;
    http1_version_e version;
    http1_payload_t payload_;

    size_t uri_length;
    size_t path_length;
    size_t ext_length;

    const char* uri;
    const char* path;
    const char* ext;

    http1_query_t* query;
    http1_query_t* last_query;
    http1_header_t* header_;
    http1_header_t* last_header;

    connection_t* connection;

    http1_header_t*(*header)(struct http1request*, const char*);
    http1_header_t*(*headern)(struct http1request*, const char*, size_t);

    db_t*(*database_list)(struct http1request*);

    char*(*payload)(struct http1request*);
    char*(*payloadf)(struct http1request*, const char*);
    char*(*payload_urlencoded)(struct http1request*, const char*);
    http1_payloadfile_t(*payload_file)(struct http1request*);
    http1_payloadfile_t(*payload_filef)(struct http1request*, const char*);
} http1request_t;

http1request_t* http1request_create(connection_t*);

char* http1request_payload(http1request_t*);
char* http1request_payloadf(http1request_t*, const char*);
char* http1request_payload_urlencoded(http1request_t*, const char*);
http1_payloadfile_t http1request_payload_file(http1request_t*);
http1_payloadfile_t http1request_payload_filef(http1request_t*, const char*);

#endif
