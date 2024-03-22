#ifndef __MAIL__
#define __MAIL__

#include <arpa/inet.h>

#include "openssl.h"

#define MAIL_IP_LIST_SIZE 5
#define MAIL_RECORDS_SIZE 5
#define MAIL_STRING_SIZE 1024

typedef struct mail_string {
    char string[MAIL_STRING_SIZE];
    size_t length;
} mail_string_t;

typedef struct mail_connection {
    int fd;
    in_addr_t ip;
    unsigned short port;
    SSL* ssl;
    SSL_CTX* ssl_ctx;

    void(*free)(struct mail_connection* connection);
    int(*close)(struct mail_connection* connection);
    void(*read)(struct mail_connection* connection, char* buffer, size_t buffer_size);
    void(*write)(struct mail_connection* connection, char* buffer, size_t buffer_size);
} mail_connection_t;

typedef struct mail_header {
    char* key;
    char* value;
    size_t key_length;
    size_t value_length;
    struct mail_header* next;
} mail_header_t;

typedef struct mail {
    int reseted;
    int response_code;
    char response_text[4096];
    mail_string_t from_with_name;
    mail_string_t from;
    mail_string_t to;
    mail_string_t subject;
    mail_string_t date;
    mail_string_t message_id;

    mail_connection_t* connection;
    char* buffer;
    char* data;
    size_t data_size;
    char* content;
    size_t content_size;

    mail_header_t* _header;
    mail_header_t* _last_header;

    int(*connected)(struct mail* instance);
    int(*connect)(struct mail* instance, const char* email);

    int(*read_banner)(struct mail* instance);
    int(*send_hello)(struct mail* instance);
    int(*start_tls)(struct mail* instance);
    int(*set_from)(struct mail* instance, const char* email, const char* sender_name);
    int(*set_to)(struct mail* instance, const char* email);
    int(*set_subject)(struct mail* instance, const char* subject);
    int(*set_body)(struct mail* instance, const char* body);

    int(*send_mail)(struct mail* instance);
    int(*send_reset)(struct mail* instance);

    void(*free)(struct mail* instance);
} mail_t;

typedef struct mail_mx_record {
    int ok;
    int preference;
    char domain[NS_MAXDNAME];
    struct in_addr ip_list[MAIL_IP_LIST_SIZE];
} mail_mx_record_t;

mail_t* mail_create();
int mail_is_real(const char* email);

#endif