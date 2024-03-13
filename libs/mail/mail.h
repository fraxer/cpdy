#ifndef __MAIL__
#define __MAIL__

#include <arpa/inet.h>

#include "openssl.h"

#define MAIL_IP_LIST_SIZE 5
#define MAIL_RECORDS_SIZE 5

typedef struct mail_string {
    char key[64];
    char value[2048];
    size_t key_length;
    size_t value_length;
} mail_string_t;

typedef struct mail_connection {
    int fd;
    in_addr_t ip;
    unsigned short port;
    SSL* ssl;
    SSL_CTX* ssl_ctx;

    void(*free)(struct mail_connection* connection);
} mail_connection_t;

typedef struct mail {
    int reseted;
    int response_code;
    mail_string_t from_with_name;
    mail_string_t from;
    mail_string_t to;
    mail_string_t subject;
    mail_string_t date;
    mail_string_t message_id;

    mail_connection_t* connection;
    char* body;

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

#endif