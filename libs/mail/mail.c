#include <string.h>
#include <sys/time.h>
#include <idn2.h>

#include "log.h"
#include "mail.h"

void __mail_string_reset(mail_string_t* string);
int __mail_connected(mail_t* instance);
int __mail_connect(mail_t* instance, const char* email);
mail_connection_t* __mail_connection_create();
void __mail_connection_free(mail_connection_t* connection);
int __mail_read_banner(mail_t* instance);
int __mail_send_hello(mail_t* instance);
int __mail_start_tls(mail_t* instance);
int __mail_set_from(mail_t* instance, const char* email, const char* sender_name);
int __mail_set_to(mail_t* instance, const char* email);
int __mail_set_subject(mail_t* instance, const char* subject);
int __mail_set_body(mail_t* instance, const char* body);
int __mail_send_mail(mail_t* instance);
int __mail_send_reset(mail_t* instance);
void __mail_free(mail_t* instance);
const char* __mail_domain_from_email(const char* email);
int __mail_set_conn_timeout(const int fd);

mail_t* mail_create() {
    mail_t* instance = malloc(sizeof * instance);
    if (instance == NULL) return NULL;

    instance->reseted = 0;
    instance->response_code = 0;

    __mail_string_reset(&instance->from_with_name);
    __mail_string_reset(&instance->from);
    __mail_string_reset(&instance->to);
    __mail_string_reset(&instance->subject);
    __mail_string_reset(&instance->date);
    __mail_string_reset(&instance->message_id);

    instance->connection = NULL;
    instance->body = NULL;

    instance->connected = __mail_connected;
    instance->connect = __mail_connect;
    instance->read_banner = __mail_read_banner;
    instance->send_hello = __mail_send_hello;
    instance->start_tls = __mail_start_tls;
    instance->set_from = __mail_set_from;
    instance->set_to = __mail_set_to;
    instance->set_subject = __mail_set_subject;
    instance->set_body = __mail_set_body;
    instance->send_mail = __mail_send_mail;
    instance->send_reset = __mail_send_reset;
    instance->free = __mail_free;

    return instance;
}

void __mail_string_reset(mail_string_t* string) {
    if (string == NULL) return;

    string->key[0] = 0;
    string->value[0] = 0;
    string->key_length = 0;
    string->value_length = 0;
}

int __mail_connected(mail_t* instance) {
    if (instance == NULL) return 0;
    if (instance->connection == NULL) return 0;

    return instance->connection->fd > 0;
}

int __mail_connect(mail_t* instance, const char* email) {
    if (instance == NULL) return 0;
    if (email == NULL) return 0;

    const char* domain = __mail_domain_from_email(email);
    if (domain == NULL) {
        log_error("Domain not detected by email: %s\n", email);
        return 0;
    }

    instance->connection = __mail_connection_create();
    if (instance->connection == NULL) {
        log_error("Error mail connection create\n");
        return 0;
    }

    char* punycode_domain = NULL;
    int r = idn2_to_ascii_8z(domain, &punycode_domain, IDN2_NONTRANSITIONAL);
    if (r != IDNA_SUCCESS) {
        log_error("Mail idn2_to_ascii_8z failed (%d): %s\n", r, idn2_strerror(r));
        return 0;
    }

    log_info("Mail domain: %s", punycode_domain);

    void* mx_records = get_mx_servers(punycode_domain);

    free(punycode_domain);

    // if(mx_records.size() == 0) {
    //     syslog(LOG_ERR, "[ERROR][mail/mail.cpp][createConnection] Not found servers\n");
    //     return false;
    // }

    // map<int, mx_domain*>::iterator it = mx_records.begin();

    // syslog(LOG_INFO, "[INFO][mail/mail.cpp][createConnection] MX server ip: %d", it->second->ip_list[0].s_addr);

    // struct in_addr ip_addr = it->second->ip_list[0];

    // sockaddr_in sockaddr;

    // bzero((void*)&sockaddr,sizeof(sockaddr));

    // sockaddr.sin_family      = AF_INET;
    // sockaddr.sin_port        = htons(this->port);
    // sockaddr.sin_addr.s_addr = ip_addr.s_addr;

    // if(connect(this->socket, (struct sockaddr*) &sockaddr, sizeof(sockaddr)) == -1) {
    //     syslog(LOG_ERR, "[ERROR][mail/mail.cpp][createConnection] Error in connect\n");
    //     return false;
    // }

    // for(auto &x : mx_records) {
    //     delete x.second;
    // }

    // mx_records.clear();

    // this->connected = true;

    return 0;
}

mail_connection_t* __mail_connection_create() {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd <= 0) {
        log_error("Error mail socket create\n");
        return NULL;
    }

    if (!__mail_set_conn_timeout(fd)) {
        log_error("Error mail set socket timeout\n");
        return NULL;
    }

    mail_connection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection->fd = fd;
    connection->ip = 0;
    connection->port = 0;
    connection->ssl = NULL;
    connection->ssl_ctx = NULL;

    connection->free = __mail_connection_free;

    return connection;
}

void __mail_connection_free(mail_connection_t* connection) {
    if (connection == NULL) return;

    if (connection->ssl != NULL) {
        SSL_free(connection->ssl);
        connection->ssl = NULL;
    }
    if (connection->ssl_ctx != NULL) {
        SSL_CTX_free(connection->ssl_ctx);
        connection->ssl_ctx = NULL;
    }

    free(connection);
}

int __mail_read_banner(mail_t* instance) {
    if (instance == NULL) return 0;

    return 0;
}

int __mail_send_hello(mail_t* instance) {
    if (instance == NULL) return 0;

    return 0;
}

int __mail_start_tls(mail_t* instance) {
    if (instance == NULL) return 0;

    return 0;
}

int __mail_set_from(mail_t* instance, const char* email, const char* sender_name) {
    if (instance == NULL) return 0;

    return 0;
}

int __mail_set_to(mail_t* instance, const char* email) {
    if (instance == NULL) return 0;

    return 0;
}

int __mail_set_subject(mail_t* instance, const char* subject) {
    if (instance == NULL) return 0;

    return 0;
}

int __mail_set_body(mail_t* instance, const char* body) {
    if (instance == NULL) return 0;

    return 0;
}

int __mail_send_mail(mail_t* instance) {
    if (instance == NULL) return 0;

    return 0;
}

int __mail_send_reset(mail_t* instance) {
    if (instance == NULL) return 0;

    return 0;
}

void __mail_free(mail_t* instance) {
    if (instance == NULL) return;

    if (instance->body != NULL) {
        free(instance->body);
        instance->body = NULL;
    }
    if (instance->connection != NULL) {
        instance->connection->free(instance->connection);
        instance->connection = NULL;
    }

    free(instance);
}

const char* __mail_domain_from_email(const char* email) {
    const char* domain = strchr(email, '@');
    if (domain == NULL)
        return NULL;

    domain++;

    return domain;
}

int __mail_set_conn_timeout(const int fd) {
    struct timeval timeout;      
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        log_error("Error mail setsockopt SO_RCVTIMEO: %d\n", errno);
        return 0;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        log_error("Error mail setsockopt SO_SNDTIMEO: %d\n", errno);
        return 0;
    }

    return 1;
}
