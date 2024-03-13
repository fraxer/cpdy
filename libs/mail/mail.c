#define _GNU_SOURCE
#include <string.h>
#include <sys/time.h>
#include <idn2.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <netdb.h>

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
int __mail_get_mx_servers(const char* host, mail_mx_record_t* mx_records);
int __mail_parse_mx_record(unsigned char* buffer, size_t r, ns_sect s, int idx, ns_msg* message, mail_mx_record_t* mx_record);

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

    mail_mx_record_t mx_records[MAIL_RECORDS_SIZE];
    memset(mx_records, 0, sizeof(mail_mx_record_t) * MAIL_RECORDS_SIZE);
    r = __mail_get_mx_servers(punycode_domain, mx_records);

    free(punycode_domain);

    if (!r) {
        log_error("[__mail_connect] Not found servers\n");
        return 0;
    }

    for (int i = 0; i < MAIL_RECORDS_SIZE; i++) {
        mail_mx_record_t* record = &mx_records[i];
        if (!record->ok) continue;

        for (int j = 0; j < MAIL_IP_LIST_SIZE; j++) {
            log_info("MX server ip: %d\n", record->ip_list[j].s_addr);

            if (record->ip_list[0].s_addr == 0) continue;

            struct sockaddr_in sockaddr;
            memset(&sockaddr, 0, sizeof(sockaddr));

            sockaddr.sin_family = AF_INET;
            sockaddr.sin_port = htons(instance->connection->port);
            sockaddr.sin_addr.s_addr = record->ip_list[0].s_addr;

            if (connect(instance->connection->fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1) {
                log_error("[createConnection] Error in connect\n");
                continue;
            }

            return 1;
        }
    }

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

int __mail_get_mx_servers(const char* host, mail_mx_record_t* mx_records) {
    union {
        HEADER hdr;
        unsigned char buf[NS_PACKETSZ];
    } buffer;

    const int buffer_size = res_query(host, ns_c_in, ns_t_mx, (unsigned char*)&buffer, sizeof(buffer));
    if (buffer_size == -1) {
        log_error("[getMXServers] Empty buffer: %s\n", strerror(errno));
        return 0;
    }

    if (buffer.hdr.rcode != NOERROR) {
        switch (buffer.hdr.rcode) {
            case FORMERR:
                log_error("[getMXServers] Buffer error: Format error\n");
                break;
            case SERVFAIL:
                log_error("[getMXServers] Buffer error: Server failure\n");
                break;
            case NXDOMAIN:
                log_error("[getMXServers] Buffer error: Name error\n");
                break;
            case NOTIMP:
                log_error("[getMXServers] Buffer error: Not implemented\n");
                break;
            case REFUSED:
                log_error("[getMXServers] Buffer error: Refused\n");
                break;
            default:
                log_error("[getMXServers] Buffer error: Unknown error\n");
        }

        return 0;
    }

    ns_msg message;
    if (ns_initparse(buffer.buf, buffer_size, &message) == -1) {
        log_error("[getMXServers] Can't init parse ns: %s\n", strerror(errno));
        return 0;
    }

    ns_rr resource_record;
    if (ns_parserr(&message, ns_s_qd, 0, &resource_record) == -1) {
        log_error("[getMXServers] Can't parse question section: %s\n", strerror(errno));
        return 0;
    }

    int result = 0;
    int answers = ntohs(buffer.hdr.ancount);
    answers = answers > MAIL_RECORDS_SIZE ? MAIL_RECORDS_SIZE : answers;
    for (int i = 0; i < answers; ++i)
        if (__mail_parse_mx_record(buffer.buf, buffer_size, ns_s_an, i, &message, &mx_records[i]))
            result = 1;

    return result;
}

int __mail_parse_mx_record(unsigned char* buffer, size_t r, ns_sect s, int idx, ns_msg* message, mail_mx_record_t* mx_record) {
    ns_rr resource_record;
    if (ns_parserr(message, s, idx, &resource_record) == -1) {
        log_error("[parseMxRecord] Can't parse answer section: %s\n", strerror(errno));
        return 0;
    }

    if (ns_rr_type(resource_record) != ns_t_mx)
        return 0;

    const unsigned char* data = ns_rr_rdata(resource_record);
    mx_record->preference = ns_get16(data);

    {
        unsigned char tmpname[NS_MAXDNAME];
        ns_name_unpack(buffer, buffer + r, data + sizeof(u_int16_t), tmpname, NS_MAXDNAME);
        ns_name_ntop(tmpname, mx_record->domain, NS_MAXDNAME);
    }

    struct hostent* he = gethostbyname(mx_record->domain);
    if (he == NULL) {
        log_error("[parseMxRecord] Error get host by name\n");
        return 0;
    }

    mx_record->ok = 1;

    int result = 0;
    struct in_addr** addr_list = (struct in_addr**)he->h_addr_list;
    for (int i = 0; addr_list[i] != NULL && i < MAIL_IP_LIST_SIZE; i++) {
        log_info("%d\n", *addr_list[i]);

        memcpy(&mx_record->ip_list[i], addr_list[i], sizeof(struct in_addr));
    }

    log_info("[parseMxRecord] pref: %d, host name: %s\n", mx_record->preference, mx_record->domain);

    return result;
}
