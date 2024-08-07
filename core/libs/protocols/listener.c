#include "listener.h"
#include "log.h"
#include "multiplexing.h"
#include "protocolmanager.h"
#include "broadcast.h"
#include "connection_queue.h"

static int __listener_create_connection(connection_t*, server_t*);
static void __listener_connection_set_hooks(connection_t*);
static int __listener_after_read_request(connection_t*);
static int __listener_after_write_request(connection_t*);
static int __listener_queue_append(connection_queue_item_t*);
static void __listener_queue_append_broadcast(connection_queue_item_t*);
static int __listener_queue_pop(connection_t*);

void listener_read(connection_t* socket_connection, char* buffer, size_t buffer_size) {
    (void)buffer;
    (void)buffer_size;
    connection_t* connection = connection_server_create(socket_connection);
    if (connection == NULL) return;

    __listener_create_connection(connection, socket_connection->server);
}

int __listener_create_connection(connection_t* connection, server_t* server) {
    server_t* s = server;
    while (s) {
        if (s->ip == connection->ip && s->port == connection->port) {
            connection->server = s;
            break;
        }
        s = s->next;
    }

    if (s->openssl) {
        connection->ssl_ctx = s->openssl->ctx;
        protmgr_set_tls(connection);
    }
    else
        protmgr_set_http1(connection);

    __listener_connection_set_hooks(connection);

    return connection->api->control_add(connection, MPXIN | MPXRDHUP);
}

void __listener_connection_set_hooks(connection_t* connection) {
    connection->close = listener_connection_close;
    connection->after_read_request = __listener_after_read_request;
    connection->after_write_request = __listener_after_write_request;
    connection->queue_append = __listener_queue_append;
    connection->queue_append_broadcast = __listener_queue_append_broadcast;
    connection->queue_pop = __listener_queue_pop;
}

int __listener_after_read_request(connection_t* connection) {
    return connection->api->control_mod(connection, MPXOUT | MPXRDHUP);
}

int __listener_after_write_request(connection_t* connection) {
    if (connection->keepalive_enabled == 0) {
        connection->destroyed = 1;
        return connection->api->control_mod(connection, MPXOUT | MPXIN | MPXHUP);
    }

    connection_reset(connection);

    if (connection->switch_to_protocol != NULL) {
        connection->switch_to_protocol(connection);
        connection->switch_to_protocol = NULL;
    }

    if (!cqueue_empty(connection->queue)) {
        atomic_store(&connection->onwrite, 0);
        return 1;
    }

    atomic_store(&connection->onwrite, 1);

    return connection->api->control_mod(connection, MPXIN | MPXRDHUP);
}

int __listener_queue_append(connection_queue_item_t* item) {
    if (!item->connection->api->control_mod(item->connection, MPXONESHOT))
        return 0;

    connection_queue_guard_append(item);

    atomic_store(&item->connection->onwrite, 0);

    return 1;
}

void __listener_queue_append_broadcast(connection_queue_item_t* item) {
    connection_queue_guard_append(item);
}

int __listener_queue_pop(connection_t* connection) {
    return connection->api->control_mod(connection, MPXOUT | MPXRDHUP);
}

int listener_connection_close(connection_t* connection) {
    connection_lock(connection);

    if (!connection->api->control_del(connection))
        log_error("Connection not removed from api\n");

    if (connection->ssl != NULL) {
        SSL_shutdown(connection->ssl);
        SSL_clear(connection->ssl);
    }

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    connection->destroyed = 1;
    broadcast_clear(connection);

    if (connection_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_unlock(connection);

    return 1;
}
