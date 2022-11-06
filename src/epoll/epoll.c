#define _GNU_SOURCE
#include <stddef.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include "../log/log.h"
#include "../server/server.h"
#include "../socket/socket.h"
#include "../connection/connection.h"
#include "../protocols/http1.h"
#include "epoll.h"
    #include <stdio.h>

char* epoll_buffer_alloc();

void epoll_run() {
    int basefd = epoll_init();

    if (basefd == -1) return;

    char* buffer = epoll_buffer_alloc();

    if (buffer == NULL) return;

    epoll_event_t events[EPOLL_MAX_EVENTS];

    while(1) {
        int n = epoll_wait(basefd, events, EPOLL_MAX_EVENTS, -1);

        while (--n >= 0) {
            epoll_event_t* ev = &events[n];

            socket_t* listen_socket = socket_find(ev->data.fd, basefd);

            if (listen_socket != NULL) {
                while (connection_create(listen_socket->fd, basefd, epoll_after_create_connection) != NULL);
                continue;
            }

            int* p_int = (int*)ev->data.ptr;

            connection_t* connection = (connection_t*)ev->data.ptr;

            int r = connection_trylock(connection);

            if (r != 0) {
                printf("try %d, %d\n", r, gettid());
                continue;
            }

            if (ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                printf("HUP, %d, %d, %p, %p\n", connection->fd, ev->data.fd, connection, connection->apidata);

                connection->close(connection);
            }
            else if (ev->events & EPOLLIN) {
                connection->read(connection, buffer, EPOLL_BUFFER);
            }
            else if (ev->events & EPOLLOUT) {
                connection->write(connection);
            }

            connection_unlock(connection);
        }
    }

    socket_free();

    close(basefd);
}

int epoll_init() {
    int basefd = epoll_create1(0);

    if (basefd == -1) {
        log_error("Epoll error: Epoll create1 failed\n");
        return -1;
    }

    for (server_t* server = server_get_first(); server; server = server->next) {
        socket_epoll_t* socket = (socket_epoll_t*)socket_listen_create(basefd, server->ip, server->port, (void*(*)())epoll_socket_alloc);

        if (socket == NULL) return -1;

        socket->event->data.fd = socket->base.fd;
        socket->event->events = EPOLLIN;

        if (epoll_ctl(basefd, EPOLL_CTL_ADD, socket->base.fd, socket->event) == -1) {
            log_error("Epoll error: Epoll_ctl failed in addListener\n");
            return -1;
        }
    }

    return basefd;
}

char* epoll_buffer_alloc() {
    return (char*)malloc(EPOLL_BUFFER);
}

int epoll_after_create_connection(connection_t* connection) {
    epoll_event_t* event = (epoll_event_t*)malloc(sizeof(epoll_event_t));

    event->data.ptr = connection;

    connection->apidata = event;
    connection->close = epoll_connection_close;
    connection->read = http1_read;
    connection->write = http1_write;
    connection->after_read_request = epoll_after_read_request;
    connection->after_write_request = epoll_after_write_request;

    if (epoll_control_add(connection, EPOLLIN) == -1) {
        log_error("Epoll error: Error epoll_ctl failed accept\n");
        return -1;
    }

    return 0;
}

socket_epoll_t* epoll_socket_alloc() {
    socket_epoll_t* socket = (socket_epoll_t*)malloc(sizeof(socket_epoll_t));

    if (socket == NULL) return NULL;

    socket->base.fd = 0;
    socket->base.next = NULL;
    socket->event = (epoll_event_t*)malloc(sizeof(epoll_event_t));

    return socket;
}

int epoll_after_read_request(connection_t* connection) {
    if (epoll_control_mod(connection, EPOLLOUT) == -1) {
        log_error("Epoll error: Epoll_ctl failed in read done, %d, %d\n", gettid(), errno);
        return -1;
    }

    return 0;
}

int epoll_after_write_request(connection_t* connection) {
    if (connection->keepalive_enabled == 0) {
        connection->close(connection);
    } else {
        if (epoll_control_mod(connection, EPOLLIN) == -1) {
            log_error("Epoll error: Epoll_ctl failed in write done, %d, %d\n", gettid(), errno);
            return -1;
        }
    }

    return 0;
}

int epoll_connection_close(connection_t* connection) {
    if (epoll_control_del(connection) == -1) return -1;

    shutdown(connection->fd, 2);

    close(connection->fd);

    connection_free(connection);

    return 0;
}

int epoll_control(connection_t* connection, int action, uint32_t flags) {
    void* event = connection->apidata;

    ((epoll_event_t*)connection->apidata)->events = flags;

    if (action == EPOLL_CTL_DEL) {
        event = NULL;
    }

    if (epoll_ctl(connection->basefd, action, connection->fd, event) == -1) {
        log_error("Epoll error: Epoll_ctl failed, %d, %d\n", gettid(), errno);
        return -1;
    }

    return 0;
}

int epoll_control_add(connection_t* connection, uint32_t flags) {
    return epoll_control(connection, EPOLL_CTL_ADD, flags);
}

int epoll_control_mod(connection_t* connection, uint32_t flags) {
    return epoll_control(connection, EPOLL_CTL_MOD, flags);
}

int epoll_control_del(connection_t* connection) {
    return epoll_control(connection, EPOLL_CTL_DEL, 0);
}