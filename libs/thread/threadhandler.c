#define _GNU_SOURCE
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "threadhandler.h"
#include "connection_queue.h"

typedef struct thread_handler_item {
    int is_deprecated;
    pthread_t thread;
} thread_handler_item_t;

static int thread_handler_index = 0;
static int thread_handler_count = 0;

static thread_handler_item_t** thread_handlers = NULL;

void* thread_handler(void* arg) {
    thread_handler_item_t* thread_handler = arg;
    if (thread_handler == NULL) pthread_exit(NULL);

    while (1) {
        connection_queue_item_t* item = connection_queue_guard_pop();
        if (item == NULL) {
            if (thread_handler->is_deprecated)
                break;

            continue;
        }

        // connection already locked
        connection_t* connection = item->connection;
        if (!connection_alive(connection)) {
            item->free(item);

            cqueue_lock(connection->queue);
            const int queue_empty = cqueue_empty(connection->queue);
            cqueue_unlock(connection->queue);

            if (queue_empty) {
                connection_free(connection);
                connection = NULL;
            }

            connection_unlock(connection);    
            continue;
        }

        item->handle(item);
        item->free(item);
        connection_unlock(connection);

        if (thread_handler->is_deprecated)
            break;
    }

    free(thread_handler);

    pthread_exit(NULL);
}

thread_handler_item_t** thread_handler_array_alloc(int count) {
    return (thread_handler_item_t**)malloc(sizeof(thread_handler_item_t*) * count);
}

thread_handler_item_t** thread_handler_array_create(int count) {
    thread_handler_item_t** threads = thread_handler_array_alloc(count);

    if (threads == NULL) return NULL;

    for (int i = 0; i < count; i++) {
        threads[i] = NULL;
    }

    return threads;
}

thread_handler_item_t* thread_handler_alloc() {
    return (thread_handler_item_t*)malloc(sizeof(thread_handler_item_t));
}

thread_handler_item_t* thread_handler_create() {
    thread_handler_item_t* item = thread_handler_alloc();

    if (item == NULL) return NULL;

    item->is_deprecated = 0;
    item->thread = 0;

    return item;
}

int thread_handler_run(int handler_count) {
    thread_handler_item_t** threads = NULL;

    if (thread_handler_count > handler_count) {
        // -
        threads = thread_handler_array_create(thread_handler_count + handler_count);
    }
    else {
        // +
        threads = thread_handler_array_create(thread_handler_count * 2 + handler_count);
    }

    if (threads == NULL) return -1;

    for (int i = thread_handler_index, j = 0; i < thread_handler_index + thread_handler_count; i++, j++) {
        if (thread_handlers[i]) {
            threads[j] = thread_handlers[i];
            (*threads[j]).is_deprecated = 1;
        }
    }

    connection_queue_broadcast();

    for (int i = thread_handler_count; i < thread_handler_count + handler_count; i++) {
        thread_handler_item_t* item = thread_handler_create();

        if (item == NULL) return -1;

        if (pthread_create(&item->thread, NULL, thread_handler, item) != 0) {
            log_error("Thread error: Unable to create handler thread\n");
            if (thread_handlers) free(thread_handlers);
            return -1;
        }

        pthread_detach(item->thread);

        pthread_setname_np(item->thread, "Server handler");

        threads[i] = item;
    }

    if (thread_handler_count > handler_count) {
        // -
        thread_handler_index = thread_handler_count;

        thread_handler_count = handler_count;
    }
    else {
        // +
        thread_handler_count = thread_handler_count + handler_count;

        thread_handler_index = thread_handler_count - handler_count;
    }

    if (thread_handlers) free(thread_handlers);

    thread_handlers = threads;

    return 0;
}

void thread_handlers_stop() {
    connection_queue_broadcast();
}
