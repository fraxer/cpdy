#define _GNU_SOURCE
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>

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
        // connection already locked
        connection_t* connection = connection_queue_guard_pop();
        if (connection == NULL) {
            if (thread_handler->is_deprecated)
                break;

            continue;
        }

        cqueue_lock(connection->queue);
        connection_queue_item_t* item = cqueue_pop(connection->queue);
        cqueue_unlock(connection->queue);

        item->handle(item);
        item->free(item);
        if (connection_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
            connection_unlock(connection);
    }

    free(thread_handler);

    pthread_exit(NULL);
}

thread_handler_item_t** thread_handler_array_create(int count) {
    thread_handler_item_t** threads = malloc(sizeof(thread_handler_item_t*) * count);
    if (threads == NULL) return NULL;

    for (int i = 0; i < count; i++)
        threads[i] = NULL;

    return threads;
}

thread_handler_item_t* thread_handler_create() {
    thread_handler_item_t* item = malloc(sizeof * item);
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

    for (int i = thread_handler_count; i < thread_handler_count + handler_count; i++) {
        thread_handler_item_t* item = thread_handler_create();
        if (item == NULL) {
            free(threads);
            return -1;
        }

        if (pthread_create(&item->thread, NULL, thread_handler, item) != 0) {
            log_error("Thread error: Unable to create handler thread\n");
            if (thread_handlers)
                free(thread_handlers);

            free(threads);
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
