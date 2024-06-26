#define _GNU_SOURCE
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>

#include "log.h"
#include "multiplexingserver.h"
#include "threadworker.h"

typedef struct thread_worker_item {
    pthread_t thread;
    server_chain_t* server_chain;
} thread_worker_item_t;

static int thread_worker_index = 0;
static int thread_worker_count = 0;

static thread_worker_item_t** thread_workers = NULL;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* thread_worker(void* arg) {
    thread_worker_item_t* thread_worker = (thread_worker_item_t*)arg;

    mpxserver_run(thread_worker->server_chain);

    if (pthread_mutex_trylock(&mutex) == 0) {
        server_chain_t* chain = thread_worker->server_chain;
        if (chain && chain->thread_count == 0)
            chain->destroy(chain);

        pthread_mutex_unlock(&mutex);
    }

    if (thread_worker) free(thread_worker);

    pthread_exit(NULL);
}

thread_worker_item_t** thread_worker_array_create(int count) {
    thread_worker_item_t** threads = malloc(sizeof(thread_worker_item_t*) * count);
    if (threads == NULL) return NULL;

    for (int i = 0; i < count; i++)
        threads[i] = NULL;

    return threads;
}

thread_worker_item_t* thread_worker_create(server_chain_t* server_chain) {
    thread_worker_item_t* item = malloc(sizeof * item);

    if (item == NULL) return NULL;

    item->server_chain = server_chain;
    item->thread = 0;

    return item;
}

int thread_worker_run(int worker_count, server_chain_t* server_chain) {
    thread_worker_item_t** threads = NULL;

    if (thread_worker_count > worker_count) {
        // -
        threads = thread_worker_array_create(thread_worker_count + worker_count);
    }
    else {
        // +
        threads = thread_worker_array_create(thread_worker_count * 2 + worker_count);
    }

    if (threads == NULL) return -1;

    for (int i = thread_worker_index, j = 0; i < thread_worker_index + thread_worker_count; i++, j++) {
        if (thread_workers[i]) {
            threads[j] = thread_workers[i];
            (*threads[j]).server_chain->is_deprecated = 1;
        }
    }

    for (int i = thread_worker_count; i < thread_worker_count + worker_count; i++) {
        thread_worker_item_t* item = thread_worker_create(server_chain);
        if (item == NULL) {
            free(threads);
            return -1;
        }

        if (pthread_create(&item->thread, NULL, thread_worker, item) != 0) {
            log_error("Thread error: Unable to create worker thread\n");
            if (thread_workers)
                free(thread_workers);

            free(threads);
            return -1;
        }

        server_chain->thread_count++;

        pthread_detach(item->thread);

        pthread_setname_np(item->thread, "Server worker");

        threads[i] = item;
    }

    if (thread_worker_count > worker_count) {
        // -
        thread_worker_index = thread_worker_count;

        thread_worker_count = worker_count;
    }
    else {
        // +
        thread_worker_count = thread_worker_count + worker_count;

        thread_worker_index = thread_worker_count - worker_count;
    }

    if (thread_workers) free(thread_workers);

    thread_workers = threads;

    return 0;
}
