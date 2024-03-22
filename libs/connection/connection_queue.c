#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "connection_queue.h"
#include "cqueue.h"

static cqueue_t* queue = NULL;

static pthread_cond_t connection_queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t connection_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

void __connection_queue_append(connection_queue_item_t*);
void __connection_queue_append_broadcast(connection_queue_item_t*);
int __connection_queue_empty(cqueue_t*);
connection_t* __connection_queue_pop();
void __connection_queue_item_free(connection_queue_item_t*);


void __connection_queue_append(connection_queue_item_t* qitem) {
    cqueue_item_t* item = cqueue_item_create(qitem);
    if (item == NULL) {
        log_error("Connection queue error: Can't queue item create\n");
        return;
    }

    cqueue_lock(qitem->connection->queue);
    cqueue_append(qitem->connection->queue, item);
    cqueue_unlock(qitem->connection->queue);

    cqueue_item_t* titem = cqueue_item_create(qitem->connection);
    if (titem == NULL) {
        log_error("Connection queue error: Can't queue item create\n");
        return;
    }

    cqueue_lock(queue);
    cqueue_append(queue, titem);
    cqueue_unlock(queue);

    qitem->connection->cqueue++;
}

void __connection_queue_append_broadcast(connection_queue_item_t* qitem) {
    cqueue_item_t* item = cqueue_item_create(qitem);
    if (item == NULL) {
        log_error("Connection queue error: Can't queue item create\n");
        return;
    }

    cqueue_lock(qitem->connection->queue);
    cqueue_append(qitem->connection->queue, item);
    cqueue_unlock(qitem->connection->queue);
}

void connection_queue_append_c(connection_t* connection) {
    cqueue_t* q = queue;
    cqueue_item_t* titem = cqueue_item_create(connection);
    if (titem == NULL) {
        log_error("Connection queue error: Can't queue item create\n");
        return;
    }

    cqueue_lock(queue);
    cqueue_append(queue, titem);
    cqueue_unlock(queue);

    connection->cqueue++;

    pthread_mutex_lock(&connection_queue_mutex);
    pthread_cond_signal(&connection_queue_cond);
    pthread_mutex_unlock(&connection_queue_mutex);
}

connection_t* __connection_queue_pop() {
    cqueue_lock(queue);
    connection_t* connection = cqueue_pop(queue);
    cqueue_unlock(queue);

    if (connection == NULL)
        return NULL;

    while (1) {
        if (!connection_lock(connection))
            continue;

        if (connection_alive(connection) && !connection_trylockwrite(connection)) {
            connection->queue_pop(connection);
            connection_unlock(connection);
            continue;
        }

        connection->cqueue--;
        
        break;
    }

    return connection;
}

int __connection_queue_empty(cqueue_t* queue) {
    if (queue == NULL) return 1;

    cqueue_lock(queue);
    const int empty = cqueue_empty(queue);
    cqueue_unlock(queue);

    return empty;
}

void __connection_queue_item_free(connection_queue_item_t* item) {
    if (item == NULL) return;

    if (item->data)
        item->data->free(item->data);

    free(item);
}

int connection_queue_init() {
    if (queue != NULL) return 1;

    queue = cqueue_create();
    if (queue == NULL) return 0;

    return 1;
}

void connection_queue_guard_append(connection_queue_item_t* item) {
    pthread_mutex_lock(&connection_queue_mutex);
    __connection_queue_append(item);
    pthread_cond_signal(&connection_queue_cond);
    pthread_mutex_unlock(&connection_queue_mutex);
}

void connection_queue_guard_append_broadcast(connection_queue_item_t* item) {
    __connection_queue_append_broadcast(item);
}

connection_t* connection_queue_guard_pop() {
    if (__connection_queue_empty(queue)) {
        pthread_mutex_lock(&connection_queue_mutex);
        pthread_cond_wait(&connection_queue_cond, &connection_queue_mutex);
        pthread_mutex_unlock(&connection_queue_mutex);
    }

    return __connection_queue_pop();
}

void connection_queue_broadcast() {
    pthread_mutex_lock(&connection_queue_mutex);
    pthread_cond_broadcast(&connection_queue_cond);
    pthread_mutex_unlock(&connection_queue_mutex);
}

connection_queue_item_t* connection_queue_item_create() {
    connection_queue_item_t* item = malloc(sizeof * item);
    if (item == NULL) return NULL;

    item->free = __connection_queue_item_free;
    item->handle = NULL;
    item->connection = NULL;
    item->data = NULL;

    return item;
}
