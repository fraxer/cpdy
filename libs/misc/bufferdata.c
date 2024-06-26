#include <stdlib.h>
#include <string.h>

#include "bufferdata.h"

void bufferdata_init(bufferdata_t* buffer) {
    buffer->dynamic_buffer = NULL;
    buffer->offset_sbuffer = 0;
    buffer->offset_dbuffer = 0;
    buffer->dbuffer_size = 0;
    buffer->type = BUFFERDATA_STATIC;
}

int bufferdata_push(bufferdata_t* buffer, char ch) {
    buffer->static_buffer[buffer->offset_sbuffer] = ch;
    buffer->offset_sbuffer++;

    if (buffer->offset_sbuffer < BUFFERDATA_SIZE) {
        buffer->static_buffer[buffer->offset_sbuffer] = 0;
        return 1;
    }

    buffer->type = BUFFERDATA_DYNAMIC;

    return bufferdata_move(buffer);
}

void bufferdata_reset(bufferdata_t* buffer) {
    buffer->offset_dbuffer = 0;
    buffer->offset_sbuffer = 0;
    buffer->type = BUFFERDATA_STATIC;
}

void bufferdata_clear(bufferdata_t* buffer) {
    bufferdata_reset(buffer);

    if (buffer->dynamic_buffer != NULL)
        free(buffer->dynamic_buffer);

    buffer->dynamic_buffer = NULL;
    buffer->dbuffer_size = 0;
}

size_t bufferdata_writed(bufferdata_t* buffer) {
    if (buffer->type == BUFFERDATA_DYNAMIC)
        return buffer->offset_dbuffer + buffer->offset_sbuffer;

    return buffer->offset_sbuffer;
}

int bufferdata_complete(bufferdata_t* buffer) {
    if (buffer->type == BUFFERDATA_DYNAMIC)
        return bufferdata_move(buffer);

    return 1;
}

int bufferdata_move(bufferdata_t* buffer) {
    if (buffer->type != BUFFERDATA_DYNAMIC)
        return 1;

    size_t dbuffer_length = buffer->offset_dbuffer + buffer->offset_sbuffer;

    if (buffer->dbuffer_size <= dbuffer_length) {
        char* data = realloc(buffer->dynamic_buffer, dbuffer_length + 1);

        if (data == NULL) return 0;

        buffer->dbuffer_size = dbuffer_length + 1;
        buffer->dynamic_buffer = data;
    }

    memcpy(&buffer->dynamic_buffer[buffer->offset_dbuffer], buffer->static_buffer, buffer->offset_sbuffer);

    buffer->dynamic_buffer[dbuffer_length] = 0;
    buffer->offset_dbuffer = dbuffer_length;
    buffer->offset_sbuffer = 0;

    return 1;
}

char* bufferdata_get(bufferdata_t* buffer) {
    if (buffer->type == BUFFERDATA_DYNAMIC)
        return buffer->dynamic_buffer;

    return buffer->static_buffer;
}

char* bufferdata_copy(bufferdata_t* buffer) {
    char* string = bufferdata_get(buffer);
    size_t length = bufferdata_writed(buffer);

    char* data = malloc(length + 1);
    if (data == NULL) return NULL;

    memcpy(data, string, length);
    data[length] = 0;

    return data;
}

char bufferdata_back(bufferdata_t* buffer) {
    const ssize_t position = bufferdata_writed(buffer) - 1;
    if (position == -1) return 0;

    if (buffer->offset_sbuffer > 0)
        return buffer->static_buffer[position];

    return buffer->dynamic_buffer[position];
}

char bufferdata_pop_back(bufferdata_t* buffer) {
    const ssize_t position = bufferdata_writed(buffer) - 1;
    if (position == -1) return 0;

    char c = 0;
    if (buffer->offset_sbuffer > 0) {
        c = buffer->static_buffer[position];
        buffer->static_buffer[position] = 0;
        buffer->offset_sbuffer--;
    }
    else {
        c = buffer->dynamic_buffer[position];
        buffer->dynamic_buffer[position] = 0;
        buffer->offset_dbuffer--;
    }

    return c;
}
