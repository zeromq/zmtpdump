#include "buffer.h"
#include <assert.h>
#include <string.h>

buffer_t *BufferCreate()
{
    buffer_t *buffer = (buffer_t *) malloc(sizeof(buffer_t));
    memset(buffer, 0, sizeof(buffer_t));
    return buffer;
}

size_t BufferGetSize(buffer_t *self)
{
    assert(self);
    return self->size;
}

void BufferDestroy(buffer_t **self)
{
    assert(self);
    buffer_t *buffer = (buffer_t *) (*self);
    free(buffer->data);
    free(buffer);
    *self = NULL;
}

void BufferAppend(buffer_t *self, const uint8_t *data, size_t size)
{
    assert(self);
    size_t new_size = self->size + size;
    if (new_size > self->capacity) {
        size_t new_capacity = 2 * self->capacity + new_size + 8;
        if (self->data == NULL)
            self->data = (uint8_t *) malloc(new_capacity);
        else
            self->data = (uint8_t *) realloc(self->data, new_capacity);
        assert(self->data);
        self->capacity = new_capacity;
    }
    uint8_t *dest = self->data + self->size;
    memcpy(dest, data, size);
    self->size = new_size;
}

uint8_t BufferGetByte(buffer_t *self, size_t i)
{
    assert(self->data);
    assert(self->size > i);
    return self->data[i];
}

void BufferCopy(buffer_t *self, size_t size, uint8_t **data_out,
    size_t *size_out)
{
    assert(data_out);
    if (size > self->size)
        size = self->size;
    uint8_t *dest = NULL;
    if (size > 0) {
        assert(self->data);
        dest = (uint8_t *) malloc(size);
        assert(dest);
        memcpy(dest, self->data, size);
        *data_out = dest;
    } else {
        *data_out = NULL;
    }
    *size_out = size;
}

void BufferExtract(buffer_t *self, size_t size, uint8_t **data_out,
    size_t *size_out)
{
    assert(data_out);
    assert(size_out);
    if (size > self->size)
        size = self->size;
    uint8_t *dest = NULL;
    if (size > 0) {
        assert(self->data);
        dest = (uint8_t *) malloc(size);
        assert(dest);
        memcpy(dest, self->data, size);
        *data_out = dest;
        if (size < self->size) {
            size_t remaining = self->size - size;
            memmove(self->data, self->data + size, remaining);
            self->size = remaining;
        } else {
            assert(size == self->size);
            free(self->data);
            self->data = NULL;
            self->size = 0;
            self->capacity = 0;
        }
    } else {
        *data_out = NULL;
    }
    *size_out = size;
}

int BufferGetBlock(buffer_t *self, uint8_t **block, size_t start, size_t len)
{
    size_t total = start + len;
    assert(self);
    if (self->size < total)
        return 0;
    assert(block);
    *block = self->data + start;
    return 1;
}

void BufferClear(buffer_t *self)
{
    assert(self);
    self->size = 0;
}

void BufferGetData(buffer_t *self, uint8_t **data, size_t *size)
{
    assert(self);
    assert(data);
    *data = self->data;
    if (size != NULL)
        *size = self->size;
}

void BufferRemove(buffer_t *self, size_t size)
{
    assert(self);
    uint8_t *data_out;
    size_t size_out;
    BufferExtract(self, size, &data_out, &size_out);
    free(data_out);
}
