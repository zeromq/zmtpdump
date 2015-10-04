#ifndef _INCLUDED_buffer_h_
#define _INCLUDED_buffer_h_

#include <stdint.h>
#include <stdlib.h>

// TODO: data structure that is a "window" to a buffer
// that can be created without physically copying data
// from a buffer (bufferref_t).

typedef struct _buffer_t
{
    uint8_t *data;
    size_t size;
    size_t capacity;
} buffer_t;

buffer_t *BufferCreate();
size_t BufferGetSize(buffer_t *self);
void BufferDestroy(buffer_t **self);
void BufferAppend(buffer_t *self, const uint8_t *data, size_t size);
uint8_t BufferGetByte(buffer_t *self, size_t i);
void BufferCopy(buffer_t *self, size_t size, uint8_t **data_out,
    size_t *size_out);
void BufferExtract(buffer_t *self, size_t size, uint8_t **data_out,
    size_t *size_out);
int BufferGetBlock(buffer_t *self, uint8_t **block, size_t start, size_t len);
void BufferClear(buffer_t *self);
void BufferGetData(buffer_t *self, uint8_t **data, size_t *size);
void BufferRemove(buffer_t *self, size_t size);

#endif /* !_INCLUDED_buffer_h_ */
