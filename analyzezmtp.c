#include "analyzezmtp.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <endian.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>

size_t LongLongToSize(uint8_t *data)
{
    uint64_t val = be64toh(*(uint64_t *) data);
    return (size_t) val;
}

size_t LongToSize(uint8_t *data)
{
    uint32_t val = be32toh(*(uint32_t *) data);
    return (size_t) val;
}

void ZmtpReaderGenerateBinaryOutput(uint8_t *data, size_t len,
    char **ascii, char **binary)
{
    assert(ascii);
    assert(binary);
    char *ascii_tmp;
    char *binary_tmp;
    ascii_tmp = (char *) malloc(len + 1);
    assert(ascii_tmp);
    binary_tmp = (char *) malloc(3 * len + 1);
    assert(binary_tmp);
    int i;
    for (i = 0; i < len; i++) {
        if (isgraph(data[i]))
            ascii_tmp[i] = (char) data[i];
        else
            ascii_tmp[i] = '.';
        sprintf(binary_tmp + 3 * i, "%02x ", data[i]);
    }
    ascii_tmp[len] = '\0';
    binary_tmp[3 * len - 1] = '\0';
    *ascii = ascii_tmp;
    *binary = binary_tmp;
}

zmtpreader_t *ZmtpReaderNew()
{
    zmtpreader_t *reader = (zmtpreader_t *) malloc(sizeof(zmtpreader_t));
    assert(reader);
    memset(reader, 0, sizeof(zmtpreader_t));
    reader->state = ZMTP_STATE_INIT;
    reader->buffer = BufferCreate();
    reader->error = 0;
    assert(reader->buffer);
    return reader;
}

void ZmtpReaderDestroy(zmtpreader_t **self)
{
    assert(self);
    zmtpreader_t *reader = *self;
    if (reader != NULL) {
        free((void*) reader->id);
        BufferDestroy(&reader->buffer);
        free(reader);
    }
    *self = NULL;
}

void ZmtpReaderSetID(zmtpreader_t *self, const char *id)
{
    assert(self);
    assert(id);
    free((void*)self->id);
    self->id = strdup(id);
    assert(self->id);
}

void ZmtpReaderReport(zmtpreader_t *self, const char *fmt, ...)
{
    assert(self);
    assert(fmt);
    if (self->id != NULL)
        printf("%s: ", self->id);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

int ZmtpReaderGetState(zmtpreader_t *self)
{
    assert(self);
    return self->state;
}

void ZmtpReaderPush(zmtpreader_t *self, const uint8_t *data, size_t len)
{
    assert(self);
    BufferAppend(self->buffer, data, len);
    int processed = 0; // Number of bytes processed

    while (!self->error) {
        processed = 0;
        switch (self->state) {
            case ZMTP_STATE_INIT: // Get a greeting
                processed = ZmtpReader_Greeting(self);
                break;
            case ZMTP_STATE_WAIT_HANDSHAKE:
                processed = ZmtpReader_Handshake(self);
                break;
            case ZMTP_STATE_WAIT_PACKET:
                processed = ZmtpReader_Frame(self);
            default:
                break;
        }
        if (processed == 0)
            break;
    }
}

int ZmtpReader_Greeting(zmtpreader_t *self)
{
    // TODO: print error message for each case when there is something
    //       wrong with input data.
    assert(self);
    if (BufferGetSize(self->buffer) < 64)
        return 0;

    ZmtpReaderReport(self, "Analyzing greeting\n");
    ZmtpReader_Signature(self);
    if (self->error)
        return 0;
    ZmtpReader_Version(self);
    if (self->error)
        return 0;
    ZmtpReader_Mechanism(self);
    if (self->error)
        return 0;
    ZmtpReader_As_Server(self);
    if (self->error)
        return 0;
    ZmtpReader_Filler(self);
    if (self->error)
        return 0;
    self->state = ZMTP_STATE_WAIT_HANDSHAKE;
    return 64;
}

int ZmtpReader_Signature(zmtpreader_t *self)
{
    assert(self);
    assert(!self->error);
    if (BufferGetSize(self->buffer) < 10)
        return 0;
    uint8_t *data;
    size_t size;
    BufferExtract(self->buffer, 10, &data, &size);
    assert(size == 10);
    if (data[0] != 0xff) {
        self->error = 1;
        free(data);
        return 0;
    }
    if (data[9] != 0x7f) {
        self->error = 1;
        free(data);
        return 0;
    }
    ZmtpReaderReport(self, "Signature\n");
    free(data);
    return 10;
}

int ZmtpReader_Version(zmtpreader_t *self)
{
    assert(self);
    assert(!self->error);
    if (BufferGetSize(self->buffer) < 2)
        return 0;
    uint8_t *data;
    size_t size;
    BufferExtract(self->buffer, 2, &data, &size);
    self->version_major = data[0];
    self->version_minor = data[1];
    ZmtpReaderReport(self, "Version: %02x.%02x\n",
      (int) self->version_major, (int) self->version_minor);
    free(data);
    return 2;
}

int ZmtpReader_Mechanism(zmtpreader_t *self)
{
    assert(self);
    assert(!self->error);
    if (BufferGetSize(self->buffer) < 20)
        return 0;
    uint8_t *data;
    size_t size;
    BufferExtract(self->buffer, 20, &data, &size);
    assert(size == 20);
    char *strMechanism = "NULL";
    if (memcmp(data, strMechanism, strlen(strMechanism)) != 0) {
        // Mechanism is not "NULL"; at this point we only accept
        // NULL so we don't process this connection any more.
        ZmtpReaderReport(self, "Only mechanism NULL supported\n");
        self->error = 1;
        free(data);
        return 0;
    }
    self->mechanism = "NULL";
    ZmtpReaderReport(self, "Mechanism: %s\n", self->mechanism);
    free(data);
    return 20;
}

int ZmtpReader_As_Server(zmtpreader_t *self)
{
    assert(self);
    assert(!self->error);
    if (BufferGetSize(self->buffer) < 1)
        return 0;
    uint8_t *data;
    size_t size;
    BufferExtract(self->buffer, 1, &data, &size);
    assert(size == 1);
    int as_server = data[0];
    free(data);
    if ((as_server != 0) && (as_server != 1)) {
        self->error = 1;
        return 0;
    }
    self->as_server = as_server;
    ZmtpReaderReport(self, "as-server: %d\n", as_server);
    return 0;
}

int ZmtpReader_Filler(zmtpreader_t *self)
{
    assert(self);
    assert(!self->error);
    if (BufferGetSize(self->buffer) < 31)
        return 0;
    uint8_t *data;
    size_t size;
    BufferExtract(self->buffer, 31, &data, &size);
    assert(size == 31);
    uint8_t filler[31] = { 0 };
    if (memcmp(data, filler, 31) != 0) {
        self->error = 1;
        return 0;
    }
    free(data);
    ZmtpReaderReport(self, "Filler\n");
    return 31;
}

int ZmtpReader_Handshake(zmtpreader_t *self)
{
    int res = ZmtpReader_Frame(self);
    if (self->error)
        return 0;
    if (res > 0) {
        BufferRemove(self->buffer, res);
        self->state= ZMTP_STATE_WAIT_PACKET;
    }
    return res;
}

int ZmtpReader_Frame(zmtpreader_t *self)
{
    assert(self);
    uint8_t *data;
    size_t len;
    size_t processed;
    BufferGetData(self->buffer, &data, &len);
    if (len < 1) {
        return 0;
    }
    int type = data[0]; // type of frame
    size_t payload_size;
    uint8_t *payload;
    if ((type == 4) || (type == 0) || (type == 1)) { // short size
        if (len < 2)
            return 0;
        payload_size = data[1];
        if (len < 2 + payload_size)
            return 0;
        payload = data + 2;
        processed = 2 + payload_size;
    } else if ((type == 6) || (type == 3) || (type == 2)) { // long size
        if (len < 9)
            return 0;
        payload_size = LongLongToSize(&data[1]);
        if (len < 9 + payload_size)
            return 0;
        payload = data + 9;
        processed = 9 + payload_size;
    } else { // Wrong first byte
        self->error = 1;
        return 0;
    }
    if ((type == 4) || (type == 6)) { // command
        uint8_t *name;
        size_t name_len;
        uint8_t *after;
        size_t after_len;
        int res = ZmtpReaderGetKey(payload, payload_size, &name, &name_len,
            &after, &after_len);
        if (!res) {
            self->error = 1;
            goto End;
        }
        uint8_t *ready_check = (uint8_t *) "READY";
        if ((name_len != 5) || (memcmp(name, ready_check, 5) != 0)) {
            char *name_ascii;
            char *name_binary;
            ZmtpReaderGenerateBinaryOutput(name, name_len,
                &name_ascii, &name_binary);
            ZmtpReaderReport(self, "command: \"%s\" %s\n", name_ascii,
                name_binary);
            free(name_ascii);
            free(name_binary);
            char *command_data_ascii;
            char *command_data_binary;
            ZmtpReaderGenerateBinaryOutput(after, after_len,
                &command_data_ascii, &command_data_binary);
            ZmtpReaderReport(self, "command data: \"%s\" %s\n",
                command_data_ascii, command_data_binary);
            free(command_data_ascii);
            free(command_data_binary);
            goto End;
        }
        ZmtpReaderReport(self, "READY command\n");
        uint8_t *before;
        size_t before_len;
        uint8_t *property, *value;
        size_t property_len, value_len;
        before = after;
        before_len = after_len;
        while (before_len > 0) {
            res = ZmtpReaderGetKeyAndValue(before, before_len,
                &property, &property_len,
                &value, &value_len,
                &after, &after_len);
            if (!res || (property_len == 0)) {
                ZmtpReaderReport(self, "Bad property\n");
                self->error = 1;
                goto End;
            }
            char *property_ascii;
            char *property_binary;
            char *value_ascii;
            char *value_binary;
            ZmtpReaderGenerateBinaryOutput(property, property_len,
                &property_ascii, &property_binary);
            ZmtpReaderGenerateBinaryOutput(value, value_len,
                &value_ascii, &value_binary);
            ZmtpReaderReport(self, "property: \"%s\" %s\n", property_ascii,
                property_binary);
            ZmtpReaderReport(self, "value: \"%s\" %s\n", value_ascii,
                value_binary);
            free(property_ascii);
            free(property_binary);
            free(value_ascii);
            free(value_binary);

            before = after;
            before_len = after_len;
        }
    } else { // message
        char *message_ascii;
        char *message_binary;
        ZmtpReaderGenerateBinaryOutput(payload, payload_size,
            &message_ascii, &message_binary);
        char *message;
        if ((type == 0) || (type == 2))
            message = "message";
        else
            message = "message-more";
        ZmtpReaderReport(self, "%s: \"%s\" %s\n", message, message_ascii,
            message_binary);
        free(message_ascii);
        free(message_binary);
    }

End:
    BufferRemove(self->buffer, processed);
    return processed;
}

int ZmtpReaderGetKey(uint8_t *data, size_t len,
        uint8_t **key, size_t *key_len,
        uint8_t **after, size_t *after_len)
{
    assert(data);
    assert(key);
    assert(key_len);
    assert(after);
    if (len < 1)
        return 0;
    size_t l_key_len = data[0];
    if (l_key_len + 1 > len) // Wrong length encoded in the first byte
        return 0;
    *key_len = l_key_len;
    *key = data + 1;
    if (len > l_key_len + 1) { // There is something left in the buffer.
        *after = *key + l_key_len;
        *after_len = len - 1 - l_key_len;
    } else {
        *after = NULL;
        *after_len = 0;
    }
    return 1;
}

int ZmtpReaderGetValue(uint8_t *data, size_t len,
    uint8_t **value, size_t *value_len,
    uint8_t **after, size_t *after_len)
{
    assert(data);
    assert(value);
    assert(value_len);
    assert(after);
    if (len < 4)
        return 0;
    size_t l_value_len = LongToSize(data);
    if (l_value_len + 4 > len) // Wrong length encoded in the first 4 bytes
        return 0;
    *value_len = l_value_len;
    *value = data + 4;
    if (len > l_value_len + 4) { // There is something left in the buffer.
        *after = *value + l_value_len;
        *after_len = len - 4 - l_value_len;
    } else {
        *after = NULL;
        *after_len = 0;
    }
    return 1;
}

int ZmtpReaderGetKeyAndValue(uint8_t *data, size_t len,
    uint8_t **key, size_t *key_len,
    uint8_t **value, size_t *value_len,
    uint8_t **after, size_t *after_len)
{
    int res;
    uint8_t *after_key;
    size_t after_key_len;

    res = ZmtpReaderGetKey(data, len, key, key_len,
        &after_key, &after_key_len);
    if (!res)
        return 0;
    if (after_key_len == 0) // There is no value.
        return 0;
    res = ZmtpReaderGetValue(after_key, after_key_len,
        value, value_len, after, after_len);
    if (!res)
        return 0;
    return 1;
}
