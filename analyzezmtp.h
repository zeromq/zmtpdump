#ifndef _analysezmtp_h_INC_
#define _analysezmtp_h_INC_

#include <stdint.h>
#include <stdlib.h>
#include "buffer.h"

// ZMTP reader states
enum zmtpreader_state_t
{
    ZMTP_STATE_INIT = 0,
    ZMTP_STATE_WAIT_HANDSHAKE,
    ZMTP_STATE_WAIT_PACKET,
    ZMTP_STATE_INVALID
};

typedef struct _zmtpreader_t
{
    const char *id;
    int state;
    buffer_t *buffer;
    int error;
    uint8_t version_major;
    uint8_t version_minor;
    char *mechanism;
    int as_server;
    char report[1024]; // Message to write to output.
} zmtpreader_t;

zmtpreader_t *ZmtpReaderNew();
void ZmtpReaderDestroy(zmtpreader_t **self);

void ZmtpReaderSetID(zmtpreader_t *self, const char *id);
void ZmtpReaderReport(zmtpreader_t *self, const char *fmt, ...);

int ZmtpReaderGetState(zmtpreader_t *self);
void ZmtpReaderPush(zmtpreader_t *self, const uint8_t *data, size_t len);

int ZmtpReader_Greeting(zmtpreader_t *self);

int ZmtpReader_Signature(zmtpreader_t *self);
int ZmtpReader_Version(zmtpreader_t *self);
int ZmtpReader_Mechanism(zmtpreader_t *self);
int ZmtpReader_As_Server(zmtpreader_t *self);
int ZmtpReader_Filler(zmtpreader_t *self);
int ZmtpReader_Handshake(zmtpreader_t *self);

int ZmtpReader_Frame(zmtpreader_t *self);

int ZmtpReaderGetKey(uint8_t *data, size_t len,
    uint8_t **key, size_t *key_len,
    uint8_t **after, size_t *after_len);
int ZmtpReaderGetValue(uint8_t *data, size_t len,
    uint8_t **key, size_t *key_len,
    uint8_t **after, size_t *after_len);
int ZmtpReaderGetKeyAndValue(uint8_t *data, size_t len,
    uint8_t **key, size_t *key_len,
    uint8_t **value, size_t *value_len,
    uint8_t **after, size_t *after_len);

// Helper functions
size_t LongLongToSize(uint8_t *data);
size_t LongToSize(uint8_t *data);

void ZmtpReaderGenerateBinaryOutput(uint8_t *data, size_t len,
    char **ascii, char **binary);

#endif /* !_analysezmtp_h_INC_ */
