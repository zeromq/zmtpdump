#include "CuTest.h"
#include <stdint.h>
#include "analyzezmtp.h"

void TestZmtp(CuTest *tc)
{
//    CuFail(tc, "testing the test");
    zmtpreader_t *reader = ZmtpReaderNew();
    CuAssertTrue(tc, reader != NULL);

    ZmtpReaderSetID(reader, "Connection");

    // Check: reader is in initial state
    int state = ZmtpReaderGetState(reader);
    // Check: state is initial state
    CuAssertIntEquals(tc, ZMTP_STATE_INIT, state);

    // Push partial greeting - just signature
    uint8_t partial_greeting[] =
    {
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x7f
    };
    ZmtpReaderPush(reader, partial_greeting, sizeof(partial_greeting));
    state = ZmtpReaderGetState(reader);
    // Check: state is still initial state; we haven't seen the full
    //        greeting yet.
    CuAssertIntEquals(tc, ZMTP_STATE_INIT, state);

    //   - check: push full greeting and reader reports:
    //              signature 0xff padding 0x7f
    //              version
    //                major: 0x03
    //                minor: 0x00
    //                mechanism "NULL"
    //              as-server 0x00
    //              filler    31 * 0x00
    uint8_t greeting_remainder[] =
    {
0x03, 0x00, 0x4e, 0x55, 0x4c, 0x4c,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ZmtpReaderPush(reader, greeting_remainder, sizeof(greeting_remainder));
    state = ZmtpReaderGetState(reader);
    // Check: state is "waiting for handshake"
    CuAssertIntEquals(tc, ZMTP_STATE_WAIT_HANDSHAKE, state);

    uint8_t handshake[] =
    {
    // 04 1A - command, length 0x2C = 42
0x04, 0x2c,
    // 05 52 45 41 44 59 - command "READY"
0x05, 0x52, 0x45, 0x41,
0x44, 0x59,
    // 0B 53 6F 63 6B 65 74 2D 54 79 70 65 - property "Socket-Type"
0x0b, 0x53, 0x6f, 0x63, 0x6b, 0x65,
0x74, 0x2d, 0x54, 0x79, 0x70, 0x65,
    // 00 00 00 04 - property value length - 6
0x00, 0x00,
0x00, 0x06,
    // 44 45 41 4C 45 52 - property value "DEALER"
0x44, 0x45, 0x41, 0x4c, 0x45, 0x52,
    // 08 49 64 65 6E 74 69 74 79 - property "Identity"
0x08, 0x49, 0x64, 0x65, 0x6E, 0x74, 0x69, 0x74, 0x79,
    // 00 00 00 03 - property value length - 3
0x00, 0x00, 0x00, 0x03,
    // 41 42 43 - property value "ABC"
0x41, 0x42, 0x43
    };

    ZmtpReaderPush(reader, handshake, sizeof(handshake));

    state = ZmtpReaderGetState(reader);
    CuAssertIntEquals(tc, ZMTP_STATE_WAIT_PACKET, state);

    uint8_t data[] =
    {
        // Data packet:
        //   00 - message-last with short-size
        //   01 - short-size 1
        //   32 - message data '2'
0x00, 0x01, 0x32
    };

    ZmtpReaderPush(reader, data, sizeof(data));
    state = ZmtpReaderGetState(reader);
    CuAssertIntEquals(tc, ZMTP_STATE_WAIT_PACKET, state);

    // Now test sending an arbitrary command.
    uint8_t command[] =
    {
        // 04 - command, 09 - size=9
0x04, 0x09,
        // 05 - size=5, "Hello"
0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
        // "XYZ"
0x58, 0x59, 0x5a
    };
    
    ZmtpReaderPush(reader, command, sizeof(command));

    ZmtpReaderDestroy(&reader);
    CuAssertPtrEquals(tc, NULL, reader);
}

void TestParseKeysAndValues(CuTest *tc)
{
    uint8_t properties[] =
    {
    // 0B 53 6F 63 6B 65 74 2D 54 79 70 65 - property "Socket-Type"
0x0b, 0x53, 0x6f, 0x63, 0x6b, 0x65,
0x74, 0x2d, 0x54, 0x79, 0x70, 0x65,
    // 00 00 00 04 - property value length - 6
0x00, 0x00,
0x00, 0x06,
    // 44 45 41 4C 45 52 - property value "DEALER"
0x44, 0x45, 0x41, 0x4c, 0x45, 0x52,
    // 08 49 64 65 6E 74 69 74 79 - property "Identity"
0x08, 0x49, 0x64, 0x65, 0x6E, 0x74, 0x69, 0x74, 0x79,
    // 00 00 00 03 - property value length - 3
0x00, 0x00, 0x00, 0x03,
    // 41 42 43 - property value "ABC"
0x41, 0x42, 0x43
    };
    int res;
    uint8_t *key_start;   // will point to the beginning of the key
    size_t  key_len;     // will get the length of the key
    uint8_t *value_start; // will point to the beginning of the value
    size_t  value_len;   // will get the length of the value
    uint8_t *after;       // will point to the first byte after the value
    size_t  after_len;    // will get the length of the buffer after the value

    // Test reading a key.
    res = ZmtpReaderGetKey(properties, sizeof(properties),
        &key_start, &key_len, &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, properties + 1, key_start);
    CuAssertIntEquals(tc, 11, key_len);
    CuAssertPtrEquals(tc, &properties[12], after);
    CuAssertIntEquals(tc, sizeof(properties) - 12, after_len);

    // Test reading a value.
    res = ZmtpReaderGetValue(after, after_len,
        &value_start, &value_len, &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, properties + 16, value_start);
    CuAssertIntEquals(tc, 6, value_len);
    CuAssertPtrEquals(tc, &properties[22], after);
    CuAssertIntEquals(tc, sizeof(properties) - 22, after_len);

    // Test reading a value at the end of a buffer.
    res = ZmtpReaderGetValue(&properties[31], 7,
        &value_start, &value_len, &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, properties + 35, value_start);
    CuAssertIntEquals(tc, 3, value_len);
    CuAssertPtrEquals(tc, NULL, after);
    CuAssertIntEquals(tc, 0, after_len);

    // Reading a key that is at the end of a buffer
    // (after has to be set to NULL)
    uint8_t key_buffer[] =
    {
    // 08 49 64 65 6E 74 69 74 79 - property "Identity"
0x08, 0x49, 0x64, 0x65, 0x6E, 0x74, 0x69, 0x74, 0x7
    };
    res = ZmtpReaderGetKey(key_buffer, sizeof(key_buffer),
        &key_start, &key_len, &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, key_buffer + 1, key_start);
    CuAssertIntEquals(tc, 8, key_len);
    CuAssertPtrEquals(tc, NULL, after);
    CuAssertIntEquals(tc, 0, after_len);

    uint8_t key_empty[] =
    {
// Empty key
0x00,
// Empty key at the end of buffer
0x00
    };
    // Reading an empty key that is not at the end of buffer
    res = ZmtpReaderGetKey(key_empty, sizeof(key_empty),
        &key_start, &key_len, &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, key_empty + 1, key_start);
    CuAssertIntEquals(tc, 0, key_len);
    CuAssertPtrEquals(tc, key_empty + 1, after);
    CuAssertIntEquals(tc, 1, after_len);

    // Reading an empty key that is at the end of buffer
    res = ZmtpReaderGetKey(key_empty + 1, 1,
        &key_start, &key_len, &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, key_empty + 2, key_start);
    CuAssertIntEquals(tc, 0, key_len);
    CuAssertPtrEquals(tc, NULL, after);
    CuAssertIntEquals(tc, 0, after_len);

    uint8_t value_empty[] =
    {
// Empty value
0x00, 0x00, 0x00, 0x00,
// Empty value at the end of buffer
0x00, 0x00, 0x00, 0x00
    };

    // Reading an empty value that is not at the end of buffer
    res = ZmtpReaderGetValue(value_empty, 8,
        &value_start, &value_len, &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, value_empty + 4, value_start);
    CuAssertIntEquals(tc, 0, value_len);
    CuAssertPtrEquals(tc, value_empty + 4, after);
    CuAssertIntEquals(tc, 4, after_len);

    // Reading an empty value this at the end of buffer
    res = ZmtpReaderGetValue(value_empty + 4, 4,
        &value_start, &value_len, &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, value_empty + 8, value_start);
    CuAssertIntEquals(tc, 0, value_len);
    CuAssertPtrEquals(tc, NULL, after);
    CuAssertIntEquals(tc, 0, after_len);

    uint8_t properties2[] =
    {
    // 0B 53 6F 63 6B 65 74 2D 54 79 70 65 - property "Socket-Type"
0x0b, 0x53, 0x6f, 0x63, 0x6b, 0x65,
0x74, 0x2d, 0x54, 0x79, 0x70, 0x65,
    // 00 00 00 04 - property value length - 6
0x00, 0x00,
0x00, 0x06,
    // 44 45 41 4C 45 52 - property value "DEALER"
0x44, 0x45, 0x41, 0x4c, 0x45, 0x52,
    // 08 49 64 65 6E 74 69 74 79 - property "Identity"
0x08, 0x49, 0x64, 0x65, 0x6E, 0x74, 0x69, 0x74, 0x79,
    // 00 00 00 03 - property value length - 0
0x00, 0x00, 0x00, 0x00
    };

    // Reading a key-value pair
    res = ZmtpReaderGetKeyAndValue(properties2, sizeof(properties2),
        &key_start, &key_len,
        &value_start, &value_len,
        &after, &after_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, properties2 + 1, key_start);
    CuAssertIntEquals(tc, 11, key_len);
    CuAssertPtrEquals(tc, properties2 + 16, value_start);
    CuAssertIntEquals(tc, 6, value_len);
    CuAssertPtrEquals(tc, properties2 + 22, after);
    CuAssertIntEquals(tc, sizeof(properties2) - 22, after_len);

    // Reading the second key-value pair, where the value is empty
    uint8_t *after2;
    size_t after_len2;
    res = ZmtpReaderGetKeyAndValue(after, after_len,
        &key_start, &key_len,
        &value_start, &value_len,
        &after2, &after_len2);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, after + 1, key_start);
    CuAssertIntEquals(tc, 8, key_len);
    CuAssertPtrEquals(tc, after + 13, value_start);
    CuAssertIntEquals(tc, 0, value_len);
    CuAssertPtrEquals(tc, NULL, after2);
    CuAssertIntEquals(tc, 0, after_len2);
}

void TestDisplayBinary(CuTest *tc)
{
    uint8_t data[] = { 0x05, 0x52, 0x45, 0x41, 0x44, 0x59 };
    char *ascii, *binary;
    ZmtpReaderGenerateBinaryOutput(data, sizeof(data), &ascii, &binary);
    CuAssertStrEquals(tc, ".READY", ascii);
    CuAssertStrEquals(tc, "05 52 45 41 44 59", binary);
    free(ascii);
    free(binary);
}

CuSuite* CuGetSuite_zmtp(void)
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, TestZmtp);
    SUITE_ADD_TEST(suite, TestParseKeysAndValues);
    SUITE_ADD_TEST(suite, TestDisplayBinary);

    return suite;
}
