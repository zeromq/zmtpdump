#include "CuTest.h"
#include "buffer.h"
#include <string.h>

void TestCreateBuffer(CuTest* tc)
{
    buffer_t *buf = BufferCreate();
    CuAssertTrue(tc, buf != NULL);
    CuAssertIntEquals(tc, 0, BufferGetSize(buf));

    BufferDestroy(&buf);
    CuAssertPtrEquals(tc, 0, buf);
}

void TestAppend(CuTest* tc)
{
    buffer_t *buf = BufferCreate();
    uint8_t data[2] = { 1, 2 };
    BufferAppend(buf, data, sizeof(data));
    CuAssertIntEquals(tc, 2, BufferGetSize(buf));
    CuAssertIntEquals(tc, 1, BufferGetByte(buf, 0));
    CuAssertIntEquals(tc, 2, BufferGetByte(buf, 1));
    BufferDestroy(&buf);
}

void TestCopyBuffer(CuTest* tc)
{
    buffer_t *buf = BufferCreate();
    uint8_t data[4] = { 1, 2, 3, 4 };
    BufferAppend(buf, data, sizeof(data));
    uint8_t *data_out;
    size_t size_out;
    BufferCopy(buf, 2, &data_out, &size_out);
    CuAssertIntEquals(tc, 2, size_out);
    CuAssertIntEquals(tc, 0, memcmp(data, data_out, 2));
    free(data_out);
    BufferDestroy(&buf);
}

void TestExtractBuffer(CuTest* tc)
{
    buffer_t *buf = BufferCreate();
    uint8_t data[4] = { 1, 2, 3, 4 };
    BufferAppend(buf, data, sizeof(data));
    uint8_t *data_out;
    size_t size_out;
    BufferExtract(buf, 2, &data_out, &size_out);
    CuAssertIntEquals(tc, 2, size_out);
    CuAssertIntEquals(tc, 0, memcmp(data, data_out, 2));
    free(data_out);
    CuAssertIntEquals(tc, 2, BufferGetSize(buf));
    CuAssertIntEquals(tc, 3, BufferGetByte(buf, 0));
    CuAssertIntEquals(tc, 4, BufferGetByte(buf, 1));
    BufferDestroy(&buf);
}

void TestGetBlock(CuTest* tc)
{
    buffer_t *buf = BufferCreate();
    uint8_t data1[4] = { 1, 2, 3, 4 };
    BufferAppend(buf, data1, sizeof(data1));
    uint8_t *block;

    // Test case when not enough data in the buffer.
    CuAssertIntEquals(tc, 0, BufferGetBlock(buf, &block, 0, 8));

    // Add more data to the buffer.
    uint8_t data2[4] = { 5, 6, 7, 8 };
    BufferAppend(buf, data2, sizeof(data2));

    // Test case when enough data in the buffer.
    CuAssertIntEquals(tc, 1, BufferGetBlock(buf, &block, 0, 8));
    uint8_t check_data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    CuAssertIntEquals(tc, 0, memcmp(block, check_data, 8));
    BufferDestroy(&buf);
}

void TestAccessBufferData(CuTest* tc)
{
    buffer_t *buf = BufferCreate();
    uint8_t data1[4] = { 1, 2, 3, 4 };
    BufferAppend(buf, data1, sizeof(data1));
    uint8_t *buffer_data;
    size_t buffer_size;
    BufferGetData(buf, &buffer_data, &buffer_size);
    CuAssertTrue(tc, buffer_data != NULL);
    CuAssertIntEquals(tc, 4, buffer_size);

    BufferDestroy(&buf);
}

CuSuite* CuGetSuite_buffer(void)
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, TestCreateBuffer);
    SUITE_ADD_TEST(suite, TestAppend);
    SUITE_ADD_TEST(suite, TestCopyBuffer);
    SUITE_ADD_TEST(suite, TestExtractBuffer);
    SUITE_ADD_TEST(suite, TestGetBlock);
    SUITE_ADD_TEST(suite, TestAccessBufferData);

    return suite;
}
