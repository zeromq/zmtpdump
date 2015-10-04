#include "CuTest.h"
#include "cset.h"

void TestCreateKey(CuTest *tc)
{
    uint8_t port1[2] = { 0xab, 0xcd };
    uint8_t port2[2] = { 0x01, 0x02 };
    uint8_t ip1[4] = { 0x1a, 0x2a, 0x3a, 0x4a };
    uint8_t ip2[4] = { 0x1b, 0x2b, 0x3b, 0x4b };

    const char *key = CSetCreateKey(ip1, port1, ip2, port2);
    CuAssertTrue(tc, key != NULL);
    CuAssertStrEquals(tc, "1a2a3a4aabcd1b2b3b4b0102", key);
}

void TestZhash(CuTest *tc)
{
    cset_t *cset;

    cset = CSetCreate();
    CuAssertTrue(tc, cset != NULL);

    int x, y;
    uint8_t port1[2] = { 0xab, 0xcd };
    uint8_t port2[2] = { 0x01, 0x02 };
    uint8_t ip1[4] = { 74, 125, 226, 128 };
    uint8_t ip2[4] = { 50, 63, 202, 62 };

    CSetAdd(cset, ip1, port1, ip2, port2, &x);
    CSetAdd(cset, ip2, port2, ip1, port1, &y);
    void *value = CSetFind(cset, ip1, port1, ip2, port2);
    CuAssertTrue(tc, value != NULL);
    CuAssertPtrEquals(tc, &x, value);
    value = CSetFind(cset, ip2, port2, ip1, port1);
    CuAssertTrue(tc, value != NULL);
    CuAssertPtrEquals(tc, &y, value);

    // Retrieving non-existent mapping
    value = CSetFind(cset, ip1, port2, ip2, port1);
    CuAssertPtrEquals(tc, NULL, value);

    // Removing a mapping
    CSetRemove(cset, ip1, port1, ip2, port2);

    // Trying to retrieve the removed mapping
    value = CSetFind(cset, ip1, port1, ip2, port2);
    CuAssertPtrEquals(tc, NULL, value);

    // Retrieving the mapping that was not removed
    value = CSetFind(cset, ip2, port2, ip1, port1);
    CuAssertTrue(tc, value != NULL);
    CuAssertPtrEquals(tc, &y, value);

    CSetDestroy(&cset);
    CuAssertPtrEquals(tc, NULL, cset);
}

// Destructor function called for every value in a set
void _Destroy(void *value, void *arg)
{
    int *count = (int *) arg;
    int *n = (int *) value;
    assert(count);
    (*count)++;
    printf("_Destroy: n = %d count = %d\n", *n, *count);
    free(value);
}

void TestZhashDestructor(CuTest *tc)
{
    cset_t *cset;

    cset = CSetCreate();
    CuAssertTrue(tc, cset != NULL);

    int count = 0;
    CSetSetDestructor(cset, _Destroy, &count);

    int *x = (int *) malloc(sizeof(int));
    *x = 33;
    uint8_t port1[2] = { 0xab, 0xcd };
    uint8_t port2[2] = { 0x01, 0x02 };
    uint8_t ip1[4] = { 74, 125, 226, 128 };
    uint8_t ip2[4] = { 50, 63, 202, 62 };

    CSetAdd(cset, ip1, port1, ip2, port2, x);

    int *y = (int *) malloc(sizeof(int));
    *y = 44;
    CSetAdd(cset, ip2, port2, ip1, port1, y);
    CSetRemove(cset, ip2, port2, ip1, port1);

    CSetDestroy(&cset);
    CuAssertIntEquals(tc, 2, count);
}

CuSuite* CuGetSuite_zhash(void)
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, TestCreateKey);
    SUITE_ADD_TEST(suite, TestZhash);
    SUITE_ADD_TEST(suite, TestZhashDestructor);

    return suite;

}

