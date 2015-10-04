#include <stdio.h>

#include "CuTest.h"

CuSuite* CuGetSuite_zmtp();
CuSuite* CuGetSuite_buffer();
CuSuite* CuGetSuite_tcp();
CuSuite* CuGetSuite_zhash();

void RunAllTests(void)
{
    CuString *output = CuStringNew();
    CuSuite* suite = CuSuiteNew();

    CuSuiteAddSuite(suite, CuGetSuite_buffer());
    CuSuiteAddSuite(suite, CuGetSuite_tcp());
    CuSuiteAddSuite(suite, CuGetSuite_zmtp());
    CuSuiteAddSuite(suite, CuGetSuite_zhash());

    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);
}

int main(void)
{
	RunAllTests();
	return 0;
}
