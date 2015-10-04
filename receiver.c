#include <czmq.h>

int
main()
{
    zsock_t *receiver = zsock_new_pull("@tcp://*:7001");
    assert(receiver != NULL);
    while (1) {
        char *msg = zstr_recv(receiver);
        if (msg == NULL)
            break;
        printf("Received: %s\n", msg);
        free(msg);
    }
    zsock_destroy(&receiver);
}
