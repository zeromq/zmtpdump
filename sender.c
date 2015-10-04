#include <czmq.h>

int
main()
{
    
    zsock_t *send = zsock_new_push(">tcp://localhost:7001");
    assert(send != NULL);
    int i = 0;
    while (1) {
        char buff[32];
        i++;
        sprintf(buff, "%d", i);
        int res = zstr_send(send, buff);
        if (res < 0)
            break;
        res = sleep(2);
        if (res > 0)
            break;
    }
    zsock_destroy(&send);
}
