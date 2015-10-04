#ifndef _cset_h_INC_
#define _cset_h_INC_

#include <stdint.h>
#include <czmq.h>

// Type of destructor function
typedef void (*cset_fn)(void *value, void *arg);

typedef struct _cset_t
{
    zhash_t *hash;
    void *dtor_fn_arg;
    cset_fn dtor_fn;
} cset_t;

cset_t *CSetCreate();
void CSetDestroy(cset_t **self);

void CSetAdd(cset_t *self, const uint8_t *srcip, const uint8_t *srcport,
    const uint8_t *dstip, const uint8_t *dstport,
    void *value);
void *CSetFind(cset_t *self, const uint8_t *srcip, const uint8_t *srcport,
    const uint8_t *dstip, const uint8_t *dstport);
void CSetRemove(cset_t *self, const uint8_t *srcip, const uint8_t *srcport,
    const uint8_t *dstip, const uint8_t *dstport);

const char *CSetCreateKey(const uint8_t *ip1, const uint8_t *port1,
    const uint8_t *ip2, const uint8_t *port2);

void CSetSetDestructor(cset_t *self, cset_fn dtor_fn, void *arg);

#endif /* !_cset_h_INC_ */
