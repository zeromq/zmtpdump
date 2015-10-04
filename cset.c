#include "cset.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void *dtor_fn_arg = NULL;
static cset_fn g_dtor_fn = NULL;
static void _cset_free_fn(void *data)
{
    if (g_dtor_fn != NULL)
        g_dtor_fn(data, dtor_fn_arg);
}

cset_t *CSetCreate()
{
    cset_t *cset;

    cset = (cset_t *) malloc(sizeof(cset_t));
    assert(cset);
    memset(cset, 0, sizeof(cset_t));
    cset->hash = zhash_new();
    assert(cset->hash);
    return cset;
}

void CSetDestroy(cset_t **self)
{
    cset_t *cset;

    assert(self);
    cset = (cset_t *) *self;
    if (cset != NULL) {
        // Set destructor function and special destructor argument
        // before calling zhash_destroy.
        g_dtor_fn = cset->dtor_fn;
        dtor_fn_arg = cset->dtor_fn_arg;
        zhash_destroy(&cset->hash);
        free(cset);
    }
    *self = NULL;
}

const char *CSetCreateKey(const uint8_t *ip1, const uint8_t *port1,
    const uint8_t *ip2, const uint8_t *port2)
{
    static char buffer[60];
    assert(ip1);
    assert(port1);
    assert(ip2);
    assert(port2);
    sprintf(buffer, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        ip1[0], ip1[1], ip1[2], ip1[3],
        port1[0], port1[1],
        ip2[0], ip2[1], ip2[2], ip2[3],
        port2[0], port2[1]);
    return buffer;
}

void CSetAdd(cset_t *self, const uint8_t *srcip, const uint8_t *srcport,
    const uint8_t *dstip, const uint8_t *dstport,
    void *value)
{
    assert(self);
    assert(srcip);
    assert(srcport);
    assert(dstip);
    assert(dstport);
    const char *key = CSetCreateKey(srcip, srcport, dstip, dstport);
    zhash_insert(self->hash, key, value);
    zhash_freefn (self->hash, key, _cset_free_fn);
}

void *CSetFind(cset_t *self, const uint8_t *srcip, const uint8_t *srcport,
    const uint8_t *dstip, const uint8_t *dstport)
{
    assert(self);
    assert(srcip);
    assert(srcport);
    assert(dstip);
    assert(dstport);
    const char *key = CSetCreateKey(srcip, srcport, dstip, dstport);
    void *value = zhash_lookup(self->hash, key);
    return value;
}

void CSetRemove(cset_t *self, const uint8_t *srcip, const uint8_t *srcport,
    const uint8_t *dstip, const uint8_t *dstport)
{
    assert(self);
    assert(srcip);
    assert(srcport);
    assert(dstip);
    assert(dstport);
    const char *key = CSetCreateKey(srcip, srcport, dstip, dstport);

    // Set destructor function and special destructor argument before
    // calling zhash_delete.
    g_dtor_fn = self->dtor_fn;
    dtor_fn_arg = self->dtor_fn_arg;

    void *value = zhash_lookup(self->hash, key);
    if (value != NULL) {
        zhash_delete(self->hash, key);
    }
}

void CSetSetDestructor(cset_t *self, cset_fn dtor_fn, void *arg)
{
    assert(self);
    assert(dtor_fn);
    self->dtor_fn = dtor_fn;
    self->dtor_fn_arg = arg;
}
