#ifndef __WSCONTEXT__
#define __WSCONTEXT__

#include "websocketsrequest.h"
#include "websocketsresponse.h"
#include "user.h"

typedef struct wsctx {
    user_t* user;
    struct websocketsrequest* request;
    websocketsresponse_t* response;

    void(*free)(struct wsctx* ctx);
} wsctx_t;

wsctx_t* wsctx_create(void* request, void* response);

#endif