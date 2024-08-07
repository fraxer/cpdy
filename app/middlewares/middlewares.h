#ifndef __MIDDLEWARES__
#define __MIDDLEWARES__

#include "httpcontext.h"
#include "wscontext.h"
#include "middleware.h"

int middleware_http_forbidden(httpctx_t* ctx);
int middleware_query_param_required(httpctx_t* ctx, char** keys, int size);

#endif