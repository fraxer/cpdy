#include "httpcontext.h"

httpctx_t* httpctx_create(void* request, void* response) {
    httpctx_t* ctx = malloc(sizeof * ctx);
    if (ctx == NULL) return NULL;

    ctx->request = request;
    ctx->response = response;
    ctx->user = NULL;
    ctx->free = httpctx_free;
    // ctx->user = user_create_anonymous();
    // if (ctx->user == NULL) {
    //     free(ctx);
    //     return NULL;
    // }

    return ctx;
}

void httpctx_free(httpctx_t* ctx) {
    if (ctx == NULL) return;

    if (ctx->user != NULL)
        ctx->user->free(ctx->user);

    free(ctx);
}
