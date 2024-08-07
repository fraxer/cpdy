#include <string.h>

#include "http1.h"
#include "db.h"
#include "auth.h"
#include "middlewares.h"

int mw(httpctx_t* ctx) {
    ctx->response->def(ctx->response, 400);

    return 1;
}

int mw2(httpctx_t* ctx) {
    ctx->response->def(ctx->response, 401);

    return 1;
}

void login(httpctx_t* ctx) {
    middleware(
        middleware_query_param_required(ctx, args_str("a", "abc"))
    )

    // if (!mw(ctx)) return;

    ctx->response->data(ctx->response, "done");
}

void login4(httpctx_t* ctx) {
    middleware(
        middleware_query_param_required(ctx, args_str("a", "s", "d"))
    )

    (void)ctx->user->id;
}