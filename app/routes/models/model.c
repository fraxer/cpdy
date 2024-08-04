#include <string.h>
#include <elf.h>

#include "http1.h"
#include "db.h"
#include "auth.h"
#include "middleware.h"

int mw(httpctx_t* ctx) {
    ctx->response->def(ctx->response, 400);

    return 1;
}

int mw2(httpctx_t* ctx) {
    ctx->response->def(ctx->response, 401);

    return 0;
}
int mw3(httpctx_t* ctx) { return 0; }
int mw4(httpctx_t* ctx) { return 0; }
int mw5(httpctx_t* ctx) { return 0; }
int mw6(httpctx_t* ctx) { return 0; }
int mw7(httpctx_t* ctx) { return 0; }

void login(httpctx_t* ctx) {
    middleware(
        mw(ctx),
        mw2(ctx)
    )

    // if (!mw(ctx)) return;

    ctx->response->data(ctx->response, "done");
}

void login4(httpctx_t* ctx) {
    middleware(
        query_param_required(ctx, args_str("a", "s", "d")),
        authenticate_by_token_required(ctx),
        auth_required(ctx)
    )

    middlewarecb(
        authenticate_by_token_required,
        auth_required
    )

    // (void)ctx->user->id;

    // gc_add(ctx->gc, ctx->user->id);
}