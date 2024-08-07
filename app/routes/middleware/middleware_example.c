#include <string.h>

#include "http1.h"
#include "middlewares.h"

void example(httpctx_t* ctx) {
    middleware(
        middleware_http_query_param_required(ctx, args_str("a", "abc"))
    )

    // or

    if (!middleware_http_query_param_required(ctx, args_str("a", "abc"))) return;

    ctx->response->data(ctx->response, "done");
}
