#include <string.h>

#include "auth.h"
#include "middleware.h"

typedef struct middleware_global_fn {
    char name[128];
    int (*fn)(void* ctx);
} middleware_global_fn_t;

static middleware_global_fn_t __middleware_list[] = {
    {"auth_required",                  (int(*)(void*))auth_required},
    {"authenticate_by_token_required", (int(*)(void*))authenticate_by_token_required},
    {"authenticate_by_name_pass",      (int(*)(void*))authenticate_by_name_pass},
};

int run_middlewares(middleware_item_t* middleware_item, void* ctx) {
    // const size_t n = sizeof(__middleware_list) / sizeof(middleware_global_fn_t);

    // for (size_t i = 0; i < n; i++)
    //     if (strcmp(__middleware_list[i].name, middleware_item->value) == 0)
    //         return __middleware_list[i].fn(ctx);

    while (middleware_item != NULL) {
        if (!middleware_item->fn(ctx))
            return 0;

        middleware_item = middleware_item->next;
    }

    return 1;
}

int run_middlewarecb(int count, ...) {
    return count;
}

int authenticate_by_name_pass(httpctx_t* ctx) {
    char* username = ctx->request->payloadf(ctx->request, "key1");
    char* password = ctx->request->payloadf(ctx->request, "key1");

    user_t* user = authenticate("mysql", username, password);
    if (user == NULL) {
        free(username);
        free(password);
        ctx->response->data(ctx->response, "can't authenticate user");
        return 0;
    }

    // ctx->user->swap(ctx->user, user);

    free(username);
    free(password);

    return 1;
}

int query_param_required(httpctx_t* ctx, char** keys, int size) {
    for (int i = 0; i < size; i++) {
        if (ctx->request->payloadf(ctx->request, keys[i]) == NULL) {
            ctx->response->data(ctx->response, "param not found");
            return 0;
        }
    }

    return 0;
}

int auth_required(httpctx_t* ctx) {
    return 0;
}

int authenticate_by_token_required(httpctx_t* ctx) {
    return 0;
}
