#include <string.h>

#include "auth.h"

int middleware_http_forbidden(httpctx_t* ctx) {
    ctx->response->def(ctx->response, 403);

    return 0;
}

// int authenticate_by_name_pass(httpctx_t *ctx) {
//     char* username = ctx->request->payloadf(ctx->request, "key1");
//     char* password = ctx->request->payloadf(ctx->request, "key1");

//     user_t* user = authenticate("mysql", username, password);
//     if (user == NULL) {
//         free(username);
//         free(password);
//         ctx->response->data(ctx->response, "can't authenticate user");
//         return 0;
//     }

//     // ctx->user->swap(ctx->user, user);

//     free(username);
//     free(password);

//     return 1;
// }

int middleware_query_param_required(httpctx_t* ctx, char** keys, int size) {
    char message[256] = {0};
    for (int i = 0; i < size; i++) {
        const char* param = ctx->request->query(ctx->request, keys[i]);
        if (param == NULL || param[0] == 0) {
            sprintf(message, "param <%s> not found", keys[i]);
            ctx->response->data(ctx->response, message);
            return 0;
        }
    }

    return 1;
}
