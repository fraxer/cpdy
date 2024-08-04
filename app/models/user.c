#include <stdlib.h>
#include <string.h>

#include "user.h"

user_t* user_create_anonymous(void) {
    return NULL;
}

user_t* user_model_get_by_username(const char* dbinstance, const char* username)
{
    (void)dbinstance;

    user_t* user = malloc(sizeof * user);
    if (user == NULL) return NULL;

    user->id = 1;
    user->username = strdup(username);
    user->password_hash = strdup("password123");

    return user;
}

user_t* user_model_get_by_token(const char* dbinstance, const char* token) {
    return 0;
}
