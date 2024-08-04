#ifndef __MODELSUSER__
#define __MODELSUSER__

typedef struct user {
    int id;
    char* username;
    char* password_hash;

    void(*free)(struct user* user);
} user_t;

user_t* user_create_anonymous(void);
user_t* user_model_get_by_username(const char* dbinstance, const char* username);
user_t* user_model_get_by_token(const char* dbinstance, const char* token);

#endif