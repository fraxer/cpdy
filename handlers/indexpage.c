#include <openssl/sha.h>
#include <string.h>
#include "../src/base64/base64.h"
#include "../src/request/http1request.h"
#include "../src/response/http1response.h"
#include "../src/request/websocketsrequest.h"
#include "../src/response/websocketsresponse.h"
#include "../src/database/dbquery.h"
#include "../src/database/dbresult.h"
    #include <stdio.h>

void payload(http1request_t* request, http1response_t* response) {
    char* payload = request->payload(request);

    if (!payload) {
        response->data(response, "payload not found");
        return;
    }

    response->data(response, payload);
    free(payload);
}

void payloadf(http1request_t* request, http1response_t* response) {
    char* payload = request->payloadf(request, "asd");

    if (!payload) {
        response->data(response, "field not found");
        return;
    }

    response->data(response, payload);
    free(payload);
}

void payload_urlencoded(http1request_t* request, http1response_t* response) {
    char* payload = request->payload_urlencoded(request, "asd");

    if (!payload) {
        response->data(response, "field not found");
        return;
    }

    response->data(response, payload);
    free(payload);
}

void payload_file(http1request_t* request, http1response_t* response) {
    http1_payloadfile_t payloadfile = request->payload_file(request);

    if (!payloadfile.ok) {
        response->data(response, "file not found");
        return;
    }

    char* data = payloadfile.read(&payloadfile);

    response->data(response, data);

    free(data);
}

void payload_filef(http1request_t* request, http1response_t* response) {
    http1_payloadfile_t payloadfile = request->payload_filef(request, "asd");

    if (!payloadfile.ok) {
        response->data(response, "file not found");
        return;
    }

    char* data = payloadfile.read(&payloadfile);

    response->data(response, data);

    free(data);
}

void payload_(http1request_t* request, http1response_t* response) {
    char* payload = request->payloadf(request, "asd");

    if (!payload) {
        response->data(response, "field not found");
    }
    else {
        response->data(response, payload);
        free(payload);
    }

    // char* payload = request->payloadf(request, "field"); // from multipart

    // char* payload = request->payload_urlencoded(request, "field");

    // http1_pldfile* file = request->payload_file(request);
    // http1_pldfile* file = request->payload_filef(request, "field"); // from multipart

    // file->save(file, "/path/to/dir", file->name);
    // file_save(file, "/path/to/dir", file->name);
    //  |
    // \|/
    // int fd = open(file_name(file), O_CREAT | O_TRUNC);
    // write(fd, file_body(file), file_size(file));
    // close(fd);

    // -------------------

    // jsmntok_t* token = NULL;
    // if (!jsmn_parse("{}", &token)) {
    //     response->data(response, "json error");
    //     return;
    // }

    // {
    //     "a": 1,
    //     "b": true,
    //     "c": [
    //         0,
    //         { "a": null },
    //         [0, true],
    //         true
    //     ]
    // }

    // jsmntok_t* token_key1_value = jsmn_object_value(token, "key1");
    // jsmntok_t* token_key1 = jsmn_object_key(token, "key1");


    // jsmnit_t obit = {
    //     .type = OBJ | ARR,
    //     .end = 0,
    //     .key = token,
    //     .value = NULL
    // };
    // jsmnit_t it = jsmn_init_it(token);

    // do {
        // jsmntok_t* token_value = it.key;
        // jsmntok_t* token_value = it.value;
    // } while (it = jsmn_next_it(it));

    // for (jsmnit_t it = jsmn_init_it(token); !it.end; it = jsmn_next_it(it)) {}


    // jsmntok_t* token_index0_value = jsmn_array_value(token, 0);

    // for (int i = 0; i < jsmn_array_size(token); i++) {
    //     jsmntok_t* token_value = jsmn_array_value(token, i);
    // }


    // jsmn_bool(token_value);
    // jsmn_null(token_value);
    // jsmn_string(token_value);
    // jsmn_number(token_value);
    // jsmn_int(token_value);
    // jsmn_uint(token_value);
    // jsmn_double(token_value);
    // jsmn_udouble(token_value);

    // if (jsmn_is_bool(token_value)) {}
    // if (jsmn_is_null(token_value)) {}
    // if (jsmn_is_string(token_value)) {}
    // if (jsmn_is_number(token_value)) {}
    // if (jsmn_is_int(token_value)) {}
    // if (jsmn_is_uint(token_value)) {}
    // if (jsmn_is_double(token_value)) {}
    // if (jsmn_is_udouble(token_value)) {}
    // if (jsmn_is_object(token_value)) {}
    // if (jsmn_is_array(token_value)) {}

    // jsmn_free(token);

    // jsmntok_t* json = request->payload_json(request);
    // jsmntok_t* json = request->payload_jsonf(request, "field"); // from multipart

    // jsmntok_t* token_array = jsmn_create_array();
    // jsmntok_t* token_object = jsmn_create_object();
    // jsmntok_t* token_bool = jsmn_create_bool(1);
    // jsmntok_t* token_null = jsmn_create_null();
    // jsmntok_t* token_string = jsmn_create_string("");
    // jsmntok_t* token_int = jsmn_create_int(123);
    // jsmntok_t* token_double = jsmn_create_double(123.5);

    // int jsmn_array_prepend(token_array, token_bool);
    // int jsmn_array_append(token_array, token_null);
    // int jsmn_array_append(token_array, token_string);
    // int jsmn_array_append_to(token_array, 1, token_string);
    // int jsmn_array_slice(token_array, 1, 5);
    // int jsmn_array_clear(token_array);

    // int jsmn_object_set(token_object, "key", token_array);
    // int jsmn_object_remove(token_object, "key");
    // int jsmn_object_clear(token_object);

    // char* jsmn_stringify(token_object);

    // void jsmn_free(token_object);

    // -------------------

    // jsmn_parser_t parser;
    // if (jsmn_init(&parser, payload) == -1) {
    //     return;
    // }

    // if (jsmn_parse(&parser) < 0) {
    //     return;
    // }

    // jsmntok_t* token = jsmn_get_root_token(&parser);

    // jsmntok_t* payload = request->payload_json(request, &parser);
    // jsmntok_t* json = request->payload_jsonf(request, "field", &parser); // from multipart

    // jsmn_free(&parser);

    // if (payload) free(payload);
}

void cookie(http1request_t* request, http1response_t* response) {
    const char* cookie = request->cookie(request, "test");

    if (!cookie) {
        response->data(response, "cookie not found");
        return;
    }

    response->data(response, cookie);
}

void view(http1request_t* request, http1response_t* response) {
    (void)request;

    const char* data = 
    "Response"
    "123 Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст ОченьОчень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень длинный текст Очень 567"
    ;

    response->header_add(response, "Transfer-Encoding", "chunked");
    response->header_add(response, "Content-Encoding", "gzip");

    size_t length = strlen(data);

    // response->header_add(response, "key", "value");
    // response->headern_add(response, "key", 3, "value", 5);

    // response->header_remove(response, "key");
    // response->headern_remove(response, "key", 3);

    response->datan(response, data, length);

    // response->file(response, "/darek-zabrocki-mg-tree-town1-003-final-darekzabrocki.jpg"); // path
}

void user(http1request_t* request, http1response_t* response) {
    (void)request;
    response->data(response, "Response");
}

void websocket(http1request_t* request, http1response_t* response) {
    /*

    let socket = new WebSocket("wss://dtrack.tech:4443/wss");

    socket.onopen = (event) => {
      socket.send("Here's some text that the server is urgently awaiting!");
    };

    */

    const http1_header_t* connection  = request->headern(request, "Connection", 10);
    const http1_header_t* upgrade     = request->headern(request, "Upgrade", 7);
    const http1_header_t* ws_version  = request->headern(request, "Sec-WebSocket-Version", 21);
    const http1_header_t* ws_key      = request->headern(request, "Sec-WebSocket-Key", 17);
    const http1_header_t* ws_protocol = request->headern(request, "Sec-WebSocket-Protocol", 22);

    if (connection == NULL || upgrade == NULL || ws_version == NULL || ws_key == NULL) {
        response->data(response, "error connect to web socket");
        return;
    }

    const char* magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    size_t magic_string_length = strlen(magic_string);

    size_t key_length = ws_key->value_length + magic_string_length;
    size_t pos = 0;
    char key[key_length + 1];

    memcpy(&key[pos], ws_key->value, ws_key->value_length); pos += ws_key->value_length;
    memcpy(&key[pos], magic_string, magic_string_length); pos += magic_string_length;

    key[key_length] = 0;

    unsigned char result[40];

    SHA1((const unsigned char*)key, strlen(key), result);

    char pool[41];

    for (int i = 0; i < 20; i++) {
        sprintf(&pool[i*2], "%02x", (unsigned int)result[i]);
    }

    char bs[base64_encode_inline_len(20)];

    int retlen = base64_encode_inline(bs, (const char*)result, 20);

    retlen--; // without \0

    response->headern_add(response, "Upgrade", 7, "websocket", 9);
    response->headern_add(response, "Connection", 10, "Upgrade", 7);
    response->headern_add(response, "Sec-WebSocket-Accept", 20, bs, retlen);

    if (ws_protocol != NULL) {
        response->headern_add(response, "Sec-WebSocket-Protocol", 22, ws_protocol->value, ws_protocol->value_length);
    }

    response->status_code = 101;
    response->connection->keepalive_enabled = 1;
    response->switch_to_websockets(response);
}

void ws_index(websocketsrequest_t* request, websocketsresponse_t* response) {
    // printf("run view handler\n");

    char* data = "";

    if (request->payload) {
        data = request->payload;
    }

    size_t length = strlen(data);

    // printf("%ld %s\n", length, data);

    response->textn(response, data, length);

    // response->textn(response, data, length);

    // response->file(response, "/darek-zabrocki-mg-tree-town1-003-final-darekzabrocki.jpg"); // path
}

void db_pg(http1request_t* request, http1response_t* response) {
    dbinstance_t dbinst = dbinstance(request->database_list(request), "postgresql");

    if (!dbinst.ok) {
        response->data(response, "db not found");
        return;
    }

    dbresult_t result = dbquery(&dbinst, "SET ROLE slave_select; select * from \"user\" limit 3; select * from \"room\" limit 4;");

    if (!dbresult_ok(&result)) {
        response->data(response, dbresult_error_message(&result));
        dbresult_free(&result);
        return;
    }

    // do {
    //     while (dbresult_row_next(&result)) {
    //         const db_table_cell_t* field = dbresult_field(&result, "email");

    //         printf("%s\n", field->value);

    //         while (dbresult_col_next(&result)) {
    //             const db_table_cell_t* field = dbresult_field(&result, NULL);
    //         }
    //     }
    // } while (dbresult_query_next(&result));

    // dbresult_query_rows(&result);
    // dbresult_query_cols(&result);

    // for (int row = 0; row < dbresult_query_rows(&result); row++) {
    //     int col = 0;
    //     const db_table_cell_t* field = dbresult_cell(&result, row, col);
    // }

    // dbresult_query_first(&result); // reset data on start position
    // dbresult_row_first(&result);
    // dbresult_col_first(&result);

    char* str = malloc(10240);

    // for (int col = 0; col < dbresult_query_cols(&result); col++) {
    //     strcat(str, result.query->fields[col]->value);
    //     strcat(str, " | ");
    // }

    // dbresult_query_next(&result);

    // for (int col = 0; col < dbresult_query_cols(&result); col++) {
    //     strcat(str, result.query->fields[col]->value);
    //     strcat(str, " | ");
    // }

    // dbresult_query_first(&result);

    // const db_table_cell_t* field = dbresult_field(&result, "email");
    const db_table_cell_t* field = dbresult_cell(&result, 0, 1);

    // for (int row = 0; row < dbresult_query_rows(&result); row++) {
    //     for (int col = 0; col < dbresult_query_cols(&result); col++) {
    //         printf("%d %p\n", row * result.current->cols + col, result.query->table[row * result.current->cols + col]);
    //     }
    // }

    if (field)
        strcpy(str, field->value);

    dbresult_query_next(&result);

    field = dbresult_cell(&result, 2, 6);

    if (field) {
        strcat(str, " | ");
        strcat(str, field->value);
    }

    field = dbresult_cell(&result, 0, 10);

    if (field) {
        strcat(str, " | ");
        strcat(str, field->value);
    }

    field = dbresult_cell(&result, 2, 11);

    if (field) {
        strcat(str, " | ");
        strcat(str, field->value);
    }

    field = dbresult_cell(&result, 1, 12);

    if (field) {
        strcat(str, " | ");
        strcat(str, field->value);
    }

    dbresult_free(&result);

    response->data(response, str);

    free(str);

}

void db_mysql(http1request_t* request, http1response_t* response) {
    dbinstance_t dbinst = dbinstance(request->database_list(request), "mysql");

    if (!dbinst.ok) {
        response->data(response, "db not found");
        return;
    }

    dbresult_t result = dbquery(&dbinst, "select * from check_site ;select * from migration;");

    if (!dbresult_ok(&result)) {
        response->data(response, dbresult_error_message(&result));
        dbresult_free(&result);
        return;
    }

    // do {
    //     const db_table_cell_t* field = dbresult_field(&result, "domain");

    //     // printf("%s\n", field->value);
    // }
    // while (dbresult_row_next(&result));

    // dbresult_row_first(&result);
    // dbresult_col_first(&result);

    // // printf("%d\n", dbresult_query_rows(&result));
    // // printf("%d\n", dbresult_query_cols(&result));
    // // printf("\n");

    // dbresult_query_first(&result);

    // do {
    //     for (int col = 0; col < dbresult_query_cols(&result); col++) {
    //         // printf("%s | ", result.current->fields[col]->value);
    //     }
    //     // printf("\n");

    //     for (int row = 0; row < dbresult_query_rows(&result); row++) {
    //         for (int col = 0; col < dbresult_query_cols(&result); col++) {
    //             // printf("%d %d %p\n", row, col, result.current->fields[col]);
    //             const db_table_cell_t* field = dbresult_cell(&result, row, col);

    //             // printf("%s (%p) | ", field->value, field);
    //         }
    //         // printf("\n");
    //     }
    //     // printf("\n");

    //     dbresult_row_first(&result);
    //     dbresult_col_first(&result);
    // } while (dbresult_query_next(&result));

    // dbresult_query_first(&result);
    // dbresult_row_first(&result);
    // dbresult_col_first(&result);


    db_table_cell_t* field = dbresult_field(&result, "domain");


    char* str = (char*)malloc(1024);
    // strcpy(str, "test");
    
    if (field && field->value) {
        strcpy(str, field->value);
    }

    dbresult_query_next(&result);
    dbresult_row_first(&result);
    dbresult_col_first(&result);

    field = dbresult_cell(&result, 2, 0);

    if (field && field->value) {
        strcat(str, " | ");
        strcat(str, field->value);
    }

    response->data(response, str);

    dbresult_free(&result);

    free(str);
}

void db_redis(http1request_t* request, http1response_t* response) {
    dbinstance_t dbinst = dbinstance(request->database_list(request), "redis");

    if (!dbinst.ok) {
        response->data(response, "db not found");
        return;
    }

    // dbresult_t result = dbquery(&dbinst, "SET testkey 7978979");
    dbresult_t result = dbquery(&dbinst, "GET testkey");
    // dbresult_t result = dbquery(&dbinst, "GET key_bool");
    // dbresult_t result = dbquery(&dbinst, "JSON.GET json");
    // dbresult_t result = dbquery(&dbinst, "LRANGE list 0 -1");

    if (!dbresult_ok(&result)) {
        response->data(response, dbresult_error_message(&result));
        dbresult_free(&result);
        return;
    }

    const db_table_cell_t* field = dbresult_field(&result, NULL);

    response->datan(response, field->value, field->length);

    dbresult_free(&result);
}
