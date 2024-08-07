#include <dlfcn.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "routeloader.h"

routeloader_lib_t* __routeloader_init_container(const char*, void*);
void* __routeloader_get_handler_internal(routeloader_lib_t*, const char*, const char*, int);

routeloader_lib_t* routeloader_load_lib(const char* filepath) {
    void* shared_lib_p = dlopen(filepath, RTLD_LAZY);

    if (shared_lib_p == NULL) {
        log_error(ROUTELOADER_LIB_NOT_FOUND, filepath);
        return NULL;
    }

    routeloader_lib_t* routeloader_lib = __routeloader_init_container(filepath, shared_lib_p);

    if (routeloader_lib == NULL) {
        log_error(ROUTELOADER_OUT_OF_MEMORY);
        dlclose(shared_lib_p);
        return NULL;
    }

    return routeloader_lib;
}

void* routeloader_get_handler_silent(routeloader_lib_t* first_lib, const char* filepath, const char* function_name) {
    return __routeloader_get_handler_internal(first_lib, filepath, function_name, 1);
}

void* routeloader_get_handler(routeloader_lib_t* first_lib, const char* filepath, const char* function_name) {
    return __routeloader_get_handler_internal(first_lib, filepath, function_name, 0);
}

void* __routeloader_get_handler_internal(routeloader_lib_t* first_lib, const char* filepath, const char* function_name, int silent) {
    routeloader_lib_t* lib = first_lib;

    while (lib) {
        if (strcmp(lib->filepath, filepath) == 0) {
            void* function_p;

            *(void**)(&function_p) = dlsym(lib->pointer, function_name);

            if (function_p == NULL) {
                if (!silent) 
                    log_error(ROUTELOADER_FUNCTION_NOT_FOUND, function_name, filepath);

                return NULL;
            }

            return function_p;
        }

        lib = lib->next;
    }

    return NULL;
}

void routeloader_free(routeloader_lib_t* first_lib) {
    routeloader_lib_t* lib = first_lib;

    while (lib) {
        routeloader_lib_t* next = lib->next;

        free(lib->filepath);

        dlclose(lib->pointer);

        free(lib);

        lib = next;
    }
}

routeloader_lib_t* __routeloader_init_container(const char* filepath, void* shared_lib) {
    routeloader_lib_t* routeloader_lib = (routeloader_lib_t*)malloc(sizeof(routeloader_lib_t));

    if (routeloader_lib == NULL) return NULL;

    routeloader_lib->filepath = (char*)malloc(strlen(filepath) + 1);

    if (routeloader_lib->filepath == NULL) {
        free(routeloader_lib);
        return NULL;
    }

    strcpy(routeloader_lib->filepath, filepath);

    routeloader_lib->pointer = shared_lib;
    routeloader_lib->next = NULL;

    return routeloader_lib;
}

int routeloader_has_lib(routeloader_lib_t* lib, const char* filepath) {
    while (lib != NULL) {
        if (strcmp(lib->filepath, filepath) == 0) return 1;

        lib = lib->next;
    }

    return 0;
}

routeloader_lib_t* routeloader_get_last(routeloader_lib_t* lib) {
    while (lib != NULL) {
        if (lib->next == NULL)
            return lib;

        lib = lib->next;
    }

    return lib;
}
