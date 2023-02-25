#ifndef __DATABASE__
#define __DATABASE__

#include <stdatomic.h>

typedef enum dbdriver {
    NONE = 0,
    POSTGRESQL,
    MYSQL
} dbdriver_e;

typedef enum dbperms {
    READ = 0,
    WRITE
} dbperms_e;

typedef enum transaction_level {
    READ_UNCOMMITTED,
    READ_COMMITTED,
    REPEATABLE_READ,
    SERIALIZABLE
} transaction_level_e;

typedef struct dbhost {
    int read;
    int write;
    int port;
    char* ip;
    struct dbhost* next;
} dbhost_t;

typedef struct db_table_cell {
    int length;
    char* value;
} db_table_cell_t;

typedef struct dbresult {
    int ok;
    int rows;
    int cols;
    const char* error_message;
    char* data;

    db_table_cell_t** fields; // ["", "", "", ...]
    db_table_cell_t** table; // ["", "", "", ...]
} dbresult_t;

typedef struct dbconnection {
    atomic_bool locked;
    struct dbconnection* next;
    void(*free)(void*);
    dbresult_t(*send_query)(struct dbconnection*, const char*);
} dbconnection_t;

typedef struct dbconfig {
    void(*free)(void*);
    dbconnection_t*(*connection_create)(struct dbconfig*);
} dbconfig_t;

typedef struct dbinstance {
    int ok;
    atomic_bool* lock_connection;
    dbconfig_t* config;
    dbconnection_t* connection;
    dbconnection_t*(*connection_create)(struct dbconfig*);
} dbinstance_t;

typedef struct db { // mysql, postgreqsl, ...
    atomic_bool lock_connection_read;
    atomic_bool lock_connection_write;
    const char* id;
    dbconfig_t* config;
    dbconnection_t* connection_read;
    dbconnection_t* connection_write;
    struct db* next;
} db_t;

db_t* db_alloc();

db_t* db_create(const char*);

dbhost_t* db_host_create();

void db_free(db_t*);

void db_host_free(dbhost_t*);

dbconnection_t* db_find_free_connection(dbconnection_t*);

void db_connection_append(dbinstance_t*, dbconnection_t*);

int db_connection_trylock(dbconnection_t*);

void db_connection_unlock(dbconnection_t*);

#endif