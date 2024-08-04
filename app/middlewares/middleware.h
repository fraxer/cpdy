#ifndef __MIDDLEWARE__
#define __MIDDLEWARE__

#include "httpcontext.h"
#include "wscontext.h"

typedef struct middleware_item {
    char value[128];
    int (*fn)(void* ctx);
    struct middleware_item* next;
} middleware_item_t;

#define middleware(...) COND_AND(__VA_ARGS__)
#define middlewarecb(...) if (!run_middlewarecb(NARG_(__VA_ARGS__,SEQ_N()), __VA_ARGS__)) return;

#define ITEM_CONC(A, B) A##B
#define ITEM(N, ...) ITEM_CONC(ITEM_, N)(__VA_ARGS__)
#define ITEM_20(NAME, ...) NAME && ITEM_19(__VA_ARGS__)
#define ITEM_19(NAME, ...) NAME && ITEM_18(__VA_ARGS__)
#define ITEM_18(NAME, ...) NAME && ITEM_17(__VA_ARGS__)
#define ITEM_17(NAME, ...) NAME && ITEM_16(__VA_ARGS__)
#define ITEM_16(NAME, ...) NAME && ITEM_15(__VA_ARGS__)
#define ITEM_15(NAME, ...) NAME && ITEM_14(__VA_ARGS__)
#define ITEM_14(NAME, ...) NAME && ITEM_13(__VA_ARGS__)
#define ITEM_13(NAME, ...) NAME && ITEM_12(__VA_ARGS__)
#define ITEM_12(NAME, ...) NAME && ITEM_11(__VA_ARGS__)
#define ITEM_11(NAME, ...) NAME && ITEM_10(__VA_ARGS__)
#define ITEM_10(NAME, ...) NAME && ITEM_9(__VA_ARGS__)
#define ITEM_9(NAME, ...) NAME && ITEM_8(__VA_ARGS__)
#define ITEM_8(NAME, ...) NAME && ITEM_7(__VA_ARGS__)
#define ITEM_7(NAME, ...) NAME && ITEM_6(__VA_ARGS__)
#define ITEM_6(NAME, ...) NAME && ITEM_5(__VA_ARGS__)
#define ITEM_5(NAME, ...) NAME && ITEM_4(__VA_ARGS__)
#define ITEM_4(NAME, ...) NAME && ITEM_3(__VA_ARGS__)
#define ITEM_3(NAME, ...) NAME && ITEM_2(__VA_ARGS__)
#define ITEM_2(NAME, ...) NAME && ITEM_1(__VA_ARGS__)
#define ITEM_1(NAME) NAME
#define COND_AND(...) if (!(ITEM(M_NARGS(__VA_ARGS__), __VA_ARGS__))) return;

#define NARG_(...) ARG_N(__VA_ARGS__)
#define ARG_N(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,_21,_22,_23,_24,_25,_26,_27,_28,_29,_30,_31,_32,_33,_34,_35,_36,_37,_38,_39,_40,_41,_42,_43,_44,_45,_46,_47,_48,_49,_50,_51,_52,_53,_54,_55,_56,_57,_58,_59,_60,_61,_62,_63,N,...) N
#define SEQ_N() 63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0

#define args_str(...) (char*[NARG_(__VA_ARGS__,SEQ_N())]){__VA_ARGS__}, NARG_(__VA_ARGS__,SEQ_N())

int run_middlewares(middleware_item_t* middleware_item, void* ctx);
int run_middlewarecb(int count, ...);

int authenticate_by_name_pass(httpctx_t* ctx);
int query_param_required(httpctx_t* ctx, char** keys, int size);
int auth_required(httpctx_t* ctx);
int authenticate_by_token_required(httpctx_t* ctx);

#endif