#ifndef __PROTOCOLMANAGER__
#define __PROTOCOLMANAGER__

#include "tlsinternal.h"
#include "http1internal.h"
#include "websocketsinternal.h"
#include "smtpinternal.h"

void protmgr_set_tls(connection_t*);
void protmgr_set_client_tls(connection_t*);
void protmgr_set_http1(connection_t*);
void protmgr_set_client_http1(connection_t*);
void protmgr_set_websockets_default(connection_t*);
void protmgr_set_websockets_resource(connection_t*);

void protmgr_set_smtp_client_command(connection_t*);
void protmgr_set_smtp_client_content(connection_t*);
void protmgr_set_smtp_client_tls(connection_t*);

#endif
