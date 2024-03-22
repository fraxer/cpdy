#ifndef __SMTPINTERNAL__
#define __SMTPINTERNAL__

#include "connection.h"

void smtp_client_read(connection_t*, char*, size_t);
void smtp_client_write(connection_t*, char*, size_t);

#endif
