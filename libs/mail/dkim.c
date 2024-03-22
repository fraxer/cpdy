/*
The MIT License

Copyright (c) 2012 Comfirm <http://www.comfirm.se/>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "log.h"
#include "dkim.h"
    
int relaxed_header_canon(stringpair* newheaders, stringpair* headers, int headerc);
char *relaxed_body_canon(const char *body);
char *relaxed_body_canon_line(char *line);    

char *rtrim_lines(char *str);
char *rtrim(char *str);
char *ltrim(char *str);
char *wrap(char *str, int len);
RSA* dkim_rsa_read_pem(const char* buffer);
char *base64_encode(const unsigned char *input, int length);


/**
 * Create a DKIM-signature header value
 * http://tools.ietf.org/html/rfc4871
 */
char* dkim_create(stringpair* headers, int headerc, const char *body, const char* private_key, const char *domain, const char *selector) {
    RSA* rsa_private = dkim_rsa_read_pem(private_key);
    if (rsa_private == NULL) {
        log_error("DKIM error loading rsa key\n");
        return NULL;
    }

    /* relax canonicalization for headers */
    stringpair new_headers[headerc + 1];
    if (!relaxed_header_canon(new_headers, headers, headerc))
        return NULL;

    /* relax canonicalization for body */
    char* new_body = relaxed_body_canon(body);
    const size_t new_body_len = strlen(new_body);

    /* hash of the canonicalized body */
    unsigned char *uhash = malloc(SHA_DIGEST_LENGTH);
    SHA1((unsigned char*)new_body, new_body_len, uhash);

	free(new_body);
    
    /* base64 encode the hash */
    char *bh = base64_encode(uhash, SHA_DIGEST_LENGTH);
    free(uhash);

    /* create header list */
    char *header_list = malloc(headerc*200);
    int header_list_len = 0;
    for (int i = 0; i < headerc; ++i) {
        if (header_list_len != 0) {
            header_list_len += sprintf(header_list + header_list_len, ":");
        }
    
        header_list_len += sprintf(header_list + header_list_len, "%s", new_headers[i].key);
    }

	/* signature timestamp */
    time_t ts = time(0);
    
    /* create DKIM header */
    char *dkim_string = "v=1; a=rsa-sha1; s=%s; d=%s; l=%d; t=%d; c=relaxed/relaxed; h=%s; bh=%s; b=";
    char *dkim = malloc(strlen(dkim_string)+strlen(selector)+strlen(domain)+16+16+strlen(header_list)+strlen(bh)+1);
    int dkim_len = sprintf(dkim, dkim_string,
        selector, domain, new_body_len, ts, header_list, bh
    );
    
    /* free some memory */
    free (header_list);
    free (bh);
    
    /* add dkim header to headers */
    strncpy(new_headers[headerc].key, "dkim-signature", 127);
    strncpy(new_headers[headerc].value, dkim, 1023);
    headerc++;
    
    /* make a string of all headers */
    char *header_str = malloc(1500*headerc);
    int header_str_len = 0;
    
    for (int i = 0; i < headerc; ++i) {
        int key_len = strlen(new_headers[i].key);
        int value_len = strlen(new_headers[i].value);
    
        memcpy (header_str+header_str_len, new_headers[i].key, key_len);
        header_str_len += key_len;
        
        memcpy (header_str+header_str_len, ":", 1);
        header_str_len++;
        
        memcpy (header_str+header_str_len, new_headers[i].value, value_len);
        header_str_len += value_len;
        
        if (i < headerc-1) {
            memcpy (header_str+header_str_len, "\r\n", 3);
            header_str_len += 2;
        }
    }
    
    /* hash the headers */
    unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
    SHA1 ((unsigned char*)header_str, header_str_len, hash);
    
    /* sign canon headers with private key */
    unsigned char *sig = malloc(RSA_size(rsa_private));
    unsigned int sig_len;
    
    if (RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sig, &sig_len, rsa_private) == 0) {
        printf (" * ERROR RSA_sign(): %s\n", ERR_error_string(ERR_get_error(), NULL));
        free (hash);
        free (header_str);
        free (sig);
        RSA_free (rsa_private);
        return NULL;
    }
    
    free (hash);

    /* base64 encode the signature */
    char *sig_b64 = base64_encode(sig, sig_len);
    int sig_b64_len = strlen(sig_b64);
    
    /* add it to the dkim header */
    dkim = realloc(dkim, dkim_len + sig_b64_len + 1);
    memcpy (dkim + dkim_len, sig_b64, sig_b64_len + 1);
    dkim_len += sig_b64_len;
    
    /* wrap dkim header */
    dkim = wrap(dkim, dkim_len);
    
    /* free some more memory */
    free (header_str);
    free (sig);
    free (sig_b64);
    
    /* free the private key */
    RSA_free (rsa_private);
    
    /* return the dkim header value */
    return dkim;
}

/* The "relaxed" Header Canonicalization Algorithm */
int relaxed_header_canon(stringpair* new_headers, stringpair* headers, int headerc) {
    int i = 0;
    int e = 0;

    /* Copy all headers */
    for (i = 0; i < headerc; ++i) {
        int key_len = strlen(headers[i].key);
        int val_len = strlen(headers[i].value);

        new_headers[i].key[0] = 0;
        new_headers[i].value[0] = 0;

        memcpy(new_headers[i].key, headers[i].key, key_len+1);
        memcpy(new_headers[i].value, headers[i].value, val_len+1);
    }

    /* Convert all header field names (not the header field values) to
       lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC". */
    for (i = 0; i < headerc; ++i) {
        const int key_len = strlen(new_headers[i].key);
        for (e = 0; e < key_len; ++e)
            new_headers[i].key[e] = tolower(new_headers[i].key[e]);
    }
    
    /* Unfold all header field continuation lines as described in
       [RFC2822]; in particular, lines with terminators embedded in
       continued header field values (that is, CRLF sequences followed by
       WSP) MUST be interpreted without the CRLF.  Implementations MUST
       NOT remove the CRLF at the end of the header field value. */
    for (i = 0; i < headerc; ++i) {
        int val_len = strlen(new_headers[i].value);
        int new_len = 0;

        for (e = 0; e < val_len; ++e) {
            if (e < val_len + 1) {
                if (!(new_headers[i].value[e] == '\r' && new_headers[i].value[e+1] == '\n')) {
                    new_headers[i].value[new_len++] = new_headers[i].value[e];
                } else {
                    ++e;
                }
            } else {
                new_headers[i].value[new_len++] = new_headers[i].value[e];
            }
        }
        
        new_headers[i].value[new_len] = '\0';
    }
    
    /* Convert all sequences of one or more WSP characters to a single SP
       character.  WSP characters here include those before and after a
       line folding boundary. */
    for (i = 0; i < headerc; ++i) {
        int val_len = strlen(new_headers[i].value);
        int new_len = 0;

        for (e = 0; e < val_len; ++e) {
            if (new_headers[i].value[e] == '\t') {
                new_headers[i].value[e] = ' ';
            }
        
            if (e > 0) {
                if (!(new_headers[i].value[e-1] == ' ' && new_headers[i].value[e] == ' ')) {
                    new_headers[i].value[new_len++] = new_headers[i].value[e];
                } 
            } else {
                new_headers[i].value[new_len++] = new_headers[i].value[e];
            }
        }
        
        new_headers[i].value[new_len] = '\0';
    }
    
    /* Delete all WSP characters at the end of each unfolded header field
           value. */   
        /* Delete any WSP characters remaining before and after the colon
       separating the header field name from the header field value.  The
       colon separator MUST be retained. */
    for (i = 0; i < headerc; ++i) {
        strcpy(new_headers[i].value, rtrim(new_headers[i].value));
        strcpy(new_headers[i].value, ltrim(new_headers[i].value));
    }

    return 1;
}


/* The "relaxed" Body Canonicalization Algorithm */
char *relaxed_body_canon(const char *body) {
    int i = 0;
    int offset = 0;
    int body_len = strlen(body);
    
    char *new_body = malloc(body_len*2+3);
    int new_body_len = 0;

    for (i = 0; i < body_len; ++i) {
        int is_r = 0;
    
        if (body[i] == '\n') {
            if (i > 0) {
                if (body[i-1] == '\r') {
                    i--;
                    is_r = 1;
                }
            }
            
            char *line = malloc(i - offset + 1);    
            memcpy (line, body+offset, i-offset);
            line[i-offset] = '\0';
        
            relaxed_body_canon_line (line);

            int line_len = strlen(line);
            memcpy (new_body+new_body_len, line, line_len);
            memcpy (new_body+new_body_len+line_len, "\r\n", 2);
            new_body_len += line_len+2;
            
            if (is_r) {
                i++;
            }    
            
            offset = i+1;
            free (line);
        }
    }

    if (offset < body_len) {
        char *line = malloc(i - offset + 1);    
        memcpy (line, body+offset, i-offset);
        line[i-offset] = '\0';
    
        relaxed_body_canon_line (line);
                
        int line_len = strlen(line);
        memcpy (new_body+new_body_len, line, line_len);
        memcpy (new_body+new_body_len+line_len, "\r\n", 2);
        new_body_len += line_len+2;
        
        free (line);
    }

    memcpy (new_body+new_body_len, "\0", 1);
    
    /* Ignores all empty lines at the end of the message body.  "Empty
             line" is defined in Section 3.4.3. */
    new_body = rtrim_lines(new_body);
    
    /* Note that a completely empty or missing body is canonicalized as a
           single "CRLF"; that is, the canonicalized length will be 2 octets. */
    new_body_len = strlen(new_body);
    new_body[new_body_len++] = '\r';
    new_body[new_body_len++] = '\n';
    new_body[new_body_len] = '\0';
    
    return new_body;    
}


/* The "relaxed" Body Canonicalization Algorithm, per line */
char *relaxed_body_canon_line(char *line) {
    int line_len = 0;
    int i;
    
    /* Ignores all whitespace at the end of lines.  Implementations MUST
             NOT remove the CRLF at the end of the line. */
    rtrim (line);
    
    /* Reduces all sequences of WSP within a line to a single SP
       character. */
    line_len = strlen(line);
    int new_len = 0;

    for (i = 0; i < line_len; ++i) {
        if (line[i] == '\t') {
            line[i] = ' ';
        }
    
        if (i > 0) {
            if (!(line[i-1] == ' ' && line[i] == ' ')) {
                line[new_len++] = line[i];
            } 
        } else {
            line[new_len++] = line[i];
        }
    }
    
    line[new_len] = '\0';
    
    return line;
}


/* rtrim function for lines */
char *rtrim_lines(char *str) {
    char *end;
    int len = strlen(str);

    while (*str && len) {
        end = str + len-1;
        
        if (*end == '\r' || *end == '\n') {
            *end = '\0';
        } else {
            break;
        }
        
        len = strlen(str);
    }
    
    return str;
}


/* rtrim function */
char *rtrim(char *str) {
    char *end;
    int len = strlen(str);

    while (*str && len) {
        end = str + len-1;
        
        if (*end == ' ' || *end == '\t') {
            *end = '\0';
        } else {
            break;
        }
        
        len = strlen(str);
    }
    
    return str;
}


/* ltrim function */
char *ltrim(char *str) {
    char *start = str;
    int len = strlen(str);

    while (*start && len) {        
        if (*start == ' ' || *start == '\t') {
            start++;
        } else {
            break;
        }
        
        len = strlen(start);
    }
    
    char *n = malloc(strlen(start)+1);
    memcpy (n, start, strlen(start)+1);
    free (str);
    
    return n;
}


/* very simple word wrap function for headers */
char *wrap(char *str, int len) {
    char *tmp = malloc(len*3+1);
    int tmp_len = 0;
    int i;
    int lcount = 0;
    
    for (i = 0; i < len; ++i) {
        if (str[i] == ' ' || lcount == 75) {
            tmp[tmp_len++] = str[i];
            tmp[tmp_len++] = '\r';
            tmp[tmp_len++] = '\n';
            tmp[tmp_len++] = '\t';
            lcount = 0;
        } else {
            tmp[tmp_len++] = str[i];
            ++lcount;
        }
    }
    
    tmp[tmp_len] = '\0';
    free (str);
    
    return tmp;
}


RSA* dkim_rsa_read_pem(const char* buffer) {
    BIO* mem = BIO_new_mem_buf(buffer, strlen(buffer));
    if (mem == NULL)
        return NULL;

    RSA* rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);

    BIO_free(mem);

    return rsa;
} 


/* Base64 encode algorithm using openssl */
char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    
    BIO_write (b64, input, length);
    BIO_flush (b64);
    BIO_get_mem_ptr (b64, &bptr);

    char *buff = malloc(bptr->length);
    memcpy (buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = '\0';

    BIO_free_all (b64);

    /* remove line breaks */
    int buff_len = strlen(buff);
    int i, cur = 0;
    for (i = 0; i < buff_len; ++i) {
        if (buff[i] != '\r' && buff[i] != '\n') {
            buff[cur++] = buff[i];
        }
    }
    buff[cur] = '\0';    

    return buff;
}