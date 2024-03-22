#ifndef __BASE64__
#define __BASE64__

int base64_encode_len(const int len);
int base64_encode(char* encoded, const char* string, const int len);

int base64_encode_nl_len(const int len);
int base64_encode_nl(char* encoded, const char* string, const int len);

int base64_decode_len(const char* bufcoded);
int base64_decode(char* bufplain, const char* bufcoded);

#endif