#ifndef __HELPERS__
#define __HELPERS__

char* helpers_read_file(int fd);

long int helpers_file_size(int fd);

void helpers_free_null(void*);

int helpers_mkdir(const char* base_path, const char* path);

#endif