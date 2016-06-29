#if !defined(_HASH_H)
#define _HASH_H

#include <stdint.h>

#define BUCKETS 512

int shash(const char *target);
int dhash(uint32_t src, uint16_t qid);
int bhash(uint32_t src, uint32_t dst);

#endif
