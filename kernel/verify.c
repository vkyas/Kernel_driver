#include "verify.h"
#include <linux/string.h>
#include <linux/types.h>

char rc4_key[] = "!@##$asdcgfxxxop";
const uint64_t SHARED_MAGIC_VALUE = 0xFEEDFACECAFEBEEF;

void rc4_init(unsigned char* s, unsigned char* key, unsigned long len_key)
{
    int i = 0, j = 0;
    unsigned char k[256] = { 0 };
    unsigned char tmp = 0;
    for (i = 0; i < 256; i++) {
        s[i] = i;
        k[i] = key[i % len_key];
    }
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + k[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

void rc4_crypt(unsigned char* data,
    unsigned long len_data, unsigned char* key,
    unsigned long len_key)
{
    unsigned char s[256];
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    rc4_init(s, key, len_key);
    for (k = 0; k < len_data; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        data[k] = data[k] ^ s[t];
    }
}

bool init_key(char* key_buffer, size_t len_key) {
    if (!key_buffer || len_key < sizeof(SHARED_MAGIC_VALUE))
        return false;

    rc4_crypt((unsigned char*)key_buffer, len_key, (unsigned char*)rc4_key, strlen(rc4_key));

    if (memcmp(key_buffer, &SHARED_MAGIC_VALUE, sizeof(SHARED_MAGIC_VALUE)) == 0)
        return true;

    return false;
}
