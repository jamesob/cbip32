#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "bip32.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    
    bip32_key target;
    
    size_t source_len = size/2;
    char *source = malloc(source_len + 1);
    if (!source) {
        return 0;
    }
    char *path = malloc(size - source_len + 1);
    if (!path) {
        free(source);
        return 0;
    }
    
    memcpy(source, data, source_len);
    memcpy(path, data + source_len, size - source_len);
    source[source_len] = '\0';
    path[size - source_len] = '\0';
    
    if (path[0] != 'm') path[0] = 'm';
    
    bip32_derive_from_str(&target, source, path);

    free(source);
    free(path);
    return 0;
}
