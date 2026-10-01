// Copyright © 2026 Racpast. All Rights Reserved.
//
// MinGW headers expose the C23 memset_explicit API before the runtime provides
// its symbol. libsodium correctly uses that API for secret erasure, so provide
// the missing semantics instead of aliasing it to optimizable memset.

#include <stddef.h>

void* memset_explicit(void* destination, int value, size_t count) {
    volatile unsigned char* out = (volatile unsigned char*)destination;
    while (count-- != 0) *out++ = (unsigned char)value;
    return destination;
}
