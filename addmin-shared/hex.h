#pragma once

#include <stdint.h>

inline static char decodeHexDigit(char digit) {
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    else if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    else if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    }
    return 0xff;
}

size_t decodeHex(const char* hexBuf, size_t hexBufSize, char* decodedBuf, size_t decodedBufLen) {
    for (size_t i = 0; i < hexBufSize; ++i) {
        char c = hexBuf[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }

    size_t decodeLen = hexBufSize / 2;
    for (size_t i = 0; i < hexBufSize; i += 2) {
        if (i / 2 >= decodedBufLen)
            return decodedBufLen;

        char hi = decodeHexDigit(hexBuf[i]);
        char lo = decodeHexDigit(hexBuf[i + 1]);
        decodedBuf[i / 2] = (hi << 4) | lo;
    }

    return decodeLen;
}