#pragma once

#include <stdint.h>
#include <stddef.h>

#define SALSA20_SUCCESS 1
#define SALSA20_ERROR 0

/**
 * Encrypts or decrypts messages up to 2^32-1 bytes long, under a
 * 128-bit key and a unique 64-byte nonce.  Permits seeking to any
 * point within a message.
 *
 * key    Pointer to either a 128-bit or 256-bit key.
 *        No key-derivation function is applied to this key, and no
 *        entropy is gathered. It is expected that this key is already
 *        appropriate for direct use by the Salsa20 algorithm.
 *
 * keylen Length of the key.
 *        Must be S20_KEYLEN_256 or S20_KEYLEN_128.
 *
 * nonce  Pointer to an 8-byte nonce.
 *        Does not have to be random, but must be unique for every
 *        message under a single key. Nonce reuse destroys message
 *        confidentiality.
 *
 * si     Stream index.
 *        This is for seeking within a larger message. If you are only
 *        working with small messages that are encrypted/decrypted all
 *        at once (like TLS records), this will always be 0.
 *
 * buf    The data to encrypt or decrypt.
 *
 * buflen Length of the data in buf.
 */
int s20_crypt(uint8_t *key, uint8_t nonce[8], uint32_t si, uint8_t *buf, uint32_t buflen);

static uint32_t rotl(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

static void s20_quarterround(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* y3) {
    *y1 = *y1 ^ rotl(*y0 + *y3, 7);
    *y2 = *y2 ^ rotl(*y1 + *y0, 9);
    *y3 = *y3 ^ rotl(*y2 + *y1, 13);
    *y0 = *y0 ^ rotl(*y3 + *y2, 18);
}

static void s20_rowround(uint32_t y[16]) {
    s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
    s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
    s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
    s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
}

static void s20_columnround(uint32_t x[16]) {
    s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
    s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
    s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
    s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
}

static void s20_doubleround(uint32_t x[16]) {
    s20_columnround(x);
    s20_rowround(x);
}

// Creates a little-endian word from 4 bytes pointed to by b
static uint32_t s20_littleendian(uint8_t* b) {
    return b[0] +
        ((uint_fast16_t)b[1] << 8) +
        ((uint_fast32_t)b[2] << 16) +
        ((uint_fast32_t)b[3] << 24);
}

static void s20_rev_littleendian(uint8_t* b, uint32_t w) {
    b[0] = w;
    b[1] = w >> 8;
    b[2] = w >> 16;
    b[3] = w >> 24;
}

static void s20_hash(uint8_t seq[64]) {
    int i;
    uint32_t x[16];
    uint32_t z[16];

    for (i = 0; i < 16; ++i)
        x[i] = z[i] = s20_littleendian(seq + (4 * i));

    for (i = 0; i < 10; ++i)
        s20_doubleround(z);

    for (i = 0; i < 16; ++i) {
        z[i] += x[i];
        s20_rev_littleendian(seq + (4 * i), z[i]);
    }
}

static void s20_expand16(uint8_t* k, uint8_t n[16], uint8_t keystream[64]) {
    int i, j;
    // slightly customized
    uint8_t t[4][4] = {
      { 'e', 'x', 'p', 'g' },
      { 'n', 'd', ' ', '1' },
      { '6', '-', 'b', 'y' },
      { 'q', 'e', ' ', 'k' }
    };

    for (i = 0; i < 64; i += 20)
        for (j = 0; j < 4; ++j)
            keystream[i + j] = t[i / 20][j];

    for (i = 0; i < 16; ++i) {
        keystream[4 + i] = k[i];
        keystream[44 + i] = k[i];
        keystream[24 + i] = n[i];
    }

    s20_hash(keystream);
}

int s20_crypt(uint8_t* key, uint8_t nonce[8], uint32_t si, uint8_t* buf, uint32_t buflen) {
    uint8_t keystream[64];
    uint8_t n[16] = { 0 };
    uint32_t i;

    void (*expand)(uint8_t*, uint8_t*, uint8_t*) = NULL;
    expand = s20_expand16;

    if (expand == NULL || key == NULL || nonce == NULL || buf == NULL)
        return SALSA20_ERROR;

    for (i = 0; i < 8; ++i)
        n[i] = nonce[i];

    if (si % 64 != 0) {
        s20_rev_littleendian(n + 8, si / 64);
        (*expand)(key, n, keystream);
    }

    for (i = 0; i < buflen; ++i) {
        if ((si + i) % 64 == 0) {
            s20_rev_littleendian(n + 8, ((si + i) / 64));
            (*expand)(key, n, keystream);
        }

        buf[i] ^= keystream[(si + i) % 64];
    }

    return SALSA20_SUCCESS;
}