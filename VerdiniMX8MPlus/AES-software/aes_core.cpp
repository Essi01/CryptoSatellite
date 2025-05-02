// aes_core.cpp
#include "aes_core.h"
#include <cstring>

const unsigned char aes_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

static const uint8_t sbox[256] = {/* as before */};
static const uint8_t rsbox[256] = {/* as before */};
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

static void KeyExpansion(uint8_t *round_key, const uint8_t *key) { /* unchanged */ }
static void AddRoundKey(uint8_t round, uint8_t *state, const uint8_t *round_key) { /* unchanged */ }
static void SubBytes(uint8_t *state) { /* unchanged */ }
static void InvSubBytes(uint8_t *state) { /* unchanged */ }
static void ShiftRows(uint8_t *state) { /* unchanged */ }
static void InvShiftRows(uint8_t *state) { /* unchanged */ }

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void MixColumns(uint8_t *state)
{
    for (int i = 0; i < 4; ++i)
    {
        uint8_t t = state[4 * i + 0];
        uint8_t Tmp = state[4 * i + 0] ^ state[4 * i + 1] ^ state[4 * i + 2] ^ state[4 * i + 3];
        uint8_t Tm;

        Tm = xtime(state[4 * i + 0] ^ state[4 * i + 1]);
        state[4 * i + 0] ^= Tm ^ Tmp;

        Tm = xtime(state[4 * i + 1] ^ state[4 * i + 2]);
        state[4 * i + 1] ^= Tm ^ Tmp;

        Tm = xtime(state[4 * i + 2] ^ state[4 * i + 3]);
        state[4 * i + 2] ^= Tm ^ Tmp;

        Tm = xtime(state[4 * i + 3] ^ t);
        state[4 * i + 3] ^= Tm ^ Tmp;
    }
}

static uint8_t Multiply(uint8_t x, uint8_t y)
{
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (y & 1)
            result ^= x;
        uint8_t hi_bit = x & 0x80;
        x <<= 1;
        if (hi_bit)
            x ^= 0x1b;
        y >>= 1;
    }
    return result;
}

static void InvMixColumns(uint8_t *state)
{
    for (int i = 0; i < 4; ++i)
    {
        uint8_t a = state[4 * i + 0], b = state[4 * i + 1];
        uint8_t c = state[4 * i + 2], d = state[4 * i + 3];

        state[4 * i + 0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        state[4 * i + 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        state[4 * i + 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        state[4 * i + 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

void AES_init_ctx(AES_ctx *ctx, const uint8_t *key)
{
    memcpy(ctx->key, key, AES_BLOCK_SIZE);
    KeyExpansion(ctx->round_key, key);
}

static void Cipher(uint8_t *state, const uint8_t *round_key) { /* unchanged */ }
static void InvCipher(uint8_t *state, const uint8_t *round_key) { /* unchanged */ }

void AES_ECB_encrypt(const AES_ctx *ctx, uint8_t *buf) { Cipher(buf, ctx->round_key); }
void AES_ECB_decrypt(const AES_ctx *ctx, uint8_t *buf) { InvCipher(buf, ctx->round_key); }

void AES_CBC_encrypt(AES_ctx *ctx, uint8_t *iv, uint8_t *buf, uint32_t length)
{
    if (length % AES_BLOCK_SIZE)
        return;
    uint8_t current_iv[AES_BLOCK_SIZE];
    memcpy(current_iv, iv, AES_BLOCK_SIZE);

    for (uint32_t i = 0; i < length; i += AES_BLOCK_SIZE)
    {
        for (int j = 0; j < AES_BLOCK_SIZE; ++j)
            buf[i + j] ^= current_iv[j];
        AES_ECB_encrypt(ctx, buf + i);
        memcpy(current_iv, buf + i, AES_BLOCK_SIZE);
    }
    memcpy(iv, current_iv, AES_BLOCK_SIZE);
}

void AES_CBC_decrypt(AES_ctx *ctx, uint8_t *iv, uint8_t *buf, uint32_t length)
{
    if (length % AES_BLOCK_SIZE)
        return;
    uint8_t current_iv[AES_BLOCK_SIZE], temp[AES_BLOCK_SIZE];
    memcpy(current_iv, iv, AES_BLOCK_SIZE);

    for (uint32_t i = 0; i < length; i += AES_BLOCK_SIZE)
    {
        memcpy(temp, buf + i, AES_BLOCK_SIZE);
        AES_ECB_decrypt(ctx, buf + i);
        for (int j = 0; j < AES_BLOCK_SIZE; ++j)
            buf[i + j] ^= current_iv[j];
        memcpy(current_iv, temp, AES_BLOCK_SIZE);
    }
    memcpy(iv, current_iv, AES_BLOCK_SIZE);
}
