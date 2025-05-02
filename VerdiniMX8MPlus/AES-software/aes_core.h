#ifndef AES_CORE_H
#define AES_CORE_H

#include <cstdint>

#define AES_BLOCK_SIZE 16
#define AES_ROUNDS 10
#define AES_ROUND_KEY_SIZE 176
#define IV_SIZE 16

extern const unsigned char aes_key[16];

struct AES_ctx
{
    uint8_t round_key[AES_ROUND_KEY_SIZE];
    uint8_t key[AES_BLOCK_SIZE];
};

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);
void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);
void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);
void AES_CBC_encrypt(struct AES_ctx *ctx, uint8_t *iv, uint8_t *buf, uint32_t length);
void AES_CBC_decrypt(struct AES_ctx *ctx, uint8_t *iv, uint8_t *buf, uint32_t length);

#endif