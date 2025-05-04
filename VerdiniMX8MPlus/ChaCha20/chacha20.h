// chacha20.h
#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>

// Type definitions (matching GitHub repo)
typedef uint8_t key256_t[32];
typedef uint8_t nonce96_t[12];

// Constants for compatibility with benchmark system
#define IV_SIZE 12                    // 96-bit nonce 
#define KEY_SIZE 32                   // 256-bit key
#define TAG_SIZE 16                   // For compatibility with ASCON interface

// ChaCha20 context (matching GitHub repo)
typedef struct {
    uint32_t state[4*4];
    uint32_t keystream[4*4];
    uint32_t idx;
} ChaCha20_Ctx;

// Function prototypes matching GitHub repo
void ChaCha20_init(ChaCha20_Ctx* ctx, const key256_t key, const nonce96_t nonce, uint32_t count);
void ChaCha20_xor(ChaCha20_Ctx* ctx, uint8_t* buffer, size_t bufflen);

// Additional functions needed for benchmark compatibility
void chacha20_init(void);
void generateIV(unsigned char* iv);
size_t padData(const char* input, unsigned char* output, size_t len);
size_t removePadding(unsigned char* data, size_t len);
unsigned long encrypt(const unsigned char* input, unsigned char* output, size_t len);
unsigned long decrypt(const unsigned char* input, unsigned char* output, size_t len);
int evaluerUttrykk(const char* expr);
void printHex(const unsigned char* data, size_t len);

#endif /* CHACHA20_H */