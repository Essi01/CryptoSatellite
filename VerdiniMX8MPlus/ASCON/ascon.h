// ascon.h
#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// Ascon constants
#define ASCON_IV 0x80400c0600000000ULL  // Initialization vector for Ascon-128
#define ASCON_ROUNDS_A 12               // Rounds for permutation in initialization/finalization
#define ASCON_ROUNDS_B 6                // Rounds for permutation in between blocks
#define IV_SIZE 16                      // External IV size
#define KEY_SIZE 16                     // 128-bit key
#define TAG_SIZE 16                     // 128-bit authentication tag

// Function prototypes
void ascon_init(void);
uint64_t bytesToUInt64(const uint8_t* bytes);
void uint64ToBytes(uint64_t value, uint8_t* bytes);
uint64_t rotr(uint64_t x, int n);
void ascon_permutation(uint64_t* s, int rounds);
size_t padData(const char* input, unsigned char* output, size_t len);
size_t removePadding(unsigned char* data, size_t len);
void generateIV(unsigned char* iv);
unsigned long encrypt(const unsigned char* input, unsigned char* output, size_t len);
unsigned long decrypt(const unsigned char* input, unsigned char* output, size_t len);
int evaluerUttrykk(const char* expr);
void printHex(const unsigned char* data, size_t len);

#endif /* ASCON_H */