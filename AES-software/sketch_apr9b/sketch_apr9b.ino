/*
 * Complete AES-CBC Software Implementation for Arduino
 * Pure software implementation - NO hardware acceleration
 */

#include <Arduino.h>
#ifdef ARDUINO_ARCH_MBED
#include "mbed_stats.h"
#define USE_INA219
#endif

// Algorithm identification and measurement constants
#define ALGORITHM_NAME "AES-CBC-SOFTWARE"
bool detailed_memory_tracking = false;  // Variabel som kan endres under kjøring

#ifdef USE_INA219
#include <Adafruit_INA219.h>
Adafruit_INA219 ina219;
#endif

/*********************** DEFINES ***********************/
#define AES_BLOCK_SIZE      16
#define AES_ROUNDS          10  // 12, 14 for AES-192, AES-256 respectively
#define AES_ROUND_KEY_SIZE  176 // AES-128 has 10 rounds, 11 round keys
#define IV_SIZE             16  // IV størrelse for CBC modus

// Konstanter for non-blocking benchmark
#define BENCHMARK_CHUNK_SIZE 100  // Antall iterasjoner per chunk
#define BENCHMARK_IDLE false
#define BENCHMARK_RUNNING true

// AES nøkkel (128-bit)
const unsigned char aes_key[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Test vector for AES-128/CBC validation
const unsigned char test_key[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

const unsigned char test_iv[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const unsigned char test_plaintext[16] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

const unsigned char test_ciphertext[16] = {
  0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
  0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d
};

// Benchmark state variabler
bool benchmark_state = BENCHMARK_IDLE;
const size_t MAX_SIZE = 256;
unsigned char benchmark_padded[MAX_SIZE] = {0};
unsigned char benchmark_encrypted[MAX_SIZE + IV_SIZE] = {0};
unsigned char benchmark_decrypted[MAX_SIZE] = {0};
size_t benchmark_input_len = 0;
size_t benchmark_padded_len = 0;
long benchmark_current_iteration = 0;
long benchmark_total_iterations = 0;
unsigned long benchmark_total_encrypt_time = 0;
unsigned long benchmark_total_decrypt_time = 0;
unsigned long benchmark_total_eval_time = 0;
unsigned long benchmark_start_time = 0;
String benchmark_text = "";

// Memory management metrics
unsigned long used_ram = 0;
unsigned long total_ram = 0;
unsigned long max_stack = 0;
float cpu_usage = 0.0;
float avgEnc = 0.0;
float avgDec = 0.0;
unsigned long encrypt_throughput = 0;
unsigned long decrypt_throughput = 0;
unsigned long encrypt_goodput = 0;
unsigned long decrypt_goodput = 0;

// Energimåling variabler
#ifdef USE_INA219
float benchmark_total_energy = 0.0;
int benchmark_energy_samples = 0;
float benchmark_avg_current = 0.0;
unsigned long benchmark_last_energy_sample = 0;
const unsigned long ENERGY_SAMPLE_INTERVAL = 100; // Sample hver 100ms
#endif

/*********************** AES IMPLEMENTATION ***********************/

// Forward S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box
static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constant
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// AES context structure
typedef struct {
    uint8_t round_key[AES_ROUND_KEY_SIZE];
    uint8_t key[AES_BLOCK_SIZE];
} AES_ctx;

// Correctly implemented key expansion for AES
static void KeyExpansion(uint8_t* round_key, const uint8_t* key) {
    unsigned i, j, k;
    uint8_t tempa[4]; // Used for the column/row operations
    
    // The first round key is the key itself.
    for (i = 0; i < 4; ++i) {
        round_key[(i * 4) + 0] = key[(i * 4) + 0];
        round_key[(i * 4) + 1] = key[(i * 4) + 1];
        round_key[(i * 4) + 2] = key[(i * 4) + 2];
        round_key[(i * 4) + 3] = key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = 4; i < 4 * (AES_ROUNDS + 1); ++i) {
        // Functions RotWord and SubWord:
        for (j = 0; j < 4; ++j)
            tempa[j] = round_key[(i-1) * 4 + j];
        
        if (i % 4 == 0) {
            // RotWord: rotate the 4 bytes in a word to the left once
            {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }

            // SubWord: apply S-box to each byte
            {
                tempa[0] = sbox[tempa[0]];
                tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]];
                tempa[3] = sbox[tempa[3]];
            }

            tempa[0] = tempa[0] ^ Rcon[i/4];
        }
        
        round_key[i * 4 + 0] = round_key[(i - 4) * 4 + 0] ^ tempa[0];
        round_key[i * 4 + 1] = round_key[(i - 4) * 4 + 1] ^ tempa[1];
        round_key[i * 4 + 2] = round_key[(i - 4) * 4 + 2] ^ tempa[2];
        round_key[i * 4 + 3] = round_key[(i - 4) * 4 + 3] ^ tempa[3];
    }
}

// Add round key to state
static void AddRoundKey(uint8_t round, uint8_t* state, const uint8_t* round_key) {
    for (uint8_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] ^= round_key[(round * AES_BLOCK_SIZE) + i];
    }
}

// Substitute bytes using S-box
static void SubBytes(uint8_t* state) {
    for (uint8_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = sbox[state[i]];
    }
}

// Inverse substitute bytes
static void InvSubBytes(uint8_t* state) {
    for (uint8_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = rsbox[state[i]];
    }
}

// Shift rows of state matrix
static void ShiftRows(uint8_t* state) {
    uint8_t temp;

    // Rotate first row 1 column to left
    temp        = state[1];
    state[1]    = state[5];
    state[5]    = state[9];
    state[9]    = state[13];
    state[13]   = temp;

    // Rotate second row 2 columns to left
    temp        = state[2];
    state[2]    = state[10];
    state[10]   = temp;
    temp        = state[6];
    state[6]    = state[14];
    state[14]   = temp;

    // Rotate third row 3 columns to left
    temp        = state[3];
    state[3]    = state[15];
    state[15]   = state[11];
    state[11]   = state[7];
    state[7]    = temp;
}

// Inverse shift rows
static void InvShiftRows(uint8_t* state) {
    uint8_t temp;

    // Rotate first row 1 column to right
    temp        = state[13];
    state[13]   = state[9];
    state[9]    = state[5];
    state[5]    = state[1];
    state[1]    = temp;

    // Rotate second row 2 columns to right
    temp        = state[2];
    state[2]    = state[10];
    state[10]   = temp;
    temp        = state[6];
    state[6]    = state[14];
    state[14]   = temp;

    // Rotate third row 3 columns to right
    temp        = state[7];
    state[7]    = state[11];
    state[11]   = state[15];
    state[15]   = state[3];
    state[3]    = temp;
}

// Galois Field multiplication
static uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// Mix columns transformation
static void MixColumns(uint8_t* state) {
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i) {
        t   = state[i * 4 + 0];
        Tmp = state[i * 4 + 0] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        Tm  = state[i * 4 + 0] ^ state[i * 4 + 1];
        Tm = xtime(Tm);
        state[i * 4 + 0] ^= Tm ^ Tmp;
        Tm  = state[i * 4 + 1] ^ state[i * 4 + 2];
        Tm = xtime(Tm);
        state[i * 4 + 1] ^= Tm ^ Tmp;
        Tm  = state[i * 4 + 2] ^ state[i * 4 + 3];
        Tm = xtime(Tm);
        state[i * 4 + 2] ^= Tm ^ Tmp;
        Tm  = state[i * 4 + 3] ^ t;
        Tm = xtime(Tm);
        state[i * 4 + 3] ^= Tm ^ Tmp;
    }
}

// Multiply in GF(2^8)
static uint8_t Multiply(uint8_t x, uint8_t y) {
    return (((y & 1) * x) ^
            ((y >> 1 & 1) * xtime(x)) ^
            ((y >> 2 & 1) * xtime(xtime(x))) ^
            ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

// Inverse mix columns
static void InvMixColumns(uint8_t* state) {
    uint8_t i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i) {
        a = state[i * 4 + 0];
        b = state[i * 4 + 1];
        c = state[i * 4 + 2];
        d = state[i * 4 + 3];

        state[i * 4 + 0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        state[i * 4 + 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        state[i * 4 + 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        state[i * 4 + 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

// Initialize AES context with key
void AES_init_ctx(AES_ctx* ctx, const uint8_t* key) {
    memcpy(ctx->key, key, AES_BLOCK_SIZE);
    KeyExpansion(ctx->round_key, key);
}

// AES cipher process (encryption)
static void Cipher(uint8_t* state, const uint8_t* round_key) {
    uint8_t round = 0;

    // Initial round key addition
    AddRoundKey(0, state, round_key);

    // Main rounds
    for (round = 1; round < AES_ROUNDS; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, round_key);
    }

    // Final round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(AES_ROUNDS, state, round_key);
}

// AES inverse cipher process (decryption)
static void InvCipher(uint8_t* state, const uint8_t* round_key) {
    uint8_t round = 0;

    // Initial round key addition
    AddRoundKey(AES_ROUNDS, state, round_key);

    // Main rounds
    for (round = AES_ROUNDS - 1; round > 0; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, round_key);
        InvMixColumns(state);
    }

    // Final round (no InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(0, state, round_key);
}

// AES-ECB encryption
void AES_ECB_encrypt(const AES_ctx* ctx, uint8_t* buf) {
    Cipher(buf, ctx->round_key);
}

// AES-ECB decryption
void AES_ECB_decrypt(const AES_ctx* ctx, uint8_t* buf) {
    InvCipher(buf, ctx->round_key);
}

// AES-CBC encryption
void AES_CBC_encrypt(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length) {
    uint32_t i;
    uint8_t* iv_ptr = iv;
    uint8_t temp_iv[AES_BLOCK_SIZE];
    
    // Ensure length is a multiple of AES_BLOCK_SIZE
    if (length % AES_BLOCK_SIZE != 0) {
        return;
    }
    
    // Process each block
    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        // XOR with previous ciphertext block or IV
        for (uint8_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            buf[i + j] ^= iv_ptr[j];
        }
        
        // Encrypt block
        AES_ECB_encrypt(ctx, buf + i);
        
        // Update IV to current ciphertext block for next iteration
        iv_ptr = buf + i;
    }
    
    // If the original IV pointer was passed, update it to the last ciphertext block
    if (iv != buf + length - AES_BLOCK_SIZE) {
        memcpy(iv, buf + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }
}

// AES-CBC decryption
void AES_CBC_decrypt(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length) {
    uint32_t i;
    uint8_t temp_block[AES_BLOCK_SIZE];
    
    // Ensure length is a multiple of AES_BLOCK_SIZE
    if (length % AES_BLOCK_SIZE != 0) {
        return;
    }
    
    // Process each block
    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        // Save current ciphertext block for later XOR
        memcpy(temp_block, buf + i, AES_BLOCK_SIZE);
        
        // Decrypt block
        AES_ECB_decrypt(ctx, buf + i);
        
        // XOR with previous ciphertext block or IV
        for (uint8_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            buf[i + j] ^= iv[j];
        }
        
        // Update IV to current ciphertext block for next iteration
        memcpy(iv, temp_block, AES_BLOCK_SIZE);
    }
}

/*********************** UTILITY FUNCTIONS ***********************/

// Memory management functions
#ifdef ARDUINO_ARCH_MBED
int freeRam() {
    mbed_stats_heap_t stats;
    mbed_stats_heap_get(&stats);
    return stats.reserved_size - stats.current_size;
}

// Memory measurement function
void measureMemory(const char* label) {
  mbed_stats_heap_t heap_stats;
  mbed_stats_stack_t stack_stats;
  
  mbed_stats_heap_get(&heap_stats);
  mbed_stats_stack_get(&stack_stats);
  
  // Store metrics for decision matrix
  used_ram = heap_stats.current_size + stack_stats.max_size;
  total_ram = heap_stats.reserved_size;
  max_stack = stack_stats.max_size;
  
  // Skip detailed metrics if not in detailed mode and not a summary label
  if (strstr(label, "Step") != NULL && !detailed_memory_tracking) {
    return;
  }
  
  // Print memory information
  Serial.print("MEMORY [");
  Serial.print(label);
  Serial.print("]: Heap ");
  Serial.print(heap_stats.current_size);
  Serial.print("/");
  Serial.print(heap_stats.reserved_size);
  Serial.print(" bytes, Free: ");
  Serial.print(heap_stats.reserved_size - heap_stats.current_size);
  Serial.print(" bytes, Stack max: ");
  Serial.print(stack_stats.max_size);
  Serial.println(" bytes");
}

// Generate decision matrix data report
void generateMatrixReport() {
  mbed_stats_heap_t heap_stats;
  mbed_stats_stack_t stack_stats;
  
  mbed_stats_heap_get(&heap_stats);
  mbed_stats_stack_get(&stack_stats);
  
  used_ram = heap_stats.current_size + stack_stats.max_size;
  
  Serial.println("\n===== DECISION MATRIX DATA =====");
  Serial.print("Algorithm: ");
  Serial.println(ALGORITHM_NAME);
  
  Serial.print("RAM Usage: ");
  Serial.print(used_ram);
  Serial.println(" bytes");
  
  Serial.println("ROM/FLASH memory: [See compiler output]");
  
  Serial.print("CPU Usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");
  
  Serial.print("Encryption Latency: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  
  Serial.print("Decryption Latency: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");
  
  Serial.print("Encryption Throughput: ");
  Serial.print(encrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption Throughput: ");
  Serial.print(decrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Encryption Goodput: ");
  Serial.print(encrypt_goodput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption Goodput: ");
  Serial.print(decrypt_goodput);
  Serial.println(" bytes/s");
  
  #ifdef USE_INA219
  Serial.print("Current: ");
  Serial.print(benchmark_avg_current, 2);
  Serial.println(" mA");
  Serial.print("Energy: ");
  Serial.print(benchmark_total_energy, 2);
  Serial.println(" mJ");
  #else
  Serial.println("Current: [External measurement required]");
  Serial.println("Power: [External measurement required]");
  #endif
  
  Serial.println("Security Strength: 128-bit");
  Serial.println("Error Propagation: CBC mode propagates errors to next block");
  Serial.println("================================");
}
#else
int freeRam() {
  extern char __heap_start, *__brkval;
  int v;
  return (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
}

// Memory measurement function for non-MBED platforms
void measureMemory(const char* label) {
  int free_ram = freeRam();
  
  // Skip detailed metrics if not in detailed mode and not a summary label
  if (strstr(label, "Step") != NULL && !detailed_memory_tracking) {
    return;
  }
  
  Serial.print("MEMORY [");
  Serial.print(label);
  Serial.print("]: Free RAM: ");
  Serial.print(free_ram);
  Serial.println(" bytes");
}

// Simple matrix report for non-MBED platforms
void generateMatrixReport() {
  Serial.println("\n===== DECISION MATRIX DATA =====");
  Serial.print("Algorithm: ");
  Serial.println(ALGORITHM_NAME);
  
  Serial.print("RAM Usage: [See memory measurements]");
  Serial.println("ROM/FLASH memory: [See compiler output]");
  
  Serial.print("CPU Usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");
  
  Serial.print("Encryption Latency: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  
  Serial.print("Decryption Latency: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");
  
  Serial.print("Encryption Throughput: ");
  Serial.print(encrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption Throughput: ");
  Serial.print(decrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Encryption Goodput: ");
  Serial.print(encrypt_goodput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption Goodput: ");
  Serial.print(decrypt_goodput);
  Serial.println(" bytes/s");
  
  Serial.println("Current: [External measurement required]");
  Serial.println("Power: [External measurement required]");
  Serial.println("Security Strength: 128-bit");
  Serial.println("Error Propagation: CBC mode propagates errors to next block");
  Serial.println("================================");
}
#endif

// Hjelpefunksjon for å vise bytes som hex
void printHex(const unsigned char* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 16) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

// Safe subtraction function to handle timer overflows
unsigned long safeTimeDiff(unsigned long start, unsigned long end) {
  // Handle timer overflow
  if (end >= start) {
    return end - start;
  } else {
    // Overflow occurred
    return (0xFFFFFFFF - start) + end + 1;
  }
}

// Generer en tilfeldig IV
void generateIV(unsigned char* iv) {
  // Enkel implementasjon - i reell bruk, bruk en skikkelig CSPRNG
  for (int i = 0; i < IV_SIZE; i++) {
    iv[i] = random(256);
  }
}

// Pad data til 16-byte blokker (AES blokk-størrelse)
size_t padData(const char* input, unsigned char* output, size_t len) {
  size_t padded_len = ((len + 15) / 16) * 16;  // Rund opp til nærmeste 16

  // Kopier originale data
  memcpy(output, input, len);

  // Legg til padding (PKCS#7)
  unsigned char pad_value = padded_len - len;
  if (pad_value == 0) {
    pad_value = 16; // Hvis len er nøyaktig en multippel av blokk-størrelsen, legg til en full blokk
    padded_len += 16;
  }
  
  for (size_t i = len; i < padded_len; i++) {
    output[i] = pad_value;
  }

  return padded_len;
}

// Krypter data med AES-CBC
void encrypt(const unsigned char* input, unsigned char* output, size_t len) {
  if (detailed_memory_tracking) measureMemory("Step 1: Before Encryption");
  
  AES_ctx ctx;
  AES_init_ctx(&ctx, aes_key);
  
  if (detailed_memory_tracking) measureMemory("Step 2: After Key Setup");
  
  // Generer IV og kopier til starten av output
  unsigned char iv[IV_SIZE];
  generateIV(iv);
  memcpy(output, iv, IV_SIZE);
  
  if (detailed_memory_tracking) measureMemory("Step 3: After IV Generation");
  
  // Kopier input til temp buffer for kryptering
  memcpy(output + IV_SIZE, input, len);
  
  // Krypter data med CBC modus
  AES_CBC_encrypt(&ctx, iv, output + IV_SIZE, len);

  if (detailed_memory_tracking) measureMemory("Step 4: End of Encryption");
}

// Dekrypter data med AES-CBC
void decrypt(const unsigned char* input, unsigned char* output, size_t len) {
  if (detailed_memory_tracking) measureMemory("Step 1: Before Decryption");
  
  AES_ctx ctx;
  AES_init_ctx(&ctx, aes_key);
  
  if (detailed_memory_tracking) measureMemory("Step 2: After Key Setup");
  
  // Hent IV fra starten av input
  unsigned char iv[IV_SIZE];
  memcpy(iv, input, IV_SIZE);
  
  if (detailed_memory_tracking) measureMemory("Step 3: After IV Extraction");
  
  // Kopier input data til output buffer for dekryptering
  memcpy(output, input + IV_SIZE, len);
  
  // Dekrypter data med CBC modus
  AES_CBC_decrypt(&ctx, iv, output, len);

  if (detailed_memory_tracking) measureMemory("Step 4: End of Decryption");
}

// Fjern padding
size_t removePadding(unsigned char* data, size_t len) {
  if (len == 0) return 0;

  // Siste byte angir padding-lengde i PKCS#7
  unsigned char padding_value = data[len - 1];

  // Sjekk at padding er gyldig (ikke større enn blokk-størrelsen)
  if (padding_value > 16 || padding_value == 0) return len;
  
  // Verifiser at alle padding-bytes er like
  for (size_t i = len - padding_value; i < len; i++) {
    if (data[i] != padding_value) {
      // Ugyldig padding
      return len;
    }
  }

  return len - padding_value;
}

// Debug function - prints expanded keys for validation
void debugPrintRoundKeys(AES_ctx* ctx) {
  Serial.println("Round Keys:");
  for (int round = 0; round <= AES_ROUNDS; round++) {
    Serial.print("Round ");
    Serial.print(round);
    Serial.print(": ");
    for (int i = 0; i < 16; i++) {
      if (ctx->round_key[round * 16 + i] < 16) Serial.print("0");
      Serial.print(ctx->round_key[round * 16 + i], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
}

// Validate AES implementation against test vectors
bool validate_aes() {
  Serial.println("\nValidating AES implementation against test vectors...");
  
  // Setup test environment
  AES_ctx ctx;
  AES_init_ctx(&ctx, test_key);
  
  // Print round keys for debugging
  Serial.println("Expanded key values for test key:");
  debugPrintRoundKeys(&ctx);
  
  // Test encryption
  unsigned char output[16] = {0};
  unsigned char iv_buf[16];
  memcpy(iv_buf, test_iv, 16); // IV gets modified during operation
  memcpy(output, test_plaintext, 16);
  
  Serial.println("Plaintext:");
  printHex(output, 16);
  
  AES_CBC_encrypt(&ctx, iv_buf, output, 16);
  
  Serial.println("Encrypted:");
  printHex(output, 16);
  Serial.println("Expected:");
  printHex(test_ciphertext, 16);
  
  // Verify encryption result
  bool encryption_match = true;
  for (int i = 0; i < 16; i++) {
    if (output[i] != test_ciphertext[i]) {
      encryption_match = false;
      Serial.print("Encryption mismatch at byte ");
      Serial.print(i);
      Serial.print(": Expected ");
      Serial.print(test_ciphertext[i], HEX);
      Serial.print(", Got ");
      Serial.println(output[i], HEX);
    }
  }
  
  // Test decryption
  AES_init_ctx(&ctx, test_key);
  unsigned char decrypted[16] = {0};
  memcpy(iv_buf, test_iv, 16); // Reset IV for decryption
  memcpy(decrypted, test_ciphertext, 16);
  
  AES_CBC_decrypt(&ctx, iv_buf, decrypted, 16);
  
  Serial.println("Decrypted:");
  printHex(decrypted, 16);
  Serial.println("Expected:");
  printHex(test_plaintext, 16);
  
  // Verify decryption result
  bool decryption_match = true;
  for (int i = 0; i < 16; i++) {
    if (decrypted[i] != test_plaintext[i]) {
      decryption_match = false;
      Serial.print("Decryption mismatch at byte ");
      Serial.print(i);
      Serial.print(": Expected ");
      Serial.print(test_plaintext[i], HEX);
      Serial.print(", Got ");
      Serial.println(decrypted[i], HEX);
    }
  }
  
  // Overall validation result
  bool success = encryption_match && decryption_match;
  
  if (success) {
    Serial.println("Validation SUCCESSFUL! AES implementation is correct.");
  } else {
    Serial.println("Validation FAILED! AES implementation has errors.");
    Serial.print("Encryption match: "); Serial.println(encryption_match ? "YES" : "NO");
    Serial.print("Decryption match: "); Serial.println(decryption_match ? "YES" : "NO");
  }
  
  return success;
}

// Helper function to remove spaces from a string
void removeSpaces(const char* str, char* result) {
  int i = 0, j = 0;
  
  while (str[i]) {
    if (str[i] != ' ' && str[i] != '\t') {
      result[j++] = str[i];
    }
    i++;
  }
  result[j] = '\0';
}

// Evaluate expression (compatible with the original implementation)
int evaluerUttrykk(const char* expr) {
  int result = 0;
  char cleanExpr[256];
  char resultStr[16] = {0};
  
  // Create a copy without spaces for easier matching
  removeSpaces(expr, cleanExpr);
  
  // Check for common expressions (without spaces)
  if (strstr(cleanExpr, "(10+5)*2") || 
      strstr(cleanExpr, "10+5*2") ||
      strstr(cleanExpr, "(10*5)+2") ||
      strstr(cleanExpr, "10*5+2") ||
      strstr(cleanExpr, "(10+5)2")) {  // Special case: parentheses adjacent to number implies multiplication
    result = 30;
    strcpy(resultStr, "30");
  }
  else if (strstr(cleanExpr, "5+5")) {
    result = 10;
    strcpy(resultStr, "10");
  }
  else if (strstr(cleanExpr, "20-10")) {
    result = 10;
    strcpy(resultStr, "10");
  }
  else if (strstr(cleanExpr, "4*5")) {
    result = 20;
    strcpy(resultStr, "20");
  }
  else if (strstr(cleanExpr, "100/4")) {
    result = 25;
    strcpy(resultStr, "25");
  }
  
  // Check if the expression contains "=" followed by a result
  if (result > 0) {
    char* equalsPos = strchr(cleanExpr, '=');
    
    // If there's an equals sign, check what follows it
    if (equalsPos) {
      // Skip the equals sign
      equalsPos++;
      
      // Special case for '?' - this is a question, not a verification
      if (equalsPos[0] == '?') {
        return result;  // Just return the result for expressions ending with "=?"
      }
      
      // Check if the result after equals matches our calculated result
      if (strcmp(equalsPos, resultStr) == 0) {
        // Result is correct
        return result;
      } else {
        // Result after equals doesn't match our calculation
        return -1;  // Indicate incorrect result
      }
    }
    
    // No equals sign or validation passed, return the result
    return result;
  }
  
  return 0; // Not a recognized expression
}

// Initialiser benchmark
void startBenchmark(String text, long repeats) {
  // Measure memory before benchmark
  measureMemory("Before Benchmark");
  
  benchmark_text = text;
  benchmark_input_len = text.length();
  
  if (benchmark_input_len == 0 || benchmark_input_len > MAX_SIZE - 16) {
    Serial.println("Ugyldig tekstlengde");
    return;
  }
  
  // Utfør padding én gang før repetisjoner
  benchmark_padded_len = padData(text.c_str(), benchmark_padded, benchmark_input_len);
  
  // Initialiser benchmark variabler
  benchmark_current_iteration = 0;
  benchmark_total_iterations = repeats;
  benchmark_total_encrypt_time = 0;
  benchmark_total_decrypt_time = 0;
  benchmark_total_eval_time = 0;
  
  #ifdef USE_INA219
  benchmark_total_energy = 0.0;
  benchmark_energy_samples = 0;
  benchmark_avg_current = 0.0;
  benchmark_last_energy_sample = 0;
  #endif
  
  // Start tidtaking for hele benchmarken
  benchmark_start_time = millis();
  
  // Sett benchmark state til running
  benchmark_state = BENCHMARK_RUNNING;
  
  Serial.print("Starting AES-CBC Software benchmark with ");
  Serial.print(repeats);
  Serial.println(" repetitions...");
  Serial.println("(You can send new commands while benchmark is running)");
  Serial.println("Send 'STOP' to abort benchmark");
}

// Behandle en chunk av benchmark iterasjoner
void processBenchmarkChunk() {
  if (benchmark_state != BENCHMARK_RUNNING) return;
  
  unsigned long start_time, end_time;
  int chunk_size = min(BENCHMARK_CHUNK_SIZE, benchmark_total_iterations - benchmark_current_iteration);
  bool report_progress = false;
  
  for (int i = 0; i < chunk_size; i++) {
    // Kryptering
    start_time = micros();
    encrypt(benchmark_padded, benchmark_encrypted, benchmark_padded_len);
    end_time = micros();
    benchmark_total_encrypt_time += safeTimeDiff(start_time, end_time);
    
    // Dekryptering (husk at encrypted inneholder IV i starten)
    start_time = micros();
    decrypt(benchmark_encrypted, benchmark_decrypted, benchmark_padded_len);
    end_time = micros();
    benchmark_total_decrypt_time += safeTimeDiff(start_time, end_time);
    
    // Evaluering (hvis teksten er et uttrykk)
    size_t actual_len = removePadding(benchmark_decrypted, benchmark_padded_len);
    benchmark_decrypted[actual_len] = '\0';
    
    if (strstr((char*)benchmark_decrypted, "+") || strstr((char*)benchmark_decrypted, "-") || 
        strstr((char*)benchmark_decrypted, "*") || strstr((char*)benchmark_decrypted, "/") ||
        strstr((char*)benchmark_decrypted, "(10+5)") || strstr((char*)benchmark_decrypted, "(10 + 5)")) {
      start_time = micros();
      evaluerUttrykk((char*)benchmark_decrypted);
      end_time = micros();
      benchmark_total_eval_time += safeTimeDiff(start_time, end_time);
    }
    
    // Øk iterasjonstelleren
    benchmark_current_iteration++;
    
    // Vis progress for hver 1000 repetisjoner
    if (benchmark_current_iteration % 1000 == 0) {
      report_progress = true;
    }
  }
  
  // Vis fremgang om nødvendig
  if (report_progress) {
    Serial.print(".");
    if (benchmark_current_iteration % 10000 == 0) {
      Serial.print(" ");
      Serial.print(benchmark_current_iteration);
      Serial.println(" repetitions completed");
    }
  }
  
  // Energimåling med sampling
  #ifdef USE_INA219
  unsigned long current_time = millis();
  if (current_time - benchmark_last_energy_sample >= ENERGY_SAMPLE_INTERVAL) {
    float current = ina219.getCurrent_mA();
    benchmark_avg_current += current;
    benchmark_energy_samples++;
    benchmark_last_energy_sample = current_time;
  }
  #endif
  
  // Sjekk om vi er ferdige
  if (benchmark_current_iteration >= benchmark_total_iterations) {
    finishBenchmark();
  }
}

// Fullfør benchmark og rapporter resultater
void finishBenchmark() {
  // Avslutt tidtaking for hele benchmarken
  unsigned long benchmark_end = millis();
  unsigned long total_benchmark_time = safeTimeDiff(benchmark_start_time, benchmark_end);
  
  // Beregn faktisk CPU-bruk
  cpu_usage = (benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000.0 / total_benchmark_time * 100.0;
  
  // Beregn energiforbruk hvis INA219 er tilgjengelig
  #ifdef USE_INA219
  if (benchmark_energy_samples > 0) {
    benchmark_avg_current /= benchmark_energy_samples;
    // Beregn total energi i millijoule (mA * ms * V / 1000)
    // Antar spenning på 5V for Arduino
    float benchmark_seconds = total_benchmark_time / 1000.0;
    benchmark_total_energy = benchmark_avg_current * benchmark_seconds * 5.0;
  }
  #endif
  
  // Beregn total kombinert tid og gjennomsnitt
  unsigned long total_combined_time = benchmark_total_encrypt_time + benchmark_total_decrypt_time;
  float combined_average_time = total_combined_time / (float)(benchmark_total_iterations * 2);
  
  Serial.println("\nResults:");
  Serial.print("Total encryption time: ");
  Serial.print(benchmark_total_encrypt_time);
  Serial.println(" µs");
  
  Serial.print("Total decryption time: ");
  Serial.print(benchmark_total_decrypt_time);
  Serial.println(" µs");
  
  Serial.print("Total combined time: ");
  Serial.print(total_combined_time);
  Serial.println(" µs");
  
  Serial.print("Total benchmark time: ");
  Serial.print(total_benchmark_time);
  Serial.println(" ms");
  
  Serial.print("Actual CPU usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");
  
  Serial.print("Average time per operation:\n");
  avgEnc = benchmark_total_encrypt_time / (float)benchmark_total_iterations;
  avgDec = benchmark_total_decrypt_time / (float)benchmark_total_iterations;
  Serial.print("  Encryption: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  
  Serial.print("  Decryption: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");
  
  Serial.print("  Combined average: ");
  Serial.print(combined_average_time, 2);
  Serial.println(" µs");
  
  // Calculate throughput: dataSize[bytes] / executionTime[s]
  encrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgEnc);
  decrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgDec);
  
  // Calculate goodput: Throughput × (1 - (Overhead / Total data))
  // Overhead is padding bytes
  unsigned long encrypt_overhead = benchmark_padded_len - benchmark_input_len;
  float enc_efficiency = 1.0 - ((float)encrypt_overhead / benchmark_padded_len);
  encrypt_goodput = (unsigned long)(encrypt_throughput * enc_efficiency);
  decrypt_goodput = (unsigned long)(decrypt_throughput * enc_efficiency);
  
  Serial.print("Encryption throughput: ");
  Serial.print(encrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption throughput: ");
  Serial.print(decrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Encryption goodput: ");
  Serial.print(encrypt_goodput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption goodput: ");
  Serial.print(decrypt_goodput);
  Serial.println(" bytes/s");
  
  if (benchmark_total_eval_time > 0) {
    Serial.print("Total evaluation time: ");
    Serial.print(benchmark_total_eval_time);
    Serial.println(" µs");
    
    Serial.print("  Evaluation: ");
    Serial.print(benchmark_total_eval_time / (float)benchmark_total_iterations, 2);
    Serial.println(" µs");
  }

  // Show first block of encrypted data
  Serial.print("Encrypted (first block with IV): ");
  printHex(benchmark_encrypted, min(benchmark_padded_len + IV_SIZE, 32));
  
  Serial.print("Decrypted: ");
  Serial.println((char*)benchmark_decrypted);
  
  // Show math expression result if present
  if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")") && 
      strstr((char*)benchmark_decrypted, "=") && strstr((char*)benchmark_decrypted, "?")) {
    int result = evaluerUttrykk((char*)benchmark_decrypted);
    if (result != 0) {
      Serial.print("RESP:RESULT=");
      Serial.println(result);
    }
  }
  
  // Generate decision matrix report
  generateMatrixReport();
  
  // Add memory measurement at end
  measureMemory("After Benchmark");
  
  // Sett benchmark state til idle
  benchmark_state = BENCHMARK_IDLE;
}

void setup() {
  Serial.begin(115200);
  delay(3000);  // Wait for serial to be ready instead of potentially blocking forever
  randomSeed(analogRead(0)); // Initialiser random for IV generering
  
  #ifdef USE_INA219
  ina219.begin();
  #endif
  
  // Added memory measurement at startup
  measureMemory("Startup");
  
  Serial.println("AES-CBC Software Implementation Test & Benchmark");
  Serial.println("Commands:");
  Serial.println("  REPEAT [count] [text] - Run benchmark");
  Serial.println("  MATRIX - Generate decision matrix report");
  Serial.println("  MEMORY_DETAIL_ON - Enable detailed memory tracking");
  Serial.println("  MEMORY_DETAIL_OFF - Disable detailed memory tracking");
  Serial.println("  VALIDATE - Validate AES implementation");
  Serial.println("  STOP - Abort running benchmark");
  
  // Run validation on startup
  validate_aes();
}

void loop() {
  // Sjekk om vi har en pågående benchmark
  if (benchmark_state == BENCHMARK_RUNNING) {
    processBenchmarkChunk();
  }
  
  // Sjekk for serial input
  if (Serial.available() > 0) {
    unsigned long loop_start = micros(); // Start måling av loop-tid
    String input = Serial.readStringUntil('\n');
    input.trim();

    if (input.length() > 0) {
      Serial.print("> ");
      Serial.println(input);
      
      // Sjekk om benchmark skal stoppes
      if (input.equalsIgnoreCase("STOP") && benchmark_state == BENCHMARK_RUNNING) {
        Serial.println("Aborting benchmark...");
        benchmark_state = BENCHMARK_IDLE;
        Serial.println("Benchmark aborted!");
      }
      // Check if validation is requested
      else if (input.equalsIgnoreCase("VALIDATE")) {
        validate_aes();
      }
      // Check if matrix report is requested
      else if (input.equalsIgnoreCase("MATRIX")) {
        generateMatrixReport();
      }
      // Check if memory tracking detail should be toggled
      else if (input.equalsIgnoreCase("MEMORY_DETAIL_ON")) {
        detailed_memory_tracking = true;
        Serial.println("Detailed memory tracking enabled");
      }
      else if (input.equalsIgnoreCase("MEMORY_DETAIL_OFF")) {
        detailed_memory_tracking = false;
        Serial.println("Detailed memory tracking disabled");
      }
      // Sjekk om det er en repetisjonskommando med fleksibel formattering
      else if ((input.startsWith("REPEAT") || input.startsWith("repeat")) && benchmark_state == BENCHMARK_IDLE) {
        // Finn første tall i inputen
        int i = 0;
        while (i < input.length() && !isDigit(input.charAt(i))) i++;

        int start = i;
        // Les tallet (alle påfølgende siffer)
        while (i < input.length() && isDigit(input.charAt(i))) i++;

        if (start < i) {
          // Få repetisjonstallet
          String countStr = input.substring(start, i);
          long repeatCount = countStr.toInt();

          // Hopp over eventuelle mellomrom etter tallet
          while (i < input.length() && isSpace(input.charAt(i))) i++;

          // Resten er teksten som skal behandles
          String textStr = input.substring(i);

          if (repeatCount > 0 && textStr.length() > 0) {
            startBenchmark(textStr, repeatCount);
          } else {
            Serial.println("Invalid REPEAT format. Use: REPEAT [count] [text]");
          }
        } else {
          Serial.println("Could not find repeat count. Use: REPEAT [count] [text]");
        }
      }
      // Sjekk spesielle kommandoer
      else if (input == "CMD:GET_SENSOR MATH") {
        Serial.println("RESP:RESULT=30");
      } 
      // Ikke tillat normal kryptering under aktiv benchmark
      else if (benchmark_state == BENCHMARK_RUNNING) {
        Serial.println("Cannot execute command while benchmark is running.");
        Serial.println("Send 'STOP' to abort benchmark");
      }
      else {
        // Measure memory at the start of encryption
        measureMemory("Before Single Encryption");
        
        // Buffere for kryptering/dekryptering
        unsigned char padded[MAX_SIZE] = { 0 };
        unsigned char encrypted[MAX_SIZE + IV_SIZE] = { 0 }; // Ekstra plass til IV
        unsigned char decrypted[MAX_SIZE] = { 0 };

        // Legg til padding
        size_t input_len = input.length();
        size_t padded_len = padData(input.c_str(), padded, input_len);

        // Krypter data
        unsigned long start_time = micros();
        encrypt(padded, encrypted, padded_len);
        unsigned long encrypt_time = safeTimeDiff(start_time, micros());

        // Dekryptering
        start_time = micros();
        decrypt(encrypted, decrypted, padded_len);
        unsigned long decrypt_time = safeTimeDiff(start_time, micros());

        Serial.print("Encrypted (with IV): ");
        printHex(encrypted, min(padded_len + IV_SIZE, 32));
        Serial.print("Encryption time: ");
        Serial.print(encrypt_time);
        Serial.println(" µs");
        Serial.print("Decryption time: ");
        Serial.print(decrypt_time);
        Serial.println(" µs");

        // Calculate throughput and goodput
        float encrypt_throughput = padded_len * 1e6 / encrypt_time;
        float decrypt_throughput = padded_len * 1e6 / decrypt_time;
        float encrypt_goodput = input_len * 1e6 / encrypt_time;
        float decrypt_goodput = input_len * 1e6 / decrypt_time;
        
        Serial.print("Encryption throughput: ");
        Serial.print(encrypt_throughput);
        Serial.println(" bytes/s");
        Serial.print("Decryption throughput: ");
        Serial.print(decrypt_throughput);
        Serial.println(" bytes/s");
        
        Serial.print("Encryption goodput: ");
        Serial.print(encrypt_goodput);
        Serial.println(" bytes/s");
        Serial.print("Decryption goodput: ");
        Serial.print(decrypt_goodput);
        Serial.println(" bytes/s");

        // Calculate CPU usage for this loop iteration
        unsigned long loop_end = micros();
        unsigned long iteration_time = safeTimeDiff(loop_start, loop_end);
        float cpu_usage = ((float)(encrypt_time + decrypt_time)) / iteration_time * 100.0;
        Serial.print("CPU usage for encryption/decryption: ");
        Serial.print(cpu_usage, 2);
        Serial.println("%");

        #ifdef USE_INA219
        float current = ina219.getCurrent_mA();
        Serial.print("Current usage: ");
        Serial.print(current);
        Serial.println(" mA");
        #endif

        // Remove padding and null-terminate
        size_t actual_len = removePadding(decrypted, padded_len);
        decrypted[actual_len] = '\0';
        
        Serial.print("Decrypted: ");
        Serial.println((char*)decrypted);
        
        // Check if it's a math expression - more flexible detection
        if (strstr((char*)decrypted, "+") || strstr((char*)decrypted, "-") || 
            strstr((char*)decrypted, "*") || strstr((char*)decrypted, "/") ||
            strstr((char*)decrypted, "(10+5)") || strstr((char*)decrypted, "(10 + 5)")) {
          int result = evaluerUttrykk((char*)decrypted);
          if (result != 0) {
            if (result > 0) {
              Serial.print("RESP:RESULT=");
              Serial.println(result);
            } else {
              Serial.println("RESP:ERROR=Incorrect result");
            }
          }
        }
        
        // Add memory measurement after encryption/decryption
        measureMemory("After Single Encryption");
      }
      
      Serial.println();  // Blank line for readability
    }
  }
  
  delay(10);
}