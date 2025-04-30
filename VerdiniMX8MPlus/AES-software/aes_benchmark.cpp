// AES-CBC Software Implementation (Linux-compatible version for Toradex Verdin)
// Removed Arduino-specific code and replaced with standard C++
// Usage: ./aes_benchmark <repeats> "your text"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <chrono>
#include <random>
#include "aes_core.cpp"

using namespace std;
using namespace std::chrono;

#define AES_BLOCK_SIZE 16
#define AES_ROUNDS 10
#define AES_ROUND_KEY_SIZE 176
#define IV_SIZE 16

const unsigned char aes_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

unsigned long micros()
{
    return duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

unsigned long safeTimeDiff(unsigned long start, unsigned long end)
{
    return (end >= start) ? (end - start) : (ULONG_MAX - start + end + 1);
}

void generateIV(unsigned char *iv)
{
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < IV_SIZE; i++)
        iv[i] = dis(gen);
}

size_t padData(const char *input, unsigned char *output, size_t len)
{
    size_t padded_len = ((len + 15) / 16) * 16;
    memcpy(output, input, len);
    unsigned char pad_value = padded_len - len;
    for (size_t i = len; i < padded_len; i++)
        output[i] = pad_value;
    return padded_len;
}

void printHex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
    cout << dec << endl;
}

// Forward declare AES functions
void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);
void AES_CBC_encrypt(struct AES_ctx *ctx, uint8_t *iv, uint8_t *buf, uint32_t length);
void AES_CBC_decrypt(struct AES_ctx *ctx, uint8_t *iv, uint8_t *buf, uint32_t length);

#include "aes_core.cpp" // Contains full AES_ctx, sbox, and all AES-related functions

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cerr << "Usage: " << argv[0] << " <repeats> \"text to encrypt\"" << endl;
        return 1;
    }

    long repeats = atol(argv[1]);
    string input_text = argv[2];

    unsigned char padded[256] = {0};
    unsigned char encrypted[256 + IV_SIZE] = {0};
    unsigned char decrypted[256] = {0};

    size_t input_len = input_text.length();
    size_t padded_len = padData(input_text.c_str(), padded, input_len);

    AES_ctx ctx;
    AES_init_ctx(&ctx, aes_key);

    unsigned long total_encrypt = 0;
    unsigned long total_decrypt = 0;

    for (int i = 0; i < repeats; ++i)
    {
        unsigned char iv[IV_SIZE];
        generateIV(iv);

        memcpy(encrypted + IV_SIZE, padded, padded_len);
        memcpy(encrypted, iv, IV_SIZE);

        unsigned long start_enc = micros();
        AES_CBC_encrypt(&ctx, iv, encrypted + IV_SIZE, padded_len);
        unsigned long end_enc = micros();
        total_encrypt += safeTimeDiff(start_enc, end_enc);

        memcpy(iv, encrypted, IV_SIZE);
        memcpy(decrypted, encrypted + IV_SIZE, padded_len);

        unsigned long start_dec = micros();
        AES_CBC_decrypt(&ctx, iv, decrypted, padded_len);
        unsigned long end_dec = micros();
        total_decrypt += safeTimeDiff(start_dec, end_dec);
    }

    float avgEnc = total_encrypt / (float)repeats;
    float avgDec = total_decrypt / (float)repeats;

    cout << "\n=== AES-CBC Benchmark Results ===" << endl;
    cout << "Input: \"" << input_text << "\" (" << input_len << " bytes, padded to " << padded_len << ")" << endl;
    cout << "Avg Encrypt Time: " << avgEnc << " µs" << endl;
    cout << "Avg Decrypt Time: " << avgDec << " µs" << endl;
    cout << "Throughput Encrypt: " << (padded_len * 1e6 / avgEnc) << " bytes/s" << endl;
    cout << "Throughput Decrypt: " << (padded_len * 1e6 / avgDec) << " bytes/s" << endl;
    cout << "Decrypted text: " << string((char *)decrypted, input_len) << endl;

    return 0;
}
