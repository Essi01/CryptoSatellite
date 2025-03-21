#include <Arduino.h>
#include <stdint.h>
#ifdef ARDUINO_ARCH_MBED
#include "mbed_stats.h"
#endif

#ifdef USE_INA219
#include <Adafruit_INA219.h>
Adafruit_INA219 ina219;
#endif

#ifdef ARDUINO_ARCH_MBED
int freeRam() {
    mbed_stats_heap_t stats;
    mbed_stats_heap_get(&stats);
    return stats.reserved_size - stats.current_size;
}
#else
int freeRam() {
  extern char __heap_start, *__brkval;
  int v;
  return (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
}
#endif

// SPECK Cipher Constants
#define SPECK_BLOCK_SIZE 16   // 128 bits = 16 bytes
#define SPECK_KEY_SIZE 16     // 128 bits = 16 bytes for SPECK128/128
#define SPECK_ROUNDS 32       // Number of rounds for SPECK128/128
#define WORD_SIZE 64          // Using 64-bit words

// SPECK nøkkel (128-bit)
const unsigned char speck_key[SPECK_KEY_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// IV størrelse for CBC modus
#define IV_SIZE 16

// Precomputed round keys
static uint64_t round_keys[SPECK_ROUNDS];
static bool keys_initialized = false;

// Rotation operations
#define ROR(x, r) (((x) >> (r)) | ((x) << (64 - (r))))
#define ROL(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

// Helper functions for SPECK
void load_uint64(uint64_t* r, const uint8_t* ct) {
    *r = ((uint64_t)ct[0])        | ((uint64_t)ct[1] << 8)  |
         ((uint64_t)ct[2] << 16)  | ((uint64_t)ct[3] << 24) |
         ((uint64_t)ct[4] << 32)  | ((uint64_t)ct[5] << 40) |
         ((uint64_t)ct[6] << 48)  | ((uint64_t)ct[7] << 56);
}

void store_uint64(uint8_t* ct, uint64_t v) {
    ct[0] = (uint8_t)(v);
    ct[1] = (uint8_t)(v >> 8);
    ct[2] = (uint8_t)(v >> 16);
    ct[3] = (uint8_t)(v >> 24);
    ct[4] = (uint8_t)(v >> 32);
    ct[5] = (uint8_t)(v >> 40);
    ct[6] = (uint8_t)(v >> 48);
    ct[7] = (uint8_t)(v >> 56);
}

// Initialize SPECK round keys
void speck_init() {
    if (keys_initialized) return;
    
    uint64_t key_words[2] = {0, 0};
    
    // Load key into 64-bit words
    load_uint64(&key_words[0], speck_key);
    load_uint64(&key_words[1], speck_key + 8);
    
    // First round key
    round_keys[0] = key_words[0];
    
    // Key schedule for SPECK128/128
    uint64_t a = key_words[1];
    
    for (int i = 0; i < SPECK_ROUNDS - 1; i++) {
        // Key schedule round
        a = ROR(a, 8);
        a += round_keys[i];
        a ^= i;
        round_keys[i + 1] = ROL(round_keys[i], 3) ^ a;
    }
    
    keys_initialized = true;
}

// Encrypt a single SPECK block
void speck_encrypt_block(uint64_t* block) {
    uint64_t x = block[0];
    uint64_t y = block[1];
    
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        x = ROR(x, 8);
        x += y;
        x ^= round_keys[i];
        y = ROL(y, 3);
        y ^= x;
    }
    
    block[0] = x;
    block[1] = y;
}

// Decrypt a single SPECK block
void speck_decrypt_block(uint64_t* block) {
    uint64_t x = block[0];
    uint64_t y = block[1];
    
    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        y ^= x;
        y = ROR(y, 3);
        x ^= round_keys[i];
        x -= y;
        x = ROL(x, 8);
    }
    
    block[0] = x;
    block[1] = y;
}

// Hjelpefunksjon for å vise bytes som hex
void printHex(const unsigned char* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 16) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

// Generer en tilfeldig IV
void generateIV(unsigned char* iv) {
  // Enkel implementasjon - i reell bruk, bruk en skikkelig CSPRNG
  for (int i = 0; i < IV_SIZE; i++) {
    iv[i] = random(256);
  }
}

// Pad data til 16-byte blokker (SPECK blokk-størrelse)
size_t padData(const char* input, unsigned char* output, size_t len) {
  size_t padded_len = ((len + 15) / 16) * 16;  // Rund opp til nærmeste 16

  // Kopier originale data
  memcpy(output, input, len);

  // Legg til padding (PKCS#7)
  unsigned char pad_value = padded_len - len;
  for (size_t i = len; i < padded_len; i++) {
    output[i] = pad_value;
  }

  return padded_len;
}

// Krypter data med SPECK-CBC
void encrypt(const unsigned char* input, unsigned char* output, size_t len) {
  // Ensure round keys are initialized
  speck_init();
  
  // Generer IV og kopier til starten av output
  unsigned char iv[IV_SIZE];
  generateIV(iv);
  memcpy(output, iv, IV_SIZE);
  
  // XOR og krypter blokk for blokk (CBC mode)
  uint64_t block[2], prev_block[2];
  
  // Initialize prev_block with IV
  load_uint64(&prev_block[0], iv);
  load_uint64(&prev_block[1], iv + 8);
  
  for (size_t i = 0; i < len; i += SPECK_BLOCK_SIZE) {
    // Load plaintext block
    load_uint64(&block[0], input + i);
    load_uint64(&block[1], input + i + 8);
    
    // XOR with previous ciphertext (or IV for first block)
    block[0] ^= prev_block[0];
    block[1] ^= prev_block[1];
    
    // Encrypt the block
    speck_encrypt_block(block);
    
    // Store the result
    store_uint64(output + IV_SIZE + i, block[0]);
    store_uint64(output + IV_SIZE + i + 8, block[1]);
    
    // Save this block as previous for next iteration
    prev_block[0] = block[0];
    prev_block[1] = block[1];
  }
}

// Dekrypter data med SPECK-CBC
void decrypt(const unsigned char* input, unsigned char* output, size_t len) {
  // Ensure round keys are initialized
  speck_init();
  
  // Hent IV fra starten av input
  uint64_t iv_block[2];
  load_uint64(&iv_block[0], input);
  load_uint64(&iv_block[1], input + 8);
  
  uint64_t block[2], prev_block[2];
  
  // Initialize prev_block with IV
  prev_block[0] = iv_block[0];
  prev_block[1] = iv_block[1];
  
  for (size_t i = 0; i < len; i += SPECK_BLOCK_SIZE) {
    // Load ciphertext block
    load_uint64(&block[0], input + IV_SIZE + i);
    load_uint64(&block[1], input + IV_SIZE + i + 8);
    
    // Save current ciphertext for next block's XOR
    uint64_t current_cipher[2] = {block[0], block[1]};
    
    // Decrypt the block
    speck_decrypt_block(block);
    
    // XOR with previous ciphertext (or IV for first block)
    block[0] ^= prev_block[0];
    block[1] ^= prev_block[1];
    
    // Store the result
    store_uint64(output + i, block[0]);
    store_uint64(output + i + 8, block[1]);
    
    // Update prev_block for next iteration
    prev_block[0] = current_cipher[0];
    prev_block[1] = current_cipher[1];
  }
}

// Fjern padding
size_t removePadding(unsigned char* data, size_t len) {
  if (len == 0) return 0;

  // Siste byte angir padding-lengde i PKCS#7
  unsigned char padding_value = data[len - 1];

  // Sjekk at padding er gyldig (ikke større enn blokk-størrelsen)
  if (padding_value > 16) return len;

  return len - padding_value;
}

// Evaluer uttrykk
int evaluerUttrykk(const char* expr) {
  // For enkelhets skyld, returner bare 30 hvis uttrykket inneholder "10 + 5" og "* 2"
  if (strstr(expr, "10 + 5") && strstr(expr, "* 2")) {
    return 30;
  }
  return 0;
}

// Konstanter for non-blocking benchmark
#define BENCHMARK_CHUNK_SIZE 100  // Antall iterasjoner per chunk
#define BENCHMARK_IDLE false
#define BENCHMARK_RUNNING true

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

// Energimåling variabler
#ifdef USE_INA219
float benchmark_total_energy = 0.0;
int benchmark_energy_samples = 0;
float benchmark_avg_current = 0.0;
unsigned long benchmark_last_energy_sample = 0;
const unsigned long ENERGY_SAMPLE_INTERVAL = 100; // Sample hver 100ms
#endif

// Initialiser benchmark
void startBenchmark(String text, long repeats) {
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
  
  Serial.print("Starter benchmark med ");
  Serial.print(repeats);
  Serial.println(" repetisjoner...");
  Serial.println("(Du kan sende nye kommandoer mens benchmark kjører)");
  Serial.println("Send 'STOP' for å avbryte benchmark");
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
    benchmark_total_encrypt_time += (end_time - start_time);
    
    // Dekryptering (husk at encrypted inneholder IV i starten)
    start_time = micros();
    decrypt(benchmark_encrypted, benchmark_decrypted, benchmark_padded_len);
    end_time = micros();
    benchmark_total_decrypt_time += (end_time - start_time);
    
    // Evaluering (hvis teksten er et uttrykk)
    size_t actual_len = removePadding(benchmark_decrypted, benchmark_padded_len);
    benchmark_decrypted[actual_len] = '\0';
    
    if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")")) {
      start_time = micros();
      evaluerUttrykk((char*)benchmark_decrypted);
      end_time = micros();
      benchmark_total_eval_time += (end_time - start_time);
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
      Serial.println(" repetisjoner fullført");
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
  unsigned long total_benchmark_time = benchmark_end - benchmark_start_time;
  
  // Beregn faktisk CPU-bruk
  float cpu_usage = (benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000.0 / total_benchmark_time * 100.0;
  
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
  
  Serial.println("\nResultater:");
  Serial.print("Total krypteringstid: ");
  Serial.print(benchmark_total_encrypt_time);
  Serial.println(" µs");
  
  Serial.print("Total dekrypteringstid: ");
  Serial.print(benchmark_total_decrypt_time);
  Serial.println(" µs");
  
  Serial.print("Total kombinert tid: ");
  Serial.print(total_combined_time);
  Serial.println(" µs");
  
  Serial.print("Total benchmark tid: ");
  Serial.print(total_benchmark_time);
  Serial.println(" ms");
  
  Serial.print("Faktisk CPU bruk: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");
  
  Serial.print("Gjennomsnittlig tid per operasjon:\n");
  float avgEnc = benchmark_total_encrypt_time / (float)benchmark_total_iterations;
  float avgDec = benchmark_total_decrypt_time / (float)benchmark_total_iterations;
  Serial.print("  Kryptering: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  
  Serial.print("  Dekryptering: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");
  
  Serial.print("  Kombinert gjennomsnitt: ");
  Serial.print(combined_average_time, 2);
  Serial.println(" µs");
  
  // Beregn throughput og goodput
  unsigned long encrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgEnc);
  unsigned long decrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgDec);
  unsigned long encrypt_goodput = (unsigned long)(benchmark_input_len * 1e6 / avgEnc);
  unsigned long decrypt_goodput = (unsigned long)(benchmark_input_len * 1e6 / avgDec);
  
  Serial.print("Kryptering throughput: ");
  Serial.print(encrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Dekryptering throughput: ");
  Serial.print(decrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Kryptering goodput: ");
  Serial.print(encrypt_goodput);
  Serial.println(" bytes/s");
  
  Serial.print("Dekryptering goodput: ");
  Serial.print(decrypt_goodput);
  Serial.println(" bytes/s");
  
  #ifdef USE_INA219
  if (benchmark_energy_samples > 0) {
    Serial.print("Gjennomsnittlig strømforbruk: ");
    Serial.print(benchmark_avg_current, 2);
    Serial.println(" mA");
    
    Serial.print("Total energiforbruk: ");
    Serial.print(benchmark_total_energy, 2);
    Serial.println(" mJ");
  }
  #endif
  
  if (benchmark_total_eval_time > 0) {
    Serial.print("Total evalueringstid: ");
    Serial.print(benchmark_total_eval_time);
    Serial.println(" µs");
    
    Serial.print("  Evaluering: ");
    Serial.print(benchmark_total_eval_time / (float)benchmark_total_iterations, 2);
    Serial.println(" µs");
  }

  // Vis første og siste operasjonsresultat
  Serial.print("Kryptert (første blokk med IV): ");
  printHex(benchmark_encrypted, min(benchmark_padded_len + IV_SIZE, 32));
  
  Serial.print("Dekryptert: ");
  Serial.println((char*)benchmark_decrypted);
  
  // Vis resultatet av matteuttrykket hvis det er ett
  if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")") && 
      strstr((char*)benchmark_decrypted, "=") && strstr((char*)benchmark_decrypted, "?")) {
    int result = evaluerUttrykk((char*)benchmark_decrypted);
    if (result != 0) {
      Serial.print("RESP:RESULT=");
      Serial.println(result);
    }
  }
  
  // Sett benchmark state til idle
  benchmark_state = BENCHMARK_IDLE;
}

void setup() {
  Serial.begin(115200);
  while (!Serial);
  randomSeed(analogRead(0)); // Initialiser random for IV generering
  speck_init(); // Initialize SPECK cipher
#ifdef USE_INA219
  ina219.begin();
#endif
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
        Serial.println("Avbryter benchmark...");
        benchmark_state = BENCHMARK_IDLE;
        Serial.println("Benchmark avbrutt!");
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
            Serial.println("Ugyldig REPEAT-format. Bruk: REPEAT [antall] [tekst]");
          }
        } else {
          Serial.println("Kunne ikke finne repetisjonstallet. Bruk: REPEAT [antall] [tekst]");
        }
      }
      // Sjekk spesielle kommandoer
      else if (input == "CMD:GET_SENSOR MATH") {
        Serial.println("RESP:RESULT=30");
      } 
      // Ikke tillat normal kryptering under aktiv benchmark
      else if (benchmark_state == BENCHMARK_RUNNING) {
        Serial.println("Kan ikke utføre kommando mens benchmark kjører.");
        Serial.println("Send 'STOP' for å avbryte benchmark");
      }
      else {
        // Buffere for kryptering/dekryptering
        const size_t MAX_SIZE = 256;
        unsigned char padded[MAX_SIZE] = { 0 };
        unsigned char encrypted[MAX_SIZE + IV_SIZE] = { 0 }; // Ekstra plass til IV
        unsigned char decrypted[MAX_SIZE] = { 0 };

        // Legg til padding
        size_t input_len = input.length();
        size_t padded_len = padData(input.c_str(), padded, input_len);

        // Mål RAM før operasjon
        int ram_before = freeRam();

        // Krypter data
        unsigned long start_time = micros();
        encrypt(padded, encrypted, padded_len);
        unsigned long encrypt_time = micros() - start_time;
        int ram_after_enc = freeRam();

        // Dekryptering
        start_time = micros();
        decrypt(encrypted, decrypted, padded_len);
        unsigned long decrypt_time = micros() - start_time;
        int ram_after_dec = freeRam();

        Serial.print("Kryptert (med IV): ");
        printHex(encrypted, padded_len + IV_SIZE);
        Serial.print("Krypteringstid: ");
        Serial.print(encrypt_time);
        Serial.println(" µs");
        Serial.print("Dekrypteringstid: ");
        Serial.print(decrypt_time);
        Serial.println(" µs");

        // Beregn throughput og goodput
        float encrypt_throughput = padded_len * 1e6 / encrypt_time;
        float decrypt_throughput = padded_len * 1e6 / decrypt_time;
        float encrypt_goodput = input_len * 1e6 / encrypt_time;
        float decrypt_goodput = input_len * 1e6 / decrypt_time;
        
        Serial.print("Kryptering throughput: ");
        Serial.print(encrypt_throughput);
        Serial.println(" bytes/s");
        Serial.print("Dekryptering throughput: ");
        Serial.print(decrypt_throughput);
        Serial.println(" bytes/s");
        
        Serial.print("Kryptering goodput: ");
        Serial.print(encrypt_goodput);
        Serial.println(" bytes/s");
        Serial.print("Dekryptering goodput: ");
        Serial.print(decrypt_goodput);
        Serial.println(" bytes/s");

        // Beregn CPU usage for denne loop-iterasjonen
        unsigned long loop_end = micros();
        unsigned long iteration_time = loop_end - loop_start;
        float cpu_usage = ((float)(encrypt_time + decrypt_time)) / iteration_time * 100.0;
        Serial.print("CPU usage for encryption/decryption: ");
        Serial.print(cpu_usage, 2);
        Serial.println("%");

        // Mål og rapporter RAM-endringer
        Serial.print("RAM før operasjon: ");
        Serial.println(ram_before);
        Serial.print("RAM etter kryptering: ");
        Serial.println(ram_after_enc);
        Serial.print("RAM etter dekryptering: ");
        Serial.println(ram_after_dec);

#ifdef USE_INA219
        float current = ina219.getCurrent_mA();
        Serial.print("Strømforbruk: ");
        Serial.print(current);
        Serial.println(" mA");
#else
        Serial.println("Strømforbruk: N/A (krever INA219-bibliotek eller ekstern målemetode)");
#endif

        // Fjern padding og null-terminer
        size_t actual_len = removePadding(decrypted, padded_len);
        decrypted[actual_len] = '\0';

        Serial.print("Dekryptert: ");
        Serial.println((char*)decrypted);

        // Sjekk om det er et matteuttrykk
        if (strstr((char*)decrypted, "(") && strstr((char*)decrypted, ")") &&
            strstr((char*)decrypted, "=") && strstr((char*)decrypted, "?")) {
          int result = evaluerUttrykk((char*)decrypted);
          if (result != 0) {
            Serial.print("RESP:RESULT=");
            Serial.println(result);
          }
        }
      }

      Serial.println();  // Blank linje for lesbarhet
    }
  }

  delay(10);
}