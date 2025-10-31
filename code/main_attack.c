#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#if defined(__linux__)
  #include <sys/random.h>
#endif
#include "aes-128_enc.h"

static int get_os_random(uint8_t *dst, size_t n) {
#if defined(__linux__)
    ssize_t r = getrandom(dst, n, 0);
    if (r == (ssize_t)n) return 1;
#endif
 
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t got = 0;
        while (got < n) {
            ssize_t m = read(fd, dst + got, n - got);
            if (m <= 0) break;
            got += (size_t)m;
        }
        close(fd);
        if (got == n) return 1;
    }
 
    uint32_t s = (uint32_t)time(NULL) ^ (uint32_t)getpid() ^ (uint32_t)getppid();
    for (size_t i = 0; i < n; ++i) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        dst[i] = (uint8_t)(s & 0xFF);
    }
    return 1;
}

static uint32_t xs;
static void init_rng(void) {
    uint8_t seed[4];
    get_os_random(seed, sizeof seed);
    xs = ((uint32_t)seed[0] << 24) | ((uint32_t)seed[1] << 16)
       | ((uint32_t)seed[2] <<  8) | ((uint32_t)seed[3]);
    if (xs == 0) xs = 0x9E3779B9u; // avoid zero state
}
static uint32_t rnd32(void){
    xs ^= xs << 13; xs ^= xs >> 17; xs ^= xs << 5;
    return xs;
}
static void rnd_bytes(uint8_t *p, size_t n){
    for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(rnd32() & 0xFF);
}


static void aes35_enc(uint8_t b[16], const uint8_t k[16]) {
    aes128_enc(b, k, 4u, 0);
}


static void build_lambda_set(uint8_t P[256][16], int varying_pos, const uint8_t fixed[16]) {
    for (int v = 0; v < 256; ++v) {
        for (int i = 0; i < 16; ++i) P[v][i] = fixed[i];
        P[v][varying_pos] = (uint8_t)v;
    }
}

static int balanced_for_guess(const uint8_t C[256][16], int byte_index, uint8_t guess) {
    uint8_t acc = 0;
    for (int v = 0; v < 256; ++v) {
        acc ^= Sinv[(uint8_t)(C[v][byte_index] ^ guess)];
    }
    return acc == 0;
}

static void recover_last_round_key(uint8_t lastkey[16], const uint8_t master_key[16]) {
    const int NUM_SETS = 5;           
    const int varying_pos = 0;         //which plaintext byte ranges over 0 255

    uint8_t candidate[16][256];
    for (int j = 0; j < 16; ++j)
        for (int g = 0; g < 256; ++g)
            candidate[j][g] = 1;

    uint8_t fixed[16], P[256][16], C[256][16];

    for (int s = 0; s < NUM_SETS; ++s) {
        // choose a random fixed base for the Λ-set
        rnd_bytes(fixed, 16);

        // build and encrypt Λ-set
        build_lambda_set(P, varying_pos, fixed);
        for (int v = 0; v < 256; ++v) {
            uint8_t b[16]; memcpy(b, P[v], 16);
            aes35_enc(b, master_key); // oracle
            memcpy(C[v], b, 16);
        }

        // update candidates per byte by keeping only guesses that balance to zero
        for (int j = 0; j < 16; ++j) {
            for (int g = 0; g < 256; ++g) {
                if (!candidate[j][g]) continue;
                if (!balanced_for_guess(C, j, (uint8_t)g)) candidate[j][g] = 0;
            }
        }
    }
    for (int j = 0; j < 16; ++j) {
        int found = -1, count = 0;
        for (int g = 0; g < 256; ++g) if (candidate[j][g]) { found = g; ++count; }
        if (count != 1) {
            fprintf(stderr, "[!] Byte %d has %d candidates; increase NUM_SETS or randomize sets more.\n", j, count);
            if (found < 0) found = 0; // fallback
        }
        lastkey[j] = (uint8_t)found;
    }
}


static void invert_to_master_key(uint8_t master_out[16], const uint8_t last_round_key[16]) {
    uint8_t k4[16], k3[16], k2[16], k1[16], k0[16];
    memcpy(k4, last_round_key, 16);

    prev_aes128_round_key(k4, k3, 3); // recover round 3 from 4
    prev_aes128_round_key(k3, k2, 2); // round 2
    prev_aes128_round_key(k2, k1, 1); // round 1
    prev_aes128_round_key(k1, k0, 0); // master (round 0)

    memcpy(master_out, k0, 16);
}




static int verify_recovery(const uint8_t true_key[16], const uint8_t recovered_key[16]) {
    if (memcmp(true_key, recovered_key, 16) == 0) return 1;
    for (int t = 0; t < 8; ++t) {
        uint8_t p[16], c1[16], c2[16];
        rnd_bytes(p, 16);
        memcpy(c1, p, 16); aes35_enc(c1, true_key);
        memcpy(c2, p, 16); aes35_enc(c2, recovered_key);
        if (memcmp(c1, c2, 16) != 0) return 0;
    }
    return 1;
}



static void print_key(const char *label, const uint8_t k[16]) {
    printf("%s", label);
    for (int i = 0; i < 16; ++i) printf("%02x", k[i]);
    printf("\n");
}

int main(void) {
    init_rng();
    uint8_t secret_key[16];
    get_os_random(secret_key, sizeof secret_key);

    uint8_t last_round_key[16], recovered_master[16];

    recover_last_round_key(last_round_key, secret_key);
    invert_to_master_key(recovered_master, last_round_key);

    print_key("Secret master key     : ", secret_key);
    print_key("Recovered master key  : ", recovered_master);
    print_key("Recovered last rnd key: ", last_round_key);

    if (verify_recovery(secret_key, recovered_master)) {
        puts("Key-recovery check: OK");
        return 0;
    } else {
        puts("Key-recovery check: FAILED");
        return 1;
    }
}
