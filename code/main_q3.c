#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "aes-128_enc.h"

static void aes3_enc(uint8_t b[16], const uint8_t k[16]) {
    aes128_enc(b, k, 3u, 1);
}



static void F_eval(uint8_t out[16], const uint8_t k1[16], const uint8_t k2[16], const uint8_t x[16]) {
    uint8_t t1[16], t2[16];
    memcpy(t1, x, 16);
    memcpy(t2, x, 16);
    aes3_enc(t1, k1);
    aes3_enc(t2, k2);
    for (int i = 0; i < 16; ++i) out[i] = (uint8_t)(t1[i] ^ t2[i]);
}

static uint32_t xs = 0xC0FFEE11u;

static uint32_t rnd32(void){ xs^=xs<<13; xs^=xs>>17; xs^=xs<<5; return xs; }
static void rnd_bytes(uint8_t *p, size_t n){ for (size_t i=0;i<n;i++) p[i]=(uint8_t)(rnd32()&0xFF); }

static void build_lambda_set(uint8_t P[256][16], int pos, uint8_t c) {
    for (int v = 0; v < 256; ++v) {
        for (int i = 0; i < 16; ++i) P[v][i] = c;
        P[v][pos] = (uint8_t)v;
    }
}


static void lambda_xor_under_F(uint8_t acc[16], const uint8_t k1[16], const uint8_t k2[16], int pos, uint8_t c) {
    uint8_t P[256][16], y[16];
    memset(acc, 0, 16);
    build_lambda_set(P, pos, c);
    for (int v = 0; v < 256; ++v) {
        F_eval(y, k1, k2, P[v]);
        for (int i = 0; i < 16; ++i) acc[i] ^= y[i];
    }
}

static int is_all_zero(const uint8_t a[16]) {
    uint8_t t = 0;
    for (int i = 0; i < 16; ++i) t |= a[i];
    return t == 0;
}

int main(void)
{
    uint8_t k1[16], k2[16];
    rnd_bytes(k1, 16);
    do { rnd_bytes(k2, 16); } while (memcmp(k1, k2, 16) == 0);

    {
        uint8_t out[16], x[16] = {0};
        F_eval(out, k1, k1, x);
        int zero = is_all_zero(out);
        printf("[check] With k1==k2, F(x) is %s (should be all zeros)\n", zero ? "all-zero" : "NON-zero");
    }

    int trials = 100;                 
    int passes = 0;
    for (int t = 0; t < trials; ++t) {
        int pos = t % 16;          
        uint8_t c = (uint8_t)(t * 17);
        uint8_t acc[16];
        lambda_xor_under_F(acc, k1, k2, pos, c);
        if (is_all_zero(acc)) ++passes;
        else {
            printf("[FAIL] Λ-XOR not zero at trial %d, pos=%d\n", t, pos);
            printf(" acc =");
            for (int i=0;i<16;i++) printf(" %02x", acc[i]);
            printf("\n");
            return 1;
        }
    }
    printf("Square distinguisher for F: %d/%d trials balanced to zero. OK.\n", passes, trials);
    return 0;
}
