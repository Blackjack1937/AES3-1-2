#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "aes-128_enc.h"

void next_aes128_round_key(const uint8_t prev_key[16], uint8_t next_key[16], int round);
void prev_aes128_round_key(const uint8_t next_key[16], uint8_t prev_key[16], int round);

static uint32_t xs=0x12345678u;
static uint32_t rnd32(void){ xs^=xs<<13; xs^=xs>>17; xs^=xs<<5; return xs; }

int main(void)
{
    for (int t = 0; t < 10000; ++t) {
        uint8_t k[16], n[16], p[16], n2[16];

        for (int i=0;i<16;i++) k[i] = (uint8_t)(rnd32() & 0xFF);

        for (int round=0; round<10; ++round) {
            next_aes128_round_key(k, n, round);
            prev_aes128_round_key(n, p, round);
            if (memcmp(k, p, 16) != 0) {
                fprintf(stderr, "Mismatch: prev(next(k)) != k at round %d\n", round);
                return 1;
            }

            prev_aes128_round_key(n, p, round);
            next_aes128_round_key(p, n2, round);
            if (memcmp(n, n2, 16) != 0) {
                fprintf(stderr, "Mismatch: next(prev(n)) != n at round %d\n", round);
                return 2;
            }
            memcpy(k, n, 16);
        }
    }
    puts("Key schedule inversion tests: OK");
    return 0;
}
