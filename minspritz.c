/*
 * minspritz: A portable implementation of the Spritz cypher in C.
 * Currently untested alpha code, not to be considered for any serious use. 
 * Written for leigibility over speed.
 *
 * Based on pseudocode in:
 * "Spritz—a spongy RC4-like stream cipher and hash function" Rivest, Schuldt
 * https://people.csail.mit.edu/rivest/pubs/RS14.pdf
 *
 * Copyright Chris Hemingway 2015
 * License: BSD
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 256

/* Only apply for N = 256 */
#define LOW(b)     (b&0x0f)
#define HIGH(b)    ((b>>4)&0x0f)


/* Full definition of state structure */
struct minspritz_s {
    uint8_t i, j, k, z, a, w;
    uint8_t S[N];
};

/* Internal Functions */
static void initialise_state(struct minspritz_s *q);
static void shuffle(struct minspritz_s *q);
static void absorb(struct minspritz_s *q, const uint8_t *i, size_t i_len);
static void absorb_nibble(struct minspritz_s *q, uint8_t x);
static void whip(struct minspritz_s *q, int r);
static void crush(struct minspritz_s *q);
static uint8_t *squeeze(struct minspritz_s *q, int r);
static uint8_t drip(struct minspritz_s *q);
static void update(struct minspritz_s *q);
static uint8_t output(struct minspritz_s *q);


void initialise_state(struct minspritz_s *q) {
    int v;

    q->i = 0;
    q->j = 0;
    q->k = 0;
    q->z = 0;
    q->a = 0;
    q->w = 1;

    for (v=0; v<N; v++) {
        q->S[v] = v;
    }
}

void absorb(struct minspritz_s *q, const uint8_t *i, size_t i_len) {
    int v;

    for (v=0; v<i_len; v++) {
        /* Here we deviate from the pseudocode by replacing absorb_byte(b) */
        absorb_nibble(q,LOW(i[v]));
        absorb_nibble(q,HIGH(i[v]));
    }
}

void absorb_nibble(struct minspritz_s *q, uint8_t x) {
    uint8_t temp;

    if (q->a == N/2) {
        shuffle(q);
    }
    /* SWAP(S[a],S[⌊N/2⌋+x]) */
    /* We do not need to %N S[(N/2)+x] for any value of N > 32 */
    temp = q->S[(q->a)%N];
    q->S[(q->a)%N] = q->S[(N/2) + x];
    q->S[(N/2) + x] = temp;

    q->a += 1;
}

void absorb_stop(struct minspritz_s *q) {
    if (q->a == N/2) {
        shuffle(q);
    }
    q->a += 1;
}

void shuffle(struct minspritz_s *q) {
    whip(q, 2*N);
    crush(q);
    whip(q, 2*N);
    crush(q);
    whip(q, 2*N);
    q->a = 0;
}

void whip(struct minspritz_s *q, int r) {
    int v;

    for (v=0; v<r; v++) {
        update(q);
    }
    /* When N is a power of two, the last two lines of the Whip code in Figure 2 are equivalent to w = w + 2. */
    #if N==256
        q->w += 2;
    #else
        #error "N!=256 Not Implemented!"
    #endif
}

void crush(struct minspritz_s *q) {
    int v;

    /* As v is only 0 to N, we do not need to modulo N the index here */
    for (v=0; v<N/2; v++) {
        if ( q->S[v] > q->S[N - 1 - v]) {
            uint8_t temp;
            temp = q->S[v];
            q->S[v] = q->S[N - 1 - v];
            q->S[N - 1 - v] = temp;
        }
    }
}

uint8_t *squeeze(struct minspritz_s *q, int r) {
    int v;
    uint8_t *p;

    if (q->a > 0) {
        shuffle(q);
    }

    p = (uint8_t *)malloc(r * sizeof(uint8_t));

    for (v=0; v<r; v++) {
        p[v] = drip(q);
    }
    return p;
}

uint8_t drip(struct minspritz_s *q) {
    if (q->a > 0) {
        shuffle(q);
    }
    update(q);
    return output(q);
}

void update(struct minspritz_s *q) {
    uint8_t temp;

    q->i = q->i + q->w;
    q->j = q->k + q->S[(q->j + q->S[q->i])%N];
    q->k = q->i + q->k + q->S[(q->j)%N];

    temp = q->S[(q->i)%N];
    q->S[(q->i)%N] = q->S[(q->j)%N];
    q->S[(q->j)%N] = temp;
}

uint8_t output(struct minspritz_s *q) {
    /* z = S[j+S[i+S[z+k]]] */
    q->z = q->S[(q->j + q->S[ (q->i + q->S[(q->z+q->k)%N])%N])%N];
    return q->z;
}

uint8_t *minspritz_hash(uint8_t *m, size_t m_len, uint8_t r) {
    struct minspritz_s q;

    initialise_state(&q);
    absorb(&q,m,m_len); absorb_stop(&q);
    absorb(&q,&r,1); /* TODO: Make r adaptable */
    return squeeze(&q, r);
}

/* Fixme: Incorrect Output! */
uint8_t *minminspritz_stream(uint8_t *m, size_t m_len) {
    struct minspritz_s q;

    initialise_state(&q);
    absorb(&q,m,m_len);
    return squeeze(&q, 32);
}


void print_hex(uint8_t *bytes, size_t len) {
    int i;
    for (i=0; i<len; i++) {
        printf("%02X",bytes[i]);
    }
    putchar('\n');
}

int main(int argc, char *argv[]) {
    /* Test vectors from Section E */
    char in1[] = "ABC";
    char in2[] = "spam";
    char in3[] = "arcfour";
    uint8_t *res;

    res = minspritz_hash((uint8_t *)in1, strlen(in1), 32);
    print_hex(res,32);

    res = minspritz_hash((uint8_t *)in2, strlen(in2), 32);
    print_hex(res,32);

    res = minspritz_hash((uint8_t *)in3, strlen(in3), 32);
    print_hex(res,32);

}