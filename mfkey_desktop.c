#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <signal.h>

// MIFARE Classic key size
#define MF_CLASSIC_KEY_SIZE 6

// Crypto1 constants
#define LF_POLY_ODD  (0x29CE5C)
#define LF_POLY_EVEN (0x870804)
#define CONST_M1_1   (LF_POLY_EVEN << 1 | 1)
#define CONST_M2_1   (LF_POLY_ODD << 1)
#define CONST_M1_2   (LF_POLY_ODD)
#define CONST_M2_2   (LF_POLY_EVEN << 1 | 1)
#define BIT(x, n)    ((x) >> (n) & 1)
#define BEBIT(x, n)  BIT(x, (n) ^ 24)
#define SWAPENDIAN(x) \
    ((x) = ((x) >> 8 & 0xff00ff) | ((x) & 0xff00ff) << 8, (x) = (x) >> 16 | (x) << 16)

// MSB processing chunk size
static int MSB_LIMIT = 16;

// Structures
struct Crypto1State {
    uint32_t odd, even;
};

struct Msb {
    int tail;
    uint32_t states[768];
};

typedef struct {
    uint8_t data[MF_CLASSIC_KEY_SIZE];
} MfClassicKey;

typedef enum {
    mfkey32,
    static_nested,
    static_encrypted
} AttackType;

typedef struct {
    AttackType attack;
    MfClassicKey key;
    uint32_t uid;
    uint32_t nt0;
    uint32_t nt1;
    uint32_t uid_xor_nt0;
    uint32_t uid_xor_nt1;
    union {
        // Mfkey32
        struct {
            uint32_t p64;
            uint32_t p64b;
            uint32_t nr0_enc;
            uint32_t ar0_enc;
            uint32_t nr1_enc;
            uint32_t ar1_enc;
        };
        // Nested
        struct {
            uint32_t ks1_1_enc;
            uint32_t ks1_2_enc;
            char par_1_str[5];
            char par_2_str[5];
            uint8_t par_1;
            uint8_t par_2;
        };
    };
} MfClassicNonce;

// Lookup tables for filter function
static const uint8_t lookup1[256] = {
    0, 0,  16, 16, 0,  16, 0,  0,  0, 16, 0,  0,  16, 16, 16, 16, 0, 0,  16, 16, 0,  16, 0,  0,
    0, 16, 0,  0,  16, 16, 16, 16, 0, 0,  16, 16, 0,  16, 0,  0,  0, 16, 0,  0,  16, 16, 16, 16,
    8, 8,  24, 24, 8,  24, 8,  8,  8, 24, 8,  8,  24, 24, 24, 24, 8, 8,  24, 24, 8,  24, 8,  8,
    8, 24, 8,  8,  24, 24, 24, 24, 8, 8,  24, 24, 8,  24, 8,  8,  8, 24, 8,  8,  24, 24, 24, 24,
    0, 0,  16, 16, 0,  16, 0,  0,  0, 16, 0,  0,  16, 16, 16, 16, 0, 0,  16, 16, 0,  16, 0,  0,
    0, 16, 0,  0,  16, 16, 16, 16, 8, 8,  24, 24, 8,  24, 8,  8,  8, 24, 8,  8,  24, 24, 24, 24,
    0, 0,  16, 16, 0,  16, 0,  0,  0, 16, 0,  0,  16, 16, 16, 16, 0, 0,  16, 16, 0,  16, 0,  0,
    0, 16, 0,  0,  16, 16, 16, 16, 8, 8,  24, 24, 8,  24, 8,  8,  8, 24, 8,  8,  24, 24, 24, 24,
    8, 8,  24, 24, 8,  24, 8,  8,  8, 24, 8,  8,  24, 24, 24, 24, 0, 0,  16, 16, 0,  16, 0,  0,
    0, 16, 0,  0,  16, 16, 16, 16, 8, 8,  24, 24, 8,  24, 8,  8,  8, 24, 8,  8,  24, 24, 24, 24,
    8, 8,  24, 24, 8,  24, 8,  8,  8, 24, 8,  8,  24, 24, 24, 24};

static const uint8_t lookup2[256] = {
    0, 0, 4, 4, 0, 4, 0, 0, 0, 4, 0, 0, 4, 4, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 0, 4, 0, 0, 4,
    4, 4, 4, 2, 2, 6, 6, 2, 6, 2, 2, 2, 6, 2, 2, 6, 6, 6, 6, 2, 2, 6, 6, 2, 6, 2, 2, 2, 6,
    2, 2, 6, 6, 6, 6, 0, 0, 4, 4, 0, 4, 0, 0, 0, 4, 0, 0, 4, 4, 4, 4, 2, 2, 6, 6, 2, 6, 2,
    2, 2, 6, 2, 2, 6, 6, 6, 6, 0, 0, 4, 4, 0, 4, 0, 0, 0, 4, 0, 0, 4, 4, 4, 4, 0, 0, 4, 4,
    0, 4, 0, 0, 0, 4, 0, 0, 4, 4, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 0, 4, 0, 0, 4, 4, 4, 4, 2,
    2, 6, 6, 2, 6, 2, 2, 2, 6, 2, 2, 6, 6, 6, 6, 0, 0, 4, 4, 0, 4, 0, 0, 0, 4, 0, 0, 4, 4,
    4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 0, 4, 0, 0, 4, 4, 4, 4, 2, 2, 6, 6, 2, 6, 2, 2, 2, 6, 2,
    2, 6, 6, 6, 6, 2, 2, 6, 6, 2, 6, 2, 2, 2, 6, 2, 2, 6, 6, 6, 6, 2, 2, 6, 6, 2, 6, 2, 2,
    2, 6, 2, 2, 6, 6, 6, 6, 2, 2, 6, 6, 2, 6, 2, 2, 2, 6, 2, 2, 6, 6, 6, 6};

// Global variables for tracking found keys
static MfClassicKey* found_keys = NULL;
static int found_key_count = 0;
static bool stop_attack = false;

// Global progress tracking variables
static int current_nonce = 0;
static int total_nonces = 0;
static int current_msb_round = 0;
static int total_msb_rounds = 0;
static int global_current_nonce = 0;
static int global_total_nonces = 0;

// Function declarations
void print_progress_bar(float percentage, int width);
void print_simple_progress(int nonce_current, int nonce_total, int msb_current, int msb_total, float msb_progress);
void signal_handler(int sig);

// Crypto1 functions
static inline uint8_t evenparity32(uint32_t x) {
    return __builtin_parity(x);
}

static inline int filter(uint32_t const x) {
    uint32_t f;
    f = lookup1[x & 0xff] | lookup2[(x >> 8) & 0xff];
    f |= 0x0d938 >> (x >> 16 & 0xf) & 1;
    return BIT(0xEC57E80A, f);
}

static uint8_t get_nth_byte(uint32_t value, int n) {
    if(n < 0 || n > 3) {
        return 0;
    }
    return (value >> (8 * (3 - n))) & 0xFF;
}

static uint8_t nfc_util_even_parity8(uint8_t data) {
    return __builtin_parity(data);
}

static uint8_t crypt_bit(struct Crypto1State* s, uint8_t in, int is_encrypted) {
    uint32_t feedin, t;
    uint8_t ret = filter(s->odd);
    feedin = ret & !!is_encrypted;
    feedin ^= !!in;
    feedin ^= LF_POLY_ODD & s->odd;
    feedin ^= LF_POLY_EVEN & s->even;
    s->even = s->even << 1 | evenparity32(feedin);
    t = s->odd, s->odd = s->even, s->even = t;
    return ret;
}

static inline uint32_t crypt_word_par(
    struct Crypto1State* s,
    uint32_t in,
    int is_encrypted,
    uint32_t nt_plain,
    uint8_t* parity_keystream_bits) {
    uint32_t ret = 0;
    *parity_keystream_bits = 0;

    for(int i = 0; i < 32; i++) {
        uint8_t bit = crypt_bit(s, BEBIT(in, i), is_encrypted);
        ret |= bit << (24 ^ i);
        // Save keystream parity bit
        if((i + 1) % 8 == 0) {
            *parity_keystream_bits |=
                (filter(s->odd) ^ nfc_util_even_parity8(get_nth_byte(nt_plain, i / 8)))
                << (3 - (i / 8));
        }
    }
    return ret;
}

static inline void update_contribution(unsigned int data[], int item, int mask1, int mask2) {
    int p = data[item] >> 25;
    p = p << 1 | evenparity32(data[item] & mask1);
    p = p << 1 | evenparity32(data[item] & mask2);
    data[item] = p << 24 | (data[item] & 0xffffff);
}

static inline uint32_t prng_successor(uint32_t x, uint32_t n) {
    SWAPENDIAN(x);
    while(n--)
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    return SWAPENDIAN(x);
}

static inline uint32_t crypt_word(struct Crypto1State* s) {
    uint32_t res_ret = 0;
    uint32_t feedin, t;
    for(int i = 0; i <= 31; i++) {
        res_ret |= (filter(s->odd) << (24 ^ i));
        feedin = LF_POLY_EVEN & s->even;
        feedin ^= LF_POLY_ODD & s->odd;
        s->even = s->even << 1 | (evenparity32(feedin));
        t = s->odd, s->odd = s->even, s->even = t;
    }
    return res_ret;
}

static inline void crypt_word_noret(struct Crypto1State* s, uint32_t in, int x) {
    uint8_t ret;
    uint32_t feedin, t, next_in;
    for(int i = 0; i <= 31; i++) {
        next_in = BEBIT(in, i);
        ret = filter(s->odd);
        feedin = ret & (!!x);
        feedin ^= LF_POLY_EVEN & s->even;
        feedin ^= LF_POLY_ODD & s->odd;
        feedin ^= !!next_in;
        s->even = s->even << 1 | (evenparity32(feedin));
        t = s->odd, s->odd = s->even, s->even = t;
    }
}

static inline uint32_t crypt_word_ret(struct Crypto1State* s, uint32_t in, int x) {
    uint32_t ret = 0;
    uint32_t feedin, t, next_in;
    uint8_t next_ret;
    for(int i = 0; i <= 31; i++) {
        next_in = BEBIT(in, i);
        next_ret = filter(s->odd);
        feedin = next_ret & (!!x);
        feedin ^= LF_POLY_EVEN & s->even;
        feedin ^= LF_POLY_ODD & s->odd;
        feedin ^= !!next_in;
        s->even = s->even << 1 | (evenparity32(feedin));
        t = s->odd, s->odd = s->even, s->even = t;
        ret |= next_ret << (24 ^ i);
    }
    return ret;
}

static inline void rollback_word_noret(struct Crypto1State* s, uint32_t in, int x) {
    uint8_t ret;
    uint32_t feedin, t, next_in;
    for(int i = 31; i >= 0; i--) {
        next_in = BEBIT(in, i);
        s->odd &= 0xffffff;
        t = s->odd, s->odd = s->even, s->even = t;
        ret = filter(s->odd);
        feedin = ret & (!!x);
        feedin ^= s->even & 1;
        feedin ^= LF_POLY_EVEN & (s->even >>= 1);
        feedin ^= LF_POLY_ODD & s->odd;
        feedin ^= !!next_in;
        s->even |= (evenparity32(feedin)) << 23;
    }
}

uint8_t napi_lfsr_rollback_bit(struct Crypto1State* s, uint32_t in, int fb) {
    int out;
    uint8_t ret;
    uint32_t t;
    s->odd &= 0xffffff;
    t = s->odd, s->odd = s->even, s->even = t;

    out = s->even & 1;
    out ^= LF_POLY_EVEN & (s->even >>= 1);
    out ^= LF_POLY_ODD & s->odd;
    out ^= !!in;
    out ^= (ret = filter(s->odd)) & !!fb;

    s->even |= evenparity32(out) << 23;
    return ret;
}

uint32_t napi_lfsr_rollback_word(struct Crypto1State* s, uint32_t in, int fb) {
    int i;
    uint32_t ret = 0;
    for(i = 31; i >= 0; --i)
        ret |= napi_lfsr_rollback_bit(s, BEBIT(in, i), fb) << (i ^ 24);
    return ret;
}

void crypto1_get_lfsr(struct Crypto1State* state, MfClassicKey* lfsr) {
    int i;
    uint64_t lfsr_value = 0;
    for(i = 23; i >= 0; --i) {
        lfsr_value = lfsr_value << 1 | BIT(state->odd, i ^ 3);
        lfsr_value = lfsr_value << 1 | BIT(state->even, i ^ 3);
    }

    for(i = 0; i < 6; ++i) {
        lfsr->data[i] = (lfsr_value >> ((5 - i) * 8)) & 0xFF;
    }
}

// Add found key to the list
void add_found_key(MfClassicKey* key) {
    // Check if key already exists
    for(int i = 0; i < found_key_count; i++) {
        if(memcmp(found_keys[i].data, key->data, MF_CLASSIC_KEY_SIZE) == 0) {
            return; // Already found
        }
    }
    
    found_keys = realloc(found_keys, sizeof(MfClassicKey) * (found_key_count + 1));
    found_keys[found_key_count] = *key;
    found_key_count++;
    
    // Print key found message on new line
    printf("\nFound key: ");
    for(int i = 0; i < MF_CLASSIC_KEY_SIZE; i++) {
        printf("%02X", key->data[i]);
    }
    printf("\n");
}

static inline int check_state(struct Crypto1State* t, MfClassicNonce* n) {
    if(!(t->odd | t->even)) return 0;
    
    if(n->attack == mfkey32) {
        uint32_t rb = (napi_lfsr_rollback_word(t, 0, 0) ^ n->p64);
        if(rb != n->ar0_enc) {
            return 0;
        }
        rollback_word_noret(t, n->nr0_enc, 1);
        rollback_word_noret(t, n->uid_xor_nt0, 0);
        struct Crypto1State temp = {t->odd, t->even};
        crypt_word_noret(t, n->uid_xor_nt1, 0);
        crypt_word_noret(t, n->nr1_enc, 1);
        if(n->ar1_enc == (crypt_word(t) ^ n->p64b)) {
            crypto1_get_lfsr(&temp, &(n->key));
            add_found_key(&(n->key));
            return 1;
        }
    } else if(n->attack == static_nested) {
        struct Crypto1State temp = {t->odd, t->even};
        rollback_word_noret(t, n->uid_xor_nt1, 0);
        if(n->ks1_1_enc == crypt_word_ret(t, n->uid_xor_nt0, 0)) {
            rollback_word_noret(&temp, n->uid_xor_nt1, 0);
            crypto1_get_lfsr(&temp, &(n->key));
            add_found_key(&(n->key));
            return 1;
        }
    } else if(n->attack == static_encrypted) {
        if(n->ks1_1_enc == napi_lfsr_rollback_word(t, n->uid_xor_nt0, 0)) {
            // Reduce with parity check
            uint8_t local_parity_keystream_bits;
            struct Crypto1State temp = {t->odd, t->even};
            if((crypt_word_par(&temp, n->uid_xor_nt0, 0, n->nt0, &local_parity_keystream_bits) ==
                n->ks1_1_enc) &&
               (local_parity_keystream_bits == n->par_1)) {
                crypto1_get_lfsr(t, &(n->key));
                add_found_key(&(n->key));
                return 1;
            }
        }
    }
    return 0;
}

static inline int state_loop(
    unsigned int* states_buffer,
    int xks,
    int m1,
    int m2,
    unsigned int in,
    uint8_t and_val) {
    int states_tail = 0;
    int round = 0, s = 0, xks_bit = 0, round_in = 0;

    for(round = 1; round <= 12; round++) {
        xks_bit = BIT(xks, round);
        if(round > 4) {
            round_in = ((in >> (2 * (round - 4))) & and_val) << 24;
        }

        for(s = 0; s <= states_tail; s++) {
            states_buffer[s] <<= 1;

            if((filter(states_buffer[s]) ^ filter(states_buffer[s] | 1)) != 0) {
                states_buffer[s] |= filter(states_buffer[s]) ^ xks_bit;
                if(round > 4) {
                    update_contribution(states_buffer, s, m1, m2);
                    states_buffer[s] ^= round_in;
                }
            } else if(filter(states_buffer[s]) == xks_bit) {
                if(round > 4) {
                    states_buffer[++states_tail] = states_buffer[s + 1];
                    states_buffer[s + 1] = states_buffer[s] | 1;
                    update_contribution(states_buffer, s, m1, m2);
                    states_buffer[s++] ^= round_in;
                    update_contribution(states_buffer, s, m1, m2);
                    states_buffer[s] ^= round_in;
                } else {
                    states_buffer[++states_tail] = states_buffer[++s];
                    states_buffer[s] = states_buffer[s - 1] | 1;
                }
            } else {
                states_buffer[s--] = states_buffer[states_tail--];
            }
        }
    }

    return states_tail;
}

int binsearch(unsigned int data[], int start, int stop) {
    int mid, val = data[stop] & 0xff000000;
    while(start != stop) {
        mid = (stop - start) >> 1;
        if((data[start + mid] ^ 0x80000000) > (val ^ 0x80000000))
            stop = start + mid;
        else
            start += mid + 1;
    }
    return start;
}

void quicksort(unsigned int array[], int low, int high) {
    if(low >= high) return;
    int middle = low + (high - low) / 2;
    unsigned int pivot = array[middle];
    int i = low, j = high;
    while(i <= j) {
        while(array[i] < pivot) {
            i++;
        }
        while(array[j] > pivot) {
            j--;
        }
        if(i <= j) {
            int temp = array[i];
            array[i] = array[j];
            array[j] = temp;
            i++;
            j--;
        }
    }
    if(low < j) {
        quicksort(array, low, j);
    }
    if(high > i) {
        quicksort(array, i, high);
    }
}

int extend_table(unsigned int data[], int tbl, int end, int bit, int m1, int m2, unsigned int in) {
    in <<= 24;
    for(data[tbl] <<= 1; tbl <= end; data[++tbl] <<= 1) {
        if((filter(data[tbl]) ^ filter(data[tbl] | 1)) != 0) {
            data[tbl] |= filter(data[tbl]) ^ bit;
            update_contribution(data, tbl, m1, m2);
            data[tbl] ^= in;
        } else if(filter(data[tbl]) == bit) {
            data[++end] = data[tbl + 1];
            data[tbl + 1] = data[tbl] | 1;
            update_contribution(data, tbl, m1, m2);
            data[tbl++] ^= in;
            update_contribution(data, tbl, m1, m2);
            data[tbl] ^= in;
        } else {
            data[tbl--] = data[end--];
        }
    }
    return end;
}

int old_recover(
    unsigned int odd[],
    int o_head,
    int o_tail,
    int oks,
    unsigned int even[],
    int e_head,
    int e_tail,
    int eks,
    int rem,
    int s,
    MfClassicNonce* n,
    unsigned int in,
    int first_run) {
    int o, e, i;
    if(rem == -1) {
        for(e = e_head; e <= e_tail; ++e) {
            even[e] = (even[e] << 1) ^ evenparity32(even[e] & LF_POLY_EVEN) ^ (!!(in & 4));
            for(o = o_head; o <= o_tail; ++o, ++s) {
                struct Crypto1State temp = {0, 0};
                temp.even = odd[o];
                temp.odd = even[e] ^ evenparity32(odd[o] & LF_POLY_ODD);
                if(check_state(&temp, n)) {
                    return -1;
                }
            }
        }
        return s;
    }
    if(first_run == 0) {
        for(i = 0; (i < 4) && (rem-- != 0); i++) {
            oks >>= 1;
            eks >>= 1;
            in >>= 2;
            o_tail = extend_table(
                odd, o_head, o_tail, oks & 1, LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0);
            if(o_head > o_tail) return s;
            e_tail = extend_table(
                even, e_head, e_tail, eks & 1, LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, in & 3);
            if(e_head > e_tail) return s;
        }
    }
    first_run = 0;
    quicksort(odd, o_head, o_tail);
    quicksort(even, e_head, e_tail);
    while(o_tail >= o_head && e_tail >= e_head) {
        if(((odd[o_tail] ^ even[e_tail]) >> 24) == 0) {
            o_tail = binsearch(odd, o_head, o = o_tail);
            e_tail = binsearch(even, e_head, e = e_tail);
            s = old_recover(
                odd,
                o_tail--,
                o,
                oks,
                even,
                e_tail--,
                e,
                eks,
                rem,
                s,
                n,
                in,
                first_run);
            if(s == -1) {
                break;
            }
        } else if((odd[o_tail] ^ 0x80000000) > (even[e_tail] ^ 0x80000000)) {
            o_tail = binsearch(odd, o_head, o_tail) - 1;
        } else {
            e_tail = binsearch(even, e_head, e_tail) - 1;
        }
    }
    return s;
}

int calculate_msb_tables(
    int oks,
    int eks,
    int msb_round,
    MfClassicNonce* n,
    unsigned int* states_buffer,
    struct Msb* odd_msbs,
    struct Msb* even_msbs,
    unsigned int* temp_states_odd,
    unsigned int* temp_states_even,
    unsigned int in) {
    
    unsigned int msb_head = (MSB_LIMIT * msb_round);
    unsigned int msb_tail = (MSB_LIMIT * (msb_round + 1));
    int states_tail = 0, tail = 0;
    int i = 0, j = 0, semi_state = 0, found = 0;
    unsigned int msb = 0;
    in = ((in >> 16 & 0xff) | (in << 16) | (in & 0xff00)) << 1;
    
    memset(odd_msbs, 0, MSB_LIMIT * sizeof(struct Msb));
    memset(even_msbs, 0, MSB_LIMIT * sizeof(struct Msb));

    for(semi_state = 1 << 20; semi_state >= 0; semi_state--) {
        if(stop_attack) return 0;
        
        if(semi_state % 65536 == 0) {
            // Calculate progress percentage
            float progress = (float)(1048576 - semi_state) / 1048576.0 * 100.0;
            print_simple_progress(global_current_nonce, global_total_nonces, current_msb_round, total_msb_rounds, progress);
        }

        if(filter(semi_state) == (oks & 1)) {
            states_buffer[0] = semi_state;
            states_tail = state_loop(states_buffer, oks, CONST_M1_1, CONST_M2_1, 0, 0);

            for(i = states_tail; i >= 0; i--) {
                msb = states_buffer[i] >> 24;
                if((msb >= msb_head) && (msb < msb_tail)) {
                    found = 0;
                    for(j = 0; j < odd_msbs[msb - msb_head].tail - 1; j++) {
                        if(odd_msbs[msb - msb_head].states[j] == states_buffer[i]) {
                            found = 1;
                            break;
                        }
                    }

                    if(!found) {
                        tail = odd_msbs[msb - msb_head].tail++;
                        odd_msbs[msb - msb_head].states[tail] = states_buffer[i];
                    }
                }
            }
        }

        if(filter(semi_state) == (eks & 1)) {
            states_buffer[0] = semi_state;
            states_tail = state_loop(states_buffer, eks, CONST_M1_2, CONST_M2_2, in, 3);

            for(i = 0; i <= states_tail; i++) {
                msb = states_buffer[i] >> 24;
                if((msb >= msb_head) && (msb < msb_tail)) {
                    found = 0;

                    for(j = 0; j < even_msbs[msb - msb_head].tail; j++) {
                        if(even_msbs[msb - msb_head].states[j] == states_buffer[i]) {
                            found = 1;
                            break;
                        }
                    }

                    if(!found) {
                        tail = even_msbs[msb - msb_head].tail++;
                        even_msbs[msb - msb_head].states[tail] = states_buffer[i];
                    }
                }
            }
        }
    }

    oks >>= 12;
    eks >>= 12;

    for(i = 0; i < MSB_LIMIT; i++) {
        if(stop_attack) return 0;
        
        memset(temp_states_even, 0, sizeof(unsigned int) * (1280));
        memset(temp_states_odd, 0, sizeof(unsigned int) * (1280));
        memcpy(temp_states_odd, odd_msbs[i].states, odd_msbs[i].tail * sizeof(unsigned int));
        memcpy(temp_states_even, even_msbs[i].states, even_msbs[i].tail * sizeof(unsigned int));
        
        int res = old_recover(
            temp_states_odd,
            0,
            odd_msbs[i].tail,
            oks,
            temp_states_even,
            0,
            even_msbs[i].tail,
            eks,
            3,
            0,
            n,
            in >> 16,
            1);
        if(res == -1) {
            return 1;
        }
    }

    return 0;
}

bool recover(MfClassicNonce* n, int ks2, unsigned int in) {
    bool found = false;
    
    // Allocate memory blocks
    struct Msb* odd_msbs = malloc(sizeof(struct Msb) * MSB_LIMIT * 2);
    struct Msb* even_msbs = malloc(sizeof(struct Msb) * MSB_LIMIT * 2);
    unsigned int* temp_states_odd = malloc(sizeof(unsigned int) * 1280);
    unsigned int* temp_states_even = malloc(sizeof(unsigned int) * 1280);
    unsigned int* states_buffer = malloc(sizeof(unsigned int) * 1024);
    
    if(!odd_msbs || !even_msbs || !temp_states_odd || !temp_states_even || !states_buffer) {
        printf("Memory allocation failed!\n");
        return false;
    }
    
    int oks = 0, eks = 0;
    int i = 0, msb = 0;
    
    for(i = 31; i >= 0; i -= 2) {
        oks = oks << 1 | BEBIT(ks2, i);
    }
    for(i = 30; i >= 0; i -= 2) {
        eks = eks << 1 | BEBIT(ks2, i);
    }
    
    total_msb_rounds = 256 / MSB_LIMIT;
    
    for(msb = 0; msb <= ((256 / MSB_LIMIT) - 1); msb++) {
        current_msb_round = msb + 1;
        
        if(calculate_msb_tables(
            oks,
            eks, 
            msb,
            n,
            states_buffer,
            odd_msbs,
            even_msbs,
            temp_states_odd,
            temp_states_even,
            in)) {
            found = true;
            // Key found message will be printed by add_found_key function
            break;
        }
        if(stop_attack) {
            break;
        }
        
        // Complete current MSB round
        print_simple_progress(global_current_nonce, global_total_nonces, current_msb_round, total_msb_rounds, 100.0);
    }
    
    // Free allocated memory
    free(odd_msbs);
    free(even_msbs);
    free(temp_states_odd);
    free(temp_states_even);
    free(states_buffer);
    
    return found;
}

int binaryStringToInt(const char* binStr) {
    int result = 0;
    while(*binStr) {
        result <<= 1;
        if(*binStr == '1') {
            result |= 1;
        }
        binStr++;
    }
    return result;
}

bool load_nested_nonces(const char* filename, MfClassicNonce** nonces, int* nonce_count) {
    FILE* file = fopen(filename, "r");
    if(!file) {
        printf("Failed to open file: %s\n", filename);
        return false;
    }
    
    char line[512];
    int count = 0;
    MfClassicNonce* nonce_array = NULL;
    
    printf("Loading nonces from %s...\n", filename);
    
    while(fgets(line, sizeof(line), file)) {
        // Only process lines ending with "dist 0"
        if(!strstr(line, "dist 0")) {
            continue;
        }
        
        MfClassicNonce nonce = {0};
        nonce.attack = static_encrypted;
        
        int parsed = sscanf(
            line,
            "Sec %*d key %*c cuid %" PRIx32 " nt0 %" PRIx32 " ks0 %" PRIx32
            " par0 %4s nt1 %" PRIx32 " ks1 %" PRIx32 " par1 %4s",
            &nonce.uid,
            &nonce.nt0,
            &nonce.ks1_1_enc,
            nonce.par_1_str,
            &nonce.nt1,
            &nonce.ks1_2_enc,
            nonce.par_2_str);
        
        if(parsed >= 4) { // At least one nonce is present
            nonce.par_1 = binaryStringToInt(nonce.par_1_str);
            nonce.uid_xor_nt0 = nonce.uid ^ nonce.nt0;
            
            if(parsed == 7) { // Both nonces are present  
                nonce.attack = static_nested;
                nonce.par_2 = binaryStringToInt(nonce.par_2_str);
                nonce.uid_xor_nt1 = nonce.uid ^ nonce.nt1;
            }
            
            nonce_array = realloc(nonce_array, sizeof(MfClassicNonce) * (count + 1));
            nonce_array[count] = nonce;
            count++;
            
            printf("Loaded nonce %d: UID=0x%08X, attack=%s\n", 
                count, nonce.uid, 
                (nonce.attack == static_nested) ? "static_nested" : "static_encrypted");
        }
    }
    
    fclose(file);
    
    *nonces = nonce_array;
    *nonce_count = count;
    
    printf("Total nonces loaded: %d\n\n", count);
    return count > 0;
}

void save_keys_to_file(const char* filename) {
    if(found_key_count == 0) {
        printf("No keys found to save.\n");
        return;
    }
    
    FILE* file = fopen(filename, "w");
    if(!file) {
        printf("Failed to create output file: %s\n", filename);
        return;
    }
    
    printf("Saving %d keys to %s...\n", found_key_count, filename);
    
    for(int i = 0; i < found_key_count; i++) {
        for(int j = 0; j < MF_CLASSIC_KEY_SIZE; j++) {
            fprintf(file, "%02X", found_keys[i].data[j]);
        }
        fprintf(file, "\n");
    }
    
    fclose(file);
    printf("Keys saved successfully!\n");
}

void print_usage(const char* program_name) {
    printf("Usage: %s <nested.log file> [output_keys.txt]\n", program_name);
    printf("  nested.log file: Input file containing nested attack nonces\n");
    printf("  output_keys.txt: Optional output file for found keys (default: found_keys.txt)\n");
    printf("\nExample: %s /path/to/.nested.log keys.txt\n", program_name);
}

// Progress bar display function - simple version
void print_progress_bar(float percentage, int width) {
    int filled = (int)(percentage / 100.0 * width);
    printf("[");
    for(int i = 0; i < width; i++) {
        if(i < filled) {
            printf("=");
        } else if(i == filled && percentage > (float)filled / width * 100) {
            printf(">");
        } else {
            printf("-");
        }
    }
    printf("] %5.1f%%", percentage);
}

// Simple progress display - no cursor manipulation
void print_simple_progress(int nonce_current, int nonce_total, int msb_current, int msb_total, float msb_progress) {
    // Calculate overall progress
    float nonce_percentage = (float)nonce_current / nonce_total * 100.0;
    float msb_percentage = (float)msb_current / msb_total * 100.0;
    
    printf("\rProgress: Nonce %d/%d (%.1f%%) | MSB %d/%d (%.1f%%) | Current %.1f%%", 
           nonce_current, nonce_total, nonce_percentage,
           msb_current, msb_total, msb_percentage,
           msb_progress);
    fflush(stdout);
}

// Add signal handling for Ctrl+C
void signal_handler(int sig) {
    if(sig == SIGINT) {
        printf("\n\nReceived interrupt signal. Stopping attack gracefully...\n");
        stop_attack = true;
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    
    if(argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output_file = (argc > 2) ? argv[2] : "found_keys.txt";
    
    printf("MIFARE Classic Key Recovery Tool\n");
    printf("================================================================================\n");
    printf("Input file:  %s\n", input_file);
    printf("Output file: %s\n", output_file);
    printf("================================================================================\n");
    printf("\n");
    
    MfClassicNonce* nonces = NULL;
    int nonce_count = 0;
    
    if(!load_nested_nonces(input_file, &nonces, &nonce_count)) {
        printf("Failed to load nonces from file!\n");
        return 1;
    }
    
    total_nonces = nonce_count;
    global_total_nonces = nonce_count;
    
    printf("Starting key recovery... (Press Ctrl+C to stop gracefully.)\n\n");
    
    for(int i = 0; i < nonce_count && !stop_attack; i++) {
        current_nonce = i + 1;
        global_current_nonce = i + 1;
        MfClassicNonce* nonce = &nonces[i];
        
        uint32_t ks_enc = 0, nt_xor_uid = 0;
        
        switch(nonce->attack) {
            case static_nested:
                ks_enc = nonce->ks1_2_enc;
                nt_xor_uid = nonce->uid_xor_nt1;
                break;
            case static_encrypted:
                ks_enc = nonce->ks1_1_enc;
                nt_xor_uid = nonce->uid_xor_nt0;
                break;
            default:
                printf("Unsupported attack type: %d\n", nonce->attack);
                continue;
        }
        
        recover(nonce, ks_enc, nt_xor_uid);
    }
    
    // Clear progress line and show completion
    printf("\n");
    printf("Key recovery completed!\n");
    
    printf("Total unique keys found: %d\n\n", found_key_count);
    
    if(found_key_count > 0) {
        printf("Found keys:\n");
        for(int i = 0; i < found_key_count; i++) {
            printf("Key %d: ", i + 1);
            for(int j = 0; j < MF_CLASSIC_KEY_SIZE; j++) {
                printf("%02X", found_keys[i].data[j]);
            }
            printf("\n");
        }
        printf("\n");
        
        save_keys_to_file(output_file);
    } else {
        printf("No keys were recovered. This could happen if:\n");
        printf("  * The nonces are invalid or corrupted\n");
        printf("  * The keyspace being searched doesn't contain the key\n");
        printf("  * The attack was interrupted before completion\n\n");
    }
    
    // Cleanup
    if(nonces) free(nonces);
    if(found_keys) free(found_keys);
    
    return 0;
}
