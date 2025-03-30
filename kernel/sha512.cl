/*
    SHA-512 OpenCL Kernel (Final Fix for NVIDIA)
    Adapted from original code by B. Kerler and C.B
*/

// 1. Устраняем конфликт макросов
#undef rotr64
#define rotr64(x, n) ((x >> n) | (x << (64 - n)))

// 2. Явные функции вместо макросов
ulong choose(ulong x, ulong y, ulong z) {
    return (x & y) ^ (~x & z);
}

ulong bit_maj(ulong x, ulong y, ulong z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// 3. Макрос SWAP через битовые операции
#define SWAP(x) ((x >> 56) | ((x >> 40) & 0xFF00) | ((x >> 24) & 0xFF0000) | ((x >> 8) & 0xFF000000) | \
                ((x << 8) & 0xFF00000000) | ((x << 24) & 0xFF0000000000) | ((x << 40) & 0xFF000000000000) | (x << 56))

// 4. Определения функций вращения
#define S0(x) (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39))
#define S1(x) (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41))
#define little_s0(x) (rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7))
#define little_s1(x) (rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6))

// 5. Константы SHA-512
__constant ulong k_sha512[80] = {
    SWAP(0x428a2f98d728ae22UL), SWAP(0x7137449123ef65cdUL),
    // ... (остальные константы остаются без изменений)
};

// 6. Макрос шага обработки
#define SHA512_STEP(a, b, c, d, e, f, g, h, x, K) \
    h += K + S1(e) + choose(e, f, g) + x; \
    d += h; \
    h += S0(a) + bit_maj(a, b, c);

// 7. Макрос раунда (объявлен до использования)
#define ROUND_STEP(i) \
    SHA512_STEP(a, b, c, d, e, f, g, h, W[i], k_sha512[i]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W[i+1], k_sha512[i+1]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W[i+2], k_sha512[i+2]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W[i+3], k_sha512[i+3]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W[i+4], k_sha512[i+4]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W[i+5], k_sha512[i+5]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W[i+6], k_sha512[i+6]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i+7], k_sha512[i+7]); \
    SHA512_STEP(a, b, c, d, e, f, g, h, W[i+8], k_sha512[i+8]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W[i+9], k_sha512[i+9]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W[i+10], k_sha512[i+10]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W[i+11], k_sha512[i+11]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W[i+12], k_sha512[i+12]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W[i+13], k_sha512[i+13]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W[i+14], k_sha512[i+14]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i+15], k_sha512[i+15]);

// 8. Функция паддинга
static int md_pad_128(__global ulong *msg, ulong msgLen_bytes) {
    ulong padIndex = msgLen_bytes / 8;
    ulong overhang = msgLen_bytes % 8;
    
    msg[padIndex] &= maskLong[overhang];
    msg[padIndex] |= padLong[overhang];
    
    ulong i = padIndex + 1;
    while ((i % 16) != 14) {
        msg[i++] = 0;
    }
    
    ulong length_bits = msgLen_bytes * 8;
    msg[i++] = SWAP(length_bits >> 64);
    msg[i++] = SWAP(length_bits);
    
    return i / 16;
}

// 9. Основная функция хеширования
static void sha512_hash(__global ulong *input, ulong length, __global ulong *hash) {
    ulong nBlocks = md_pad_128(input, length);
    ulong W[80] = {0};
    ulong State[8] = {
        0x6a09e667f3bcc908UL,
        0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL,
        0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL,
        0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL,
        0x5be0cd19137e2179UL
    };
    
    for (ulong block = 0; block < nBlocks; block++) {
        for (ulong i = 0; i < 16; i++) {
            W[i] = SWAP(input[i]);
        }
        for (ulong i = 16; i < 80; i++) {
            W[i] = W[i-16] + little_s0(W[i-15]) + W[i-7] + little_s1(W[i-2]);
        }
        
        ulong a = State[0], b = State[1], c = State[2], d = State[3];
        ulong e = State[4], f = State[5], g = State[6], h = State[7];
        
        for (ulong i = 0; i < 80; i += 16) {
            ROUND_STEP(i);
        }
        
        State[0] += a; State[1] += b; State[2] += c; State[3] += d;
        State[4] += e; State[5] += f; State[6] += g; State[7] += h;
        
        input += 16;
    }
    
    for (ulong i = 0; i < 8; i++) {
        hash[i] = SWAP(State[i]);
    }
}

// 10. Единое объявление ядра
__kernel void generate_pubkey(__global uchar *results, __global uchar *keys) {
    __global ulong *key = (__global ulong*)keys;
    __global ulong *hash = (__global ulong*)results;
    
    // Убран sizeof(key) - передаем реальную длину
    sha512_hash(key, get_global_size(0)*8, hash); // Пример: длина в байтах
}
