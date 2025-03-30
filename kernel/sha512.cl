/*
    SHA-512 OpenCL Kernel (Fixed for NVIDIA)
    Adapted from original code by B. Kerler and C.B
*/

// Макрос для перестановки байтов (little-endian -> big-endian)
#define SWAP(x) ((x >> 56) | ((x >> 40) & 0xFF00) | ((x >> 24) & 0xFF0000) | ((x >> 8) & 0xFF000000) | \
                ((x << 8) & 0xFF00000000) | ((x << 24) & 0xFF0000000000) | ((x << 40) & 0xFF000000000000) | (x << 56))

// Битовые вращения
#define rotr64(x, n) ((x >> n) | (x << (64 - n)))
#define S0(x) (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39))
#define S1(x) (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41))
#define little_s0(x) (rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7))
#define little_s1(x) (rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6))

// Размер блока SHA-512 (1024 бита = 16 ulong)
#define HASH_BLOCK_SIZE 16

// Константы паддинга
__constant ulong padLong[8] = {
    0x80UL, 0x8000UL, 0x800000UL, 0x80000000UL,
    0x8000000000UL, 0x800000000000UL, 0x80000000000000UL, 0x8000000000000000UL
};

__constant ulong maskLong[8] = {
    0, 0xFFUL, 0xFFFFUL, 0xFFFFFFUL,
    0xFFFFFFFFUL, 0xFFFFFFFFFFUL, 0xFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFUL
};

// Константы SHA-512 (уже в big-endian)
__constant ulong k_sha512[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

// Макросы для шагов обработки
#define SHA512_STEP(a, b, c, d, e, f, g, h, x, K) \
    h += K + S1(e) + choose(e, f, g) + x; \
    d += h; \
    h += S0(a) + bit_maj(a, b, c);

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

// Функция паддинга
static int md_pad_128(ulong *msg, const ulong msgLen_bytes) {
    const ulong padIndex = msgLen_bytes / 8;
    const ulong overhang = msgLen_bytes % 8;
    
    // Установка бита 1
    msg[padIndex] &= maskLong[overhang];
    msg[padIndex] |= padLong[overhang];
    
    // Заполнение нулями до 112 байт (16 ulong - 2 под длину)
    ulong i = padIndex + 1;
    while ((i % HASH_BLOCK_SIZE) != (HASH_BLOCK_SIZE - 2)) {
        msg[i++] = 0;
    }
    
    // Добавление длины в битах (big-endian)
    ulong length_bits = msgLen_bytes * 8;
    msg[i++] = SWAP(length_bits >> 64);  // Верхние 64 бита
    msg[i++] = SWAP(length_bits);       // Нижние 64 бита
    
    return (i / HASH_BLOCK_SIZE);
}

// Основная функция хеширования
static void sha512_hash(ulong *input, const ulong length, ulong *hash) {
    const ulong nBlocks = md_pad_128(input, length);
    ulong W[80] = {0};
    ulong State[8] = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };
    
    for (ulong block = 0; block < nBlocks; block++) {
        // Инициализация W (первые 16 слов)
        for (ulong i = 0; i < 16; i++) {
            W[i] = SWAP(input[i]);  // Перевод в big-endian
        }
        
        // Расширение W до 80 слов
        for (ulong i = 16; i < 80; i++) {
            W[i] = W[i-16] + little_s0(W[i-15]) + W[i-7] + little_s1(W[i-2]);
        }
        
        // Инициализация переменных
        ulong a = State[0], b = State[1], c = State[2], d = State[3];
        ulong e = State[4], f = State[5], g = State[6], h = State[7];
        
        // Обработка 80 раундов
        for (ulong i = 0; i < 80; i += 16) {
            ROUND_STEP(i);
        }
        
        // Обновление состояния
        State[0] += a; State[1] += b; State[2] += c; State[3] += d;
        State[4] += e; State[5] += f; State[6] += g; State[7] += h;
        
        input += HASH_BLOCK_SIZE;
    }
    
    // Перевод результата в big-endian
    for (ulong i = 0; i < 8; i++) {
        hash[i] = SWAP(State[i]);
    }
}
