/*
    Original copyright (sha256):
    OpenCL Optimized kernel
    (c) B. Kerler 2018
    MIT License
    Adapted for SHA512 by C.B .. apparently quite a while ago
    The moral of the story is always use UL on ulongs!
*/
// bitselect is "if c then b else a" for each bit
// so equivalent to (c & b) | ((~c) & a)
#define choose(x, y, z) (bitselect(z, y, x))
// Cleverly determines majority vote, conditioning on x=z
#define bit_maj(x, y, z) (bitselect(x, y, ((x) ^ (z))))
// Перестановка байтов через битовые операции для переносимости
#define SWAP(x) ( \
    ((x) >> 56) & 0xFFUL | \
    ((x) >> 40) & 0xFF00UL | \
    ((x) >> 24) & 0xFF0000UL | \
    ((x) >> 8) & 0xFF000000UL | \
    ((x) << 8) & 0xFF00000000UL | \
    ((x) << 24) & 0xFF0000000000UL | \
    ((x) << 40) & 0xFF000000000000UL | \
    ((x) << 56) & 0xFF00000000000000UL \
)
// Вращение через битовые операции (если rotate не поддерживается)
#define rotr64(x, n) ( (x >> (n)) | (x << (64 - (n))) )
#define S0(x) (rotr64(x, 28ul) ^ rotr64(x, 34ul) ^ rotr64(x, 39ul))
#define S1(x) (rotr64(x, 14ul) ^ rotr64(x, 18ul) ^ rotr64(x, 41ul))
#define little_s0(x) (rotr64(x, 1ul) ^ rotr64(x, 8ul) ^ ((x) >> 7ul))
#define little_s1(x) (rotr64(x, 19ul) ^ rotr64(x, 61ul) ^ ((x) >> 6ul))

// Размер блока SHA-512 (8 * 64-bit слов)
#define hashBlockSize_long64 8

// Константы для паддинга
__constant ulong padLong[8] = {
    0x80UL, 0x8000UL, 0x800000UL, 0x80000000UL,
    0x8000000000UL, 0x800000000000UL, 0x80000000000000UL, 0x8000000000000000UL
};
__constant ulong maskLong[8] = {
    0, 0xFFUL, 0xFFFFUL, 0xFFFFFFUL,
    0xFFFFFFFFUL, 0xFFFFFFFFFFUL, 0xFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFUL
};

static int md_pad_128(ulong *msg, const long msgLen_bytes) {
    const unsigned int padLongIndex = (unsigned int)msgLen_bytes / 8;
    const unsigned int overhang = (unsigned int)msgLen_bytes % 8;
    
    // Установка бита 1 и маскирование
    msg[padLongIndex] &= maskLong[overhang];
    msg[padLongIndex] |= padLong[overhang];
    
    // Заполнение нулями до блока
    unsigned int i = padLongIndex + 1;
    while ((i % hashBlockSize_long64) != 0) {
        msg[i++] = 0;
    }
    
    // Добавление длины в битах (big-endian)
    ulong length_bits = (ulong)msgLen_bytes * 8;
    ulong length_high = (length_bits >> 64) & 0xFFFFFFFFFFFFFFFFUL;
    ulong length_low = length_bits & 0xFFFFFFFFFFFFFFFFUL;
    
    // Перестановка байтов для big-endian
    msg[i-2] = SWAP(length_high);
    msg[i-1] = SWAP(length_low);
    
    return (i / hashBlockSize_long64);
}

// Константы для SHA-512 (переведены в big-endian)
__constant ulong k_sha512[80] = {
    SWAP(0x428a2f98d728ae22UL), SWAP(0x7137449123ef65cdUL),
    SWAP(0xb5c0fbcfec4d3b2fUL), SWAP(0xe9b5dba58189dbbcUL),
    SWAP(0x3956c25bf348b538UL), SWAP(0x59f111f1b605d019UL),
    SWAP(0x923f82a4af194f9bUL), SWAP(0xab1c5ed5da6d8118UL),
    SWAP(0xd807aa98a3030242UL), SWAP(0x12835b0145706fbeUL),
    SWAP(0x243185be4ee4b28cUL), SWAP(0x550c7dc3d5ffb4e2UL),
    SWAP(0x72be5d74f27b896fUL), SWAP(0x80deb1fe3b1696b1UL),
    SWAP(0x9bdc06a725c71235UL), SWAP(0xc19bf174cf692694UL),
    SWAP(0xe49b69c19ef14ad2UL), SWAP(0xefbe4786384f25e3UL),
    SWAP(0x0fc19dc68b8cd5b5UL), SWAP(0x240ca1cc77ac9c65UL),
    SWAP(0x2de92c6f592b0275UL), SWAP(0x4a7484aa6ea6e483UL),
    SWAP(0x5cb0a9dcbd41fbd4UL), SWAP(0x76f988da831153b5UL),
    SWAP(0x983e5152ee66dfabUL), SWAP(0xa831c66d2db43210UL),
    SWAP(0xb00327c898fb213fUL), SWAP(0xbf597fc7beef0ee4UL),
    SWAP(0xc6e00bf33da88fc2UL), SWAP(0xd5a79147930aa725UL),
    SWAP(0x06ca6351e003826fUL), SWAP(0x142929670a0e6e70UL),
    SWAP(0x27b70a8546d22ffcUL), SWAP(0x2e1b21385c26c926UL),
    SWAP(0x4d2c6dfc5ac42aedUL), SWAP(0x53380d139d95b3dfUL),
    SWAP(0x650a73548baf63deUL), SWAP(0x766a0abb3c77b2a8UL),
    SWAP(0x81c2c92e47edaee6UL), SWAP(0x92722c851482353bUL),
    SWAP(0xa2bfe8a14cf10364UL), SWAP(0xa81a664bbc423001UL),
    SWAP(0xc24b8b70d0f89791UL), SWAP(0xc76c51a30654be30UL),
    SWAP(0xd192e819d6ef5218UL), SWAP(0xd69906245565a910UL),
    SWAP(0xf40e35855771202aUL), SWAP(0x106aa07032bbd1b8UL),
    SWAP(0x19a4c116b8d2d0c8UL), SWAP(0x1e376c085141ab53UL),
    SWAP(0x2748774cdf8eeb99UL), SWAP(0x34b0bcb5e19b48a8UL),
    SWAP(0x391c0cb3c5c95a63UL), SWAP(0x4ed8aa4ae3418acbUL),
    SWAP(0x5b9cca4f7763e373UL), SWAP(0x682e6ff3d6b2b8a3UL),
    SWAP(0x748f82ee5defb2fcUL), SWAP(0x78a5636f43172f60UL),
    SWAP(0x84c87814a1f0ab72UL), SWAP(0x8cc702081a6439ecUL),
    SWAP(0x90befffa23631e28UL), SWAP(0xa4506cebde82bde9UL),
    SWAP(0xbef9a3f7b2c67915UL), SWAP(0xc67178f2e372532bUL),
    SWAP(0xca273eceea26619cUL), SWAP(0xd186b8c721c0c207UL),
    SWAP(0xeada7dd6cde0eb1eUL), SWAP(0xf57d4f7fee6ed178UL),
    SWAP(0x06f067aa72176fbaUL), SWAP(0x0a637dc5a2c898a6UL),
    SWAP(0x113f9804bef90daeUL), SWAP(0x1b710b35131c471bUL),
    SWAP(0x28db77f523047d84UL), SWAP(0x32caab7b40c72493UL),
    SWAP(0x3c9ebe0a15c9bebcUL), SWAP(0x431d67c49c100d4cUL),
    SWAP(0x4cc5d4becb3e42b6UL), SWAP(0x597f299cfc657e2aUL),
    SWAP(0x5fcb6fab3ad6faecUL), SWAP(0x6c44198c4a475817UL)
};

#define SHA512_STEP(a, b, c, d, e, f, g, h, x, K) \
{ \
    h += K + S1(e) + choose(e, f, g) + x; \
    d += h; \
    h += S0(a) + bit_maj(a, b, c); \
}

#define ROUND_STEP(i) \
{ \
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
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i+15], k_sha512[i+15]); \
}

static void sha512_hash(ulong *input, const unsigned int length, ulong *hash) {
    const unsigned int nBlocks = md_pad_128(input, length);
    ulong W[80] = {0};
    ulong State[8] = {
        SWAP(0x6a09e667f3bcc908UL),
        SWAP(0xbb67ae8584caa73bUL),
        SWAP(0x3c6ef372fe94f82bUL),
        SWAP(0xa54ff53a5f1d36f1UL),
        SWAP(0x510e527fade682d1UL),
        SWAP(0x9b05688c2b3e6c1fUL),
        SWAP(0x1f83d9abfb41bd6bUL),
        SWAP(0x5be0cd19137e2179UL)
    };
    
    for (int block_i = 0; block_i < nBlocks; block_i++) {
        // Инициализация W для текущего блока
        for (int w = 0; w < 16; w++) {
            W[w] = SWAP(input[w]);
        }
        // Расширение W до 80 элементов
        for (int i = 16; i < 80; i++) {
            ulong s0 = little_s0(W[i-15]);
            ulong s1 = little_s1(W[i-2]);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
        }
        
        ulong a = State[0], b = State[1], c = State[2], d = State[3];
        ulong e = State[4], f = State[5], g = State[6], h = State[7];
        
        // Обработка раундов
        for (int i = 0; i < 80; i += 16) {
            ROUND_STEP(i);
        }
        
        // Обновление состояния
        State[0] += a; State[1] += b; State[2] += c; State[3] += d;
        State[4] += e; State[5] += f; State[6] += g; State[7] += h;
        
        input += hashBlockSize_long64;
    }
    
    // Перевод результата в big-endian
    hash[0] = SWAP(State[0]);
    hash[1] = SWAP(State[1]);
    hash[2] = SWAP(State[2]);
    hash[3] = SWAP(State[3]);
    hash[4] = SWAP(State[4]);
    hash[5] = SWAP(State[5]);
    hash[6] = SWAP(State[6]);
    hash[7] = SWAP(State[7]);
}
