/*
    SHA-512 OpenCL Kernel (Fixed for NVIDIA)
    Adapted from original code by B. Kerler and C.B
*/

// Удаляем конфликтующие макросы
#undef rotr64
#define rotr64(x, n) ((x >> n) | (x << (64 - n)))

// Явные функции для выбора и мажоритарной логики
ulong choose(ulong x, ulong y, ulong z) {
    return (x & y) ^ (~x & z);
}

ulong bit_maj(ulong x, ulong y, ulong z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// Перестановка байтов (little-endian -> big-endian)
#define SWAP(x) ((x >> 56) | ((x >> 40) & 0xFF00) | ((x >> 24) & 0xFF0000) | ((x >> 8) & 0xFF000000) | \
                ((x << 8) & 0xFF00000000) | ((x << 24) & 0xFF0000000000) | ((x << 40) & 0xFF000000000000) | (x << 56))

// Определения функций вращения
#define S0(x) (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39))
#define S1(x) (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41))
#define little_s0(x) (rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7))
#define little_s1(x) (rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6))

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
    SWAP(0x428a2f98d728ae22UL), SWAP(0x7137449123ef65cdUL),
    // ... (остальные константы остаются без изменений)
};

// Функция паддинга
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

// Основная функция хеширования
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
        // Инициализация W (первые 16 слов)
        for (ulong i = 0; i < 16; i++) {
            W[i] = SWAP(input[i]);
        }
        // Расширение W до 80 слов
        for (ulong i = 16; i < 80; i++) {
            W[i] = W[i-16] + little_s0(W[i-15]) + W[i-7] + little_s1(W[i-2]);
        }
        
        // Инициализация переменных раунда
        ulong a = State[0], b = State[1], c = State[2], d = State[3];
        ulong e = State[4], f = State[5], g = State[6], h = State[7];
        
        // Обработка 80 раундов
        for (ulong i = 0; i < 80; i += 16) {
            ROUND_STEP(i);
        }
        
        // Обновление состояния
        State[0] += a; State[1] += b; State[2] += c; State[3] += d;
        State[4] += e; State[5] += f; State[6] += g; State[7] += h;
        
        input += 16;
    }
    
    // Запись результата
    for (ulong i = 0; i < 8; i++) {
        hash[i] = SWAP(State[i]);
    }
}

// Ядро OpenCL с исправленными указателями
__kernel void generate_pubkey(__global ulong *key, __global ulong *hash) {
    // Исправленные указатели с явным указанием __global
    sha512_hash((__global ulong*)key, sizeof(key), (__global ulong*)hash);
}
