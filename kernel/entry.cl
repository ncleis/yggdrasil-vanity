__kernel void generate_pubkey (__global uchar *results, __global uchar *keys) {
	size_t const thread = get_global_id (0);
	uchar key[32];
	for (size_t i = 0; i < 32; i++) {
		key[i] = keys[thread * 32 + i];
	}

	uchar hash[64];
	hash_private(&key, sizeof (key), &hash);
	hash[0] &= 248;
    hash[31] &= 63;
    hash[31] |= 64;

	bignum256modm a;
	ge25519 ALIGN(16) A;
	expand256_modm(a, hash, 32);
	ge25519_scalarmult_base_niels(&A, a);

	uchar pubkey[32];
	ge25519_pack(pubkey, &A);

	for (size_t i = 0; i < 32; i++) {
		results[thread * 32 + i] = pubkey[i];
	}
}
