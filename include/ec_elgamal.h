#ifndef EC_ELGAMAL_H
#define EC_ELGAMAL_H

#include "ec_curve.h"
#include <openssl/rand.h>
#include <vector>
#include <algorithm>
#include <iostream>

struct ElGamalParams {
    EC_GROUP* group;
};

struct ElGamalKeyPair {
    BIGNUM* private_key;
    EC_POINT* public_key;
};

struct ElGamalCiphertext {
    EC_POINT* C1;
    EC_POINT* C2;
};

// Setup ElGamal parameters
ElGamalParams setup_elgamal( EC_GROUP* group);

// Generate ElGamal key pair
ElGamalKeyPair generate_keypair(const ElGamalParams& params);

// multi-key version
std::pair<std::vector<BIGNUM*>, EC_POINT*> generate_multi_keypair(const ElGamalParams& params, size_t num_keys) ;

// Encrypt a message
ElGamalCiphertext encrypt(const ElGamalParams& params, const EC_POINT* public_key, const EC_POINT* message, PointConversionForm form);

// Decrypt a ciphertext
EC_POINT* decrypt(const ElGamalParams& params, const BIGNUM* private_key, const ElGamalCiphertext& ciphertext);

ElGamalCiphertext partial_decrypt(const ElGamalParams& params, const ElGamalCiphertext& ciphertext, const BIGNUM* private_key);


// ctx addition
ElGamalCiphertext add_ctx(const EC_GROUP* group, ElGamalCiphertext ctx1, ElGamalCiphertext ctx2);

// HSS function
inline void getExpParams(uint64_t setSize, uint64_t& numSeeds, uint64_t& numChosen);
std::vector<ElGamalCiphertext> fasterEncZero(const ElGamalParams& params, uint64_t setSize, const EC_POINT* public_key);

// Re-randomize a ciphertext
ElGamalCiphertext rerand(const ElGamalParams& params, ElGamalCiphertext enc_zero, ElGamalCiphertext ctx);

// Serialize ciphertext
std::vector<unsigned char> serialize_ciphertext(const ElGamalParams& params, const ElGamalCiphertext& ciphertext, PointConversionForm form);

// Deserialize ciphertext
// Deserialize ciphertext (added PointConversionForm argument)
ElGamalCiphertext deserialize_ciphertext(const ElGamalParams& params, const std::vector<unsigned char>& serialized_data, PointConversionForm form);

std::vector<unsigned char> serialize_ciphertext_vector(const ElGamalParams& params, const std::vector<ElGamalCiphertext>& ciphertexts, PointConversionForm form);

std::vector<ElGamalCiphertext> deserialize_ciphertext_vector(const ElGamalParams& params, const std::vector<unsigned char>& serialized_data, PointConversionForm form, size_t num_ciphertexts);

#endif // EC_ELGAMAL_H
