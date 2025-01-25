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

// Encrypt a message
ElGamalCiphertext encrypt(const ElGamalParams& params, const EC_POINT* public_key, const EC_POINT* message, PointConversionForm form);

// Decrypt a ciphertext
EC_POINT* decrypt(const ElGamalParams& params, const BIGNUM* private_key, const ElGamalCiphertext& ciphertext);

// ctx addition
ElGamalCiphertext add_ctx(const EC_GROUP* group, ElGamalCiphertext ctx1, ElGamalCiphertext ctx2);

// HSS function
inline void getExpParams(uint64_t setSize, uint64_t& numSeeds, uint64_t& numChosen);
std::vector<ElGamalCiphertext> fasterEncZero(const ElGamalParams& params, uint64_t setSize, const EC_POINT* public_key);

// Re-randomize a ciphertext
// ElGamalCiphertext rerand(const ElGamalParams& params, ElGamalCiphertext enc_zero);

// Serialize ciphertext
std::vector<unsigned char> serialize_ciphertext(const ElGamalParams& params, const ElGamalCiphertext& ciphertext, PointConversionForm form);

// Deserialize ciphertext
// Deserialize ciphertext (added PointConversionForm argument)
ElGamalCiphertext deserialize_ciphertext(const ElGamalParams& params, const std::vector<unsigned char>& serialized_data, PointConversionForm form);



#endif // EC_ELGAMAL_H
