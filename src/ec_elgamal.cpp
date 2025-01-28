#include "ec_elgamal.h"

ElGamalParams setup_elgamal(EC_GROUP* group) {
    return { group };
}

ElGamalKeyPair generate_keypair(const ElGamalParams& params) {
    BIGNUM* priv_key = BN_new();
    if (priv_key == nullptr) {
        handleErrors();
    }

    if (BN_rand(priv_key, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
        handleErrors();
    }

    EC_POINT* pub_key = multiply_point(params.group, EC_GROUP_get0_generator(params.group), priv_key);
    if (pub_key == nullptr) {
        handleErrors();
    }

    return { priv_key, pub_key };
}

std::pair<std::vector<BIGNUM*>, EC_POINT*> generate_multi_keypair(const ElGamalParams& params, size_t num_keys) {
    std::vector<BIGNUM*> priv_keys(num_keys);
    EC_POINT* aggregate_pub_key = EC_POINT_new(params.group);

    if (aggregate_pub_key == nullptr) {
        handleErrors();
    }

    // Initialize the aggregate public key to the identity element
    if (EC_POINT_set_to_infinity(params.group, aggregate_pub_key) != 1) {
        handleErrors();
    }

    for (size_t i = 0; i < num_keys; i++) {
        priv_keys[i] = BN_new();
        if (priv_keys[i] == nullptr) {
            handleErrors();
        }

        // Generate a random private key
        if (BN_rand(priv_keys[i], 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
            handleErrors();
        }

        // Compute the corresponding public key
        EC_POINT* pub_key = multiply_point(params.group, EC_GROUP_get0_generator(params.group), priv_keys[i]);
        if (pub_key == nullptr) {
            handleErrors();
        }

        // Add the public key to the aggregate public key
        if (EC_POINT_add(params.group, aggregate_pub_key, aggregate_pub_key, pub_key, NULL) != 1) {
            handleErrors();
        }

        // Free the temporary public key
        EC_POINT_free(pub_key);
    }

    return { priv_keys, aggregate_pub_key };
}

ElGamalCiphertext encrypt(const ElGamalParams& params, const EC_POINT* public_key, const EC_POINT* message, PointConversionForm form) {
    BIGNUM* k = BN_new();
    if (k == nullptr) {
        handleErrors();
    }

    if (BN_rand(k, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
        handleErrors();
    }

    EC_POINT* C1 = multiply_point(params.group, EC_GROUP_get0_generator(params.group), k);
    EC_POINT* pk_k = multiply_point(params.group, public_key, k);
    EC_POINT* C2 = add_points(params.group, message, pk_k);

    EC_POINT_free(pk_k);
    BN_free(k);

    return { C1, C2 };
}

EC_POINT* decrypt(const ElGamalParams& params, const BIGNUM* private_key, const ElGamalCiphertext& ciphertext) {
    EC_POINT* priv_C1 = multiply_point(params.group, ciphertext.C1, private_key);
    EC_POINT_invert(params.group, priv_C1, NULL);
    EC_POINT* message = add_points(params.group, ciphertext.C2, priv_C1);

    EC_POINT_free(priv_C1);
    return message;
}

ElGamalCiphertext partial_decrypt(const ElGamalParams& params, const ElGamalCiphertext& ciphertext, const BIGNUM* private_key) {
    // Compute the partial contribution: C1 * private_key
    EC_POINT* partial_contribution = multiply_point(params.group, ciphertext.C1, private_key);
    if (partial_contribution == nullptr) {
        handleErrors();
    }

    // Subtract partial contribution from C2
    EC_POINT* new_C2 = add_points(params.group, ciphertext.C2, partial_contribution);
    if (new_C2 == nullptr) {
        handleErrors();
    }

    // Negate the partial contribution (subtract equivalent in EC arithmetic)
    if (EC_POINT_invert(params.group, partial_contribution, NULL) != 1) {
        handleErrors();
    }

    // Add the negated contribution to compute new C2
    EC_POINT* result_C2 = add_points(params.group, ciphertext.C2, partial_contribution);

    // Free resources
    EC_POINT_free(partial_contribution);

    return { ciphertext.C1, result_C2 };
}


ElGamalCiphertext add_ctx(const EC_GROUP* group, ElGamalCiphertext ctx1, ElGamalCiphertext ctx2){
    EC_POINT* C1 = add_points(group, ctx1.C1, ctx2.C1);
    EC_POINT* C2 = add_points(group, ctx1.C2, ctx2.C2);

    return {C1,C2};
}
// HSS function
inline void getExpParams(uint64_t setSize, uint64_t& numSeeds, uint64_t& numChosen)
	{

		if (setSize <= (1 << 8))
		{
			numSeeds = 1<<7;
			numChosen = 23;
		}
		else if (setSize <= (1 << 10))
		{
			numSeeds = 1<<7;
			numChosen = 24;
		}
		else if (setSize <= (1 << 12))
		{
			numSeeds = 1<<7;
			numChosen = 25;
		}
		else if (setSize <= (1 << 14))
		{
			numSeeds = 1<<8;
			numChosen = 20;
		}
		else if (setSize <= (1 << 16))
		{
			numSeeds = 1<<9;
			numChosen = 17;
		}
		else if (setSize <= (1 << 18))
		{
			numSeeds = 1<<10;
			numChosen = 15;
		}
		else if (setSize <= (1 << 20))
		{
			numSeeds = 1<<13;
			numChosen = 11;
		}
		else if (setSize <= (1 << 22))
		{
			numSeeds = 1<<14;
			numChosen = 11;
		}
		else if (setSize <= (1 << 24))
		{
			numSeeds = 1<<15;
			numChosen = 10;
		}
	}

std::vector<ElGamalCiphertext> fasterEncZero(const ElGamalParams& params, uint64_t setSize, const EC_POINT* public_key){
    uint64_t numSeeds;
    uint64_t numChosen;
    uint64_t boundCoeff;

    getExpParams(setSize, numSeeds, numChosen);

    // small set of enc(0)
    std::vector<ElGamalCiphertext> smallSet(numSeeds);
    for(uint64_t i = 0;i<numSeeds;i++){
        BIGNUM* k = BN_new();
        if (k == nullptr) {
            handleErrors();
        }

        if (BN_rand(k, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
            handleErrors();
        }

        smallSet[i].C1 = multiply_point(params.group, EC_GROUP_get0_generator(params.group), k);
        smallSet[i].C2 = multiply_point(params.group, public_key, k);

        BN_free(k);

    }


    // large set of enc(0)
    std::vector<ElGamalCiphertext> largeSet(setSize);
    
    std::vector<uint64_t> indices(numChosen);
    for (uint64_t i = 0; i < setSize; i++)
    {
       
        indices.resize(0);
        while (indices.size() < numChosen)
        {
            int rnd = rand() % numSeeds;
            if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
                indices.push_back(rnd);
        }
        largeSet[i] = smallSet[indices[0]];
        for (uint64_t j = 1; j < numChosen; j++){
            largeSet[i] = add_ctx(params.group,largeSet[i],smallSet[indices[j]]);
        }

    }
    return largeSet;

}

ElGamalCiphertext rerand(const ElGamalParams& params, ElGamalCiphertext enc_zero, ElGamalCiphertext ctx){
    return add_ctx(params.group,enc_zero,ctx);
}

std::vector<unsigned char> serialize_ciphertext(const ElGamalParams& params, const ElGamalCiphertext& ciphertext, PointConversionForm form) {
    std::vector<unsigned char> serialized_C1 = ec_point_to_octet_string(params.group, ciphertext.C1, form);
    std::vector<unsigned char> serialized_C2 = ec_point_to_octet_string(params.group, ciphertext.C2, form);

    // Combine serialized C1 and C2 directly
    std::vector<unsigned char> serialized_data;
    serialized_data.insert(serialized_data.end(), serialized_C1.begin(), serialized_C1.end());
    serialized_data.insert(serialized_data.end(), serialized_C2.begin(), serialized_C2.end());

    return serialized_data;
}

ElGamalCiphertext deserialize_ciphertext(const ElGamalParams& params, const std::vector<unsigned char>& serialized_data, PointConversionForm form) {
    size_t point_size = (form == COMPRESSED) ? 33 : 65;

    // Deserialize C1
    std::vector<unsigned char> serialized_C1(serialized_data.begin(), serialized_data.begin() + point_size);
    EC_POINT* C1 = octet_string_to_ec_point(params.group, serialized_C1);

    // Deserialize C2
    std::vector<unsigned char> serialized_C2(serialized_data.begin() + point_size, serialized_data.begin() + 2 * point_size);
    EC_POINT* C2 = octet_string_to_ec_point(params.group, serialized_C2);

    return { C1, C2 };
}

std::vector<unsigned char> serialize_ciphertext_vector(const ElGamalParams& params, const std::vector<ElGamalCiphertext>& ciphertexts, PointConversionForm form) {
    std::vector<unsigned char> serialized_vector;

    for (const auto& ciphertext : ciphertexts) {
        // Serialize each ciphertext
        std::vector<unsigned char> serialized_ciphertext = serialize_ciphertext(params, ciphertext, form);

        // Append serialized data directly
        serialized_vector.insert(serialized_vector.end(), serialized_ciphertext.begin(), serialized_ciphertext.end());
    }

    return serialized_vector;
}


std::vector<ElGamalCiphertext> deserialize_ciphertext_vector(const ElGamalParams& params, const std::vector<unsigned char>& serialized_data, PointConversionForm form, size_t num_ciphertexts) {
    std::vector<ElGamalCiphertext> ciphertexts;
    size_t point_size = (form == COMPRESSED) ? 33 : 65;

    // Each ciphertext consists of 2 points (C1 and C2)
    size_t ciphertext_size = 2 * point_size;

    if (serialized_data.size() != num_ciphertexts * ciphertext_size) {
        throw std::runtime_error("Invalid serialized data size: mismatch with expected number of ciphertexts.");
    }

    for (size_t i = 0; i < num_ciphertexts; ++i) {
        size_t offset = i * ciphertext_size;

        // Deserialize C1
        std::vector<unsigned char> serialized_C1(serialized_data.begin() + offset, serialized_data.begin() + offset + point_size);
        EC_POINT* C1 = octet_string_to_ec_point(params.group, serialized_C1);

        // Deserialize C2
        std::vector<unsigned char> serialized_C2(serialized_data.begin() + offset + point_size, serialized_data.begin() + offset + 2 * point_size);
        EC_POINT* C2 = octet_string_to_ec_point(params.group, serialized_C2);

        // Add to the vector
        ciphertexts.push_back({ C1, C2 });
    }

    return ciphertexts;
}
