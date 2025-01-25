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


