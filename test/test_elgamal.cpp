#include <iostream>
#include <vector>
#include <chrono>
#include "ec_curve.h"
#include "ec_elgamal.h"

void test_elgamal_performance(PointConversionForm form) {
    // Create a new EC group for the secp256r1 curve
    EC_GROUP* group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    std::string form_str = (form == COMPRESSED) ? "Compressed" : "Uncompressed";
    std::cout << "\nTesting ElGamal encryption with " << form_str << " format...\n";

    // Setup parameters
    ElGamalParams params = setup_elgamal(group);

    // Generate key pair
    ElGamalKeyPair keypair = generate_keypair(params);

    // Prepare a test message
    EC_POINT* message = EC_POINT_new(params.group);
    if (EC_POINT_mul(params.group, message, BN_value_one(), NULL, NULL, NULL) != 1) {
        handleErrors();
    }

    // Performance variables
    size_t iterations = 10000;
    std::chrono::duration<double, std::milli> encryption_duration(0);
    std::chrono::duration<double, std::milli> decryption_duration(0);
    std::chrono::duration<double, std::milli> serialization_duration(0);
    std::chrono::duration<double, std::milli> deserialization_duration(0);
    size_t ciphertext_size = 0;

    for (size_t i = 0; i < iterations; ++i) {
        // Encrypt
        auto start = std::chrono::steady_clock::now();
        ElGamalCiphertext ciphertext = encrypt(params, keypair.public_key, message, form);
        auto end = std::chrono::steady_clock::now();
        encryption_duration += end - start;

        // Serialize
        start = std::chrono::steady_clock::now();
        std::vector<unsigned char> serialized = serialize_ciphertext(params, ciphertext, form);
        end = std::chrono::steady_clock::now();
        serialization_duration += end - start;

        // Capture ciphertext size
        if (i == 0) {
            ciphertext_size = serialized.size();
        }

        // Deserialize
        start = std::chrono::steady_clock::now();
        ElGamalCiphertext deserialized_ciphertext = deserialize_ciphertext(params, serialized, form);
        end = std::chrono::steady_clock::now();
        deserialization_duration += end - start;

        // Decrypt
        start = std::chrono::steady_clock::now();
        EC_POINT* decrypted_message = decrypt(params, keypair.private_key, deserialized_ciphertext);
        end = std::chrono::steady_clock::now();
        decryption_duration += end - start;

        // Cleanup
        EC_POINT_free(ciphertext.C1);
        EC_POINT_free(ciphertext.C2);
        EC_POINT_free(deserialized_ciphertext.C1);
        EC_POINT_free(deserialized_ciphertext.C2);
        EC_POINT_free(decrypted_message);
    }

    // Print results
    std::cout << "Average encryption time: " << encryption_duration.count() / iterations << " ms\n";
    std::cout << "Average serialization time: " << serialization_duration.count() / iterations << " ms\n";
    std::cout << "Average deserialization time: " << deserialization_duration.count() / iterations << " ms\n";
    std::cout << "Average decryption time: " << decryption_duration.count() / iterations << " ms\n";
    std::cout << "Ciphertext size (" << form_str << "): " << ciphertext_size << " bytes\n";

    // Cleanup
    EC_POINT_free(message);
    EC_POINT_free(keypair.public_key);
    BN_free(keypair.private_key);
    EC_GROUP_free(params.group);
}


void test_encZero(){
    uint64_t setSize = 1<<10;
    
    // Create a new EC group for the secp256r1 curve
    EC_GROUP* group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    // Setup parameters
    ElGamalParams params = setup_elgamal(group);

    // Generate key pair
    ElGamalKeyPair keypair = generate_keypair(params);
    
    std::chrono::duration<double, std::milli> zero_time(0);


    auto start = std::chrono::steady_clock::now();

    std::vector<ElGamalCiphertext> encZeros = fasterEncZero(params, setSize, keypair.public_key);

    auto end = std::chrono::steady_clock::now();
    zero_time += end-start;

    std::cout << "Average Enc Zero time: " << zero_time.count() / setSize << " ms\n";
}


void test_multi_key_elgamal() {
    // Step 1: Setup elliptic curve group and ElGamal parameters
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // Use P-256 curve
    if (group == nullptr) {
        handleErrors();
    }
    ElGamalParams params = setup_elgamal(group);

    // Step 2: Generate multiple keypairs
    size_t num_keys = 3; // Number of parties
    auto [priv_keys, aggregate_pub_key] = generate_multi_keypair(params, num_keys);

    // Step 3: Generate a random elliptic curve point as the message
    EC_POINT* message = EC_POINT_new(group);
    if (message == nullptr) {
        handleErrors();
    }
    if (EC_POINT_copy(message, EC_GROUP_get0_generator(group)) != 1) { // Use generator as a test message
        handleErrors();
    }

    // Step 4: Encrypt the message using the aggregate public key
    ElGamalCiphertext ciphertext = encrypt(params, aggregate_pub_key, message, COMPRESSED);

    // Step 5: Perform partial decryption using each private key
    ElGamalCiphertext partially_decrypted_ciphertext = ciphertext;
    for (size_t i = 0; i < num_keys; ++i) {
        partially_decrypted_ciphertext = partial_decrypt(params, partially_decrypted_ciphertext, priv_keys[i]);
    }

    // Step 6: Fully decrypt the final ciphertext
    // EC_POINT* decrypted_message = decrypt(params, BN_value_one(), partially_decrypted_ciphertext);
    EC_POINT* decrypted_message = partially_decrypted_ciphertext.C2;
    // Step 7: Verify the correctness
    if (EC_POINT_cmp(group, message, decrypted_message, NULL) == 0) {
        std::cout << "Test passed: Decrypted message matches the original message." << std::endl;
    } else {
        std::cout << "Test failed: Decrypted message does not match the original message." << std::endl;
    }

    // Free resources
    EC_POINT_free(message);
    EC_POINT_free(decrypted_message);
    EC_POINT_free(aggregate_pub_key);
    for (BIGNUM* key : priv_keys) {
        BN_free(key);
    }
    EC_GROUP_free(group);
}

void test_compact_serialize_deserialize_vector() {
    // Setup ElGamal parameters and ciphertext vector
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // Use P-256 curve
    ElGamalParams params = setup_elgamal(group);


    // Step 2: Generate multiple keypairs
    size_t num_keys = 3; // Number of parties
    auto [priv_keys, aggregate_pub_key] = generate_multi_keypair(params, num_keys);

    // Create some example ciphertexts
    size_t num_ciphertexts = 3;
    std::vector<ElGamalCiphertext> ciphertexts;
    // Step 3: Generate a random elliptic curve point as the message
    EC_POINT* message = EC_POINT_new(group);
    if (message == nullptr) {
        handleErrors();
    }
    if (EC_POINT_copy(message, EC_GROUP_get0_generator(group)) != 1) { // Use generator as a test message
        handleErrors();
    }

    for (size_t i = 0; i < num_ciphertexts; ++i) {
        ElGamalCiphertext ciphertext = encrypt(params, aggregate_pub_key, message, COMPRESSED);
        ciphertexts.push_back(ciphertext);
    }

    // Serialize the vector
    std::vector<unsigned char> serialized_data = serialize_ciphertext_vector(params, ciphertexts,COMPRESSED);

    // Deserialize the vector
    std::vector<ElGamalCiphertext> deserialized_ciphertexts = deserialize_ciphertext_vector(params, serialized_data, COMPRESSED, num_ciphertexts);

    // Verify correctness
    for (size_t i = 0; i < num_ciphertexts; ++i) {
        if (EC_POINT_cmp(group, ciphertexts[i].C1, deserialized_ciphertexts[i].C1, NULL) != 0 ||
            EC_POINT_cmp(group, ciphertexts[i].C2, deserialized_ciphertexts[i].C2, NULL) != 0) {
            std::cout << "Test failed: Ciphertext mismatch at index " << i << std::endl;
        } else {
            std::cout << "Test passed for ciphertext " << i << std::endl;
        }
    }

    // Free resources
    for (auto& ciphertext : ciphertexts) {
        EC_POINT_free(ciphertext.C1);
        EC_POINT_free(ciphertext.C2);
    }
    EC_GROUP_free(group);
}

int main() {
    // Initialize OpenSSL
    initialize_openssl();

    // Test performance with uncompressed format
    test_elgamal_performance(UNCOMPRESSED);

    // Test performance with compressed format
    test_elgamal_performance(COMPRESSED);

    // test_encZero();

    test_multi_key_elgamal();

    test_compact_serialize_deserialize_vector();

    return 0;
}
