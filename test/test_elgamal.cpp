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
    uint64_t setSize = 1<<18;
    
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

int main() {
    // Initialize OpenSSL
    initialize_openssl();

    // Test performance with uncompressed format
    test_elgamal_performance(UNCOMPRESSED);

    // Test performance with compressed format
    test_elgamal_performance(COMPRESSED);

    test_encZero();

    return 0;
}
