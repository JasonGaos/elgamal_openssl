#include <iostream>
#include <chrono>
#include <limits>
#include "ec_encoding.h"
#include "ec_curve.h"
#include "ec_elgamal.h"

void test_encoding_performance() {
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* group = create_group(NID_X9_62_prime256v1);
    if (!group) {
        std::cerr << "Failed to create EC_GROUP" << std::endl;
        return;
    }

    size_t iterations = 10000;
    std::chrono::duration<double, std::milli> encoding_duration(0);
    std::chrono::duration<double, std::milli> decoding_duration(0);

    uint64_t total_trials = 0;
    uint64_t min_trials = std::numeric_limits<uint64_t>::max();
    uint64_t max_trials = 0;

    for (size_t i = 0; i < iterations; ++i) {
        // Generate random message (224-bit random integer)
        BIGNUM* message = BN_new();
        BN_rand(message, MSG_BITS, 0, 0);

        uint64_t trials = 0;

        // Encoding
        auto start = std::chrono::steady_clock::now();
        EC_POINT* P = encode_message(group, message, ctx, &trials);
        auto end = std::chrono::steady_clock::now();
        encoding_duration += end - start;

        if (!P) {
            std::cerr << "Encoding failed!" << std::endl;
            BN_free(message);
            continue;
        }

        // Track trials
        total_trials += trials;
        if (trials < min_trials) min_trials = trials;
        if (trials > max_trials) max_trials = trials;

        // Decoding
        BIGNUM* recovered = BN_new();
        start = std::chrono::steady_clock::now();
        decode_message(group, P, recovered, ctx);
        end = std::chrono::steady_clock::now();
        decoding_duration += end - start;

        // Sanity check
        if (BN_cmp(message, recovered) != 0) {
            std::cerr << "Error: Decoded message doesn't match!" << std::endl;
        }

        // Cleanup
        BN_free(message);
        BN_free(recovered);
        EC_POINT_free(P);
    }

    std::cout << "\nEncoding/Decoding Performance over " << iterations << " iterations:\n";
    std::cout << "Average encoding time: " << encoding_duration.count() / iterations << " ms\n";
    std::cout << "Average decoding time: " << decoding_duration.count() / iterations << " ms\n";
    std::cout << "Average increment trials: " << static_cast<double>(total_trials) / iterations << std::endl;
    std::cout << "Min increment trials: " << min_trials << std::endl;
    std::cout << "Max increment trials: " << max_trials << std::endl;

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
}

int main() {
    test_encoding_performance();
    return 0;
}