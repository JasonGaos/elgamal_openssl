#include "ec_encoding.h"
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <cstdio>

// Internal helper: check quadratic residue using Euler’s criterion
static int is_quadratic_residue(const BIGNUM* rhs, const BIGNUM* p, BN_CTX* ctx) {
    BIGNUM* exp = BN_new();
    BIGNUM* result = BN_new();
    int ret = 0;

    BN_copy(exp, p);
    BN_sub_word(exp, 1);
    BN_rshift1(exp, exp);  // exp = (p-1)/2

    if (BN_mod_exp(result, rhs, exp, p, ctx) == 0)
        goto cleanup;

    ret = BN_is_one(result);

cleanup:
    BN_free(exp);
    BN_free(result);
    return ret;
}

EC_POINT* encode_message(const EC_GROUP* group, const BIGNUM* message, BN_CTX* ctx, uint64_t* increment_counter) {
    int success = 0;
    EC_POINT* P = NULL;
    BIGNUM *x = NULL, *rhs = NULL;
    EC_POINT *tmp = NULL;
    const BIGNUM* p = EC_GROUP_get0_field(group);

    x = BN_new();
    rhs = BN_new();
    tmp = EC_POINT_new(group);

    for (uint64_t counter = 0; counter < (1ULL << K_BITS); counter++) {
        BN_copy(x, message);
        BN_lshift(x, x, K_BITS);  // x = message << k
        BN_add_word(x, counter);  // add counter to low bits

        if (!EC_POINT_set_compressed_coordinates(group, tmp, x, 0, ctx)) {
            continue;
        }
        if (!EC_POINT_is_on_curve(group, tmp, ctx)) {
            continue;
        }

        // We found a valid x
        P = EC_POINT_new(group);
        if (EC_POINT_set_compressed_coordinates(group, P, x, 0, ctx) == 0) {
            EC_POINT_free(P);
            P = NULL;
            continue;
        }
        if (EC_POINT_is_on_curve(group, P, ctx)) {
            success = 1;
            if (increment_counter) {
                *increment_counter = counter + 1;  // count how many trials were needed
            }
            break;
        }
    }

    BN_free(x);
    BN_free(rhs);
    EC_POINT_free(tmp);

    return success ? P : NULL;
}


int decode_message(const EC_GROUP* group, const EC_POINT* point, BIGNUM* message_out, BN_CTX* ctx) {
    BIGNUM* x = BN_new();
    int ret = 0;

    if (EC_POINT_get_affine_coordinates(group, point, x, NULL, ctx) == 0)
        goto cleanup;

    BN_rshift(message_out, x, K_BITS);
    ret = 1;

cleanup:
    BN_free(x);
    return ret;
}
