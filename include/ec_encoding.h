#ifndef EC_ENCODING_H
#define EC_ENCODING_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif

// k = number of low bits reserved for search
#define K_BITS 40
#define FIELD_BITS 256
#define MSG_BITS (FIELD_BITS - K_BITS)

// Encode message (BIGNUM) into EC_POINT using try-and-increment
// Returns newly allocated EC_POINT on success, or NULL on failure
EC_POINT* encode_message(const EC_GROUP* group, const BIGNUM* message, BN_CTX* ctx, uint64_t* increment_counter);

// Decode message from EC_POINT (only extracts high bits from x-coordinate)
int decode_message(const EC_GROUP* group, const EC_POINT* point, BIGNUM* message_out, BN_CTX* ctx);

#ifdef __cplusplus
}
#endif

#endif
