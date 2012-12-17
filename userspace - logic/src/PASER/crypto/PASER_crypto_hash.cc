/**
 *\class  		PASER_crypto_hash
 *@brief       	Class provides functions to compute and check the hash value of PASER messages.
 *
 *\authors    	Eugen.Paul | Mohamad.Sbeiti \@paser.info
 *
 *\copyright   (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld)
 *                  at Technische Universitaet Dortmund, Germany
 *                  http://www.kn.e-technik.tu-dortmund.de/
 *
 *
 *              This program is free software; you can redistribute it
 *              and/or modify it under the terms of the GNU General Public
 *              License as published by the Free Software Foundation; either
 *              version 2 of the License, or (at your option) any later
 *              version.
 *              For further information see file COPYING
 *              in the top level directory
 ********************************************************************************
 * This work is part of the secure wireless mesh networks framework, which is currently under development by CNI
 ********************************************************************************/

#include "PASER_crypto_hash.h"

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

//#define CRYPTOHASHTIMEMEASUREMENT

#ifdef CRYPTOHASHTIMEMEASUREMENT
#include <sys/time.h>
#define CRYTO_HASH_TIME_BEGIN \
    struct timeval a;\
    struct timeval b;\
    gettimeofday(&a, NULL);
#define CRYTO_HASH_TIME_END \
    gettimeofday(&b, NULL);\
    PASER_LOG_WRITE_LOG(0,"cryptoStats: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#else
#define CRYTO_HASH_TIME_BEGIN
#define CRYTO_HASH_TIME_END
#endif

PASER_crypto_hash::PASER_crypto_hash(PASER_global * paser_global) {
    pGlobal = paser_global;
}

int PASER_crypto_hash::computeHmacTURREQ(PASER_TU_RREQ * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
//printf("GTK:0x");
//for (int n = 0; n < GTK.len; n++)
//    printf("%02x", GTK.buf[n]);
//putchar('\n');
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    packet->hash = result;
    CRYTO_HASH_TIME_END
    return 1;
}

int PASER_crypto_hash::checkHmacTURREQ(PASER_TU_RREQ * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    if (memcmp(packet->hash, result, (sizeof(u_int8_t) * result_len)) == 0) {
        free(result);
        CRYTO_HASH_TIME_END
        return 1;
    }
    free(result);
    return 0;
}

int PASER_crypto_hash::computeHmacTURREP(PASER_TU_RREP * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    packet->hash = result;
    CRYTO_HASH_TIME_END
    return 1;
}

int PASER_crypto_hash::checkHmacTURREP(PASER_TU_RREP * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    if (memcmp(packet->hash, result, (sizeof(u_int8_t) * result_len)) == 0) {
        free(result);
        CRYTO_HASH_TIME_END
        return 1;
    }
    free(result);
    return 0;
}

int PASER_crypto_hash::computeHmacTURREPACK(PASER_TU_RREP_ACK * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    packet->hash = result;
    CRYTO_HASH_TIME_END
    return 1;
}

int PASER_crypto_hash::checkHmacTURREPACK(PASER_TU_RREP_ACK * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    if (memcmp(packet->hash, result, (sizeof(u_int8_t) * result_len)) == 0) {
        free(result);
        CRYTO_HASH_TIME_END
        return 1;
    }
    free(result);
    return 0;
}

int PASER_crypto_hash::computeHmacRERR(PASER_TB_RERR * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    packet->hash = result;
    CRYTO_HASH_TIME_END
    return 1;
}

int PASER_crypto_hash::checkHmacRERR(PASER_TB_RERR * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    if (memcmp(packet->hash, result, (sizeof(u_int8_t) * result_len)) == 0) {
        free(result);
        CRYTO_HASH_TIME_END
        return 1;
    }
    free(result);
    return 0;
}

int PASER_crypto_hash::computeHmacHELLO(PASER_TB_HELLO * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    packet->hash = result;
    CRYTO_HASH_TIME_END
    return 1;
}

int PASER_crypto_hash::checkHmacHELLO(PASER_TB_HELLO * packet, lv_block GTK) {
    CRYTO_HASH_TIME_BEGIN
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, GTK.buf, GTK.len, EVP_sha256(), NULL);

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    HMAC_Update(&ctx, data, len);
    free(data);

    u_int8_t *result = (u_int8_t *) malloc(sizeof(u_int8_t) * SHA256_DIGEST_LENGTH);
    u_int32_t result_len = SHA256_DIGEST_LENGTH;
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);

    if (memcmp(packet->hash, result, (sizeof(u_int8_t) * result_len)) == 0) {
        free(result);
        CRYTO_HASH_TIME_END
        return 1;
    }
    free(result);
    return 0;
}
