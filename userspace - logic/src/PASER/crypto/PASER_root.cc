/**
 *\class  		PASER_root
 *@brief       	Class provides function to generate secrets, compute and check authentication trees.
 *
 *\authors    	Eugen.Paul | Mohamad.Sbeiti \@paser.info
 *
 *\copyright   (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld)
 *                  at Technische Universitaet Dortmund, Germany
 *                  http:///www.kn.e-technik.tu-dortmund.de/
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

#include "PASER_root.h"

#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

//#define CRYPTOROOTTIMEMEASUREMENT

#ifdef CRYPTOROOTTIMEMEASUREMENT
#include <sys/time.h>
#define CRYTO_ROOT_TIME_BEGIN \
    struct timeval a_time;\
    struct timeval b_time;\
    gettimeofday(&a_time, NULL);
#define CRYTO_ROOT_TIME_END \
    gettimeofday(&b_time, NULL);\
    PASER_LOG_WRITE_LOG(0,"cryptoStats: b-a=%ld.%6ld\n", b_time.tv_usec-a_time.tv_usec>0?b_time.tv_sec-a_time.tv_sec:b_time.tv_sec-a_time.tv_sec-1, b_time.tv_usec-a_time.tv_usec>0?b_time.tv_usec-a_time.tv_usec:b_time.tv_usec-a_time.tv_usec+1000000);
#else
#define CRYTO_ROOT_TIME_BEGIN
#define CRYTO_ROOT_TIME_END
#endif

PASER_root::PASER_root(PASER_global *paser_global) {
    pGlobal = paser_global;
}

PASER_root::~PASER_root() {
    clearLists();
}

void PASER_root::clearLists() {
    for (std::list<uint8_t *>::iterator it = secret_list.begin(); it != secret_list.end(); it++) {
        uint8_t *data = (uint8_t *) *it;
        free(data);
    }
    secret_list.clear();
    for (std::list<uint8_t *>::iterator it = tree.begin(); it != tree.end(); it++) {
        uint8_t *data = (uint8_t *) *it;
        free(data);
    }
    tree.clear();
}

bool PASER_root::init(int n) {
    iv_nr = 0;
    if (n > 31)
        return false;
    param = n;

    return regenerate();
}

bool PASER_root::regenerate() {
    CRYTO_ROOT_TIME_BEGIN
    clearLists();
    int n = param;
    int b = 1;
    b = b << n;
    // Generate secrets
    for (int i = 0; i < b; i++) {
        uint8_t *buf = (uint8_t *) malloc((sizeof(uint8_t) * PASER_SECRET_LEN));
        // Generate random bites
        if (RAND_bytes(buf, PASER_SECRET_LEN) != 1) {
            return false;
        }
        // Set IV
        int count = i << (32 - n);
        for (int j = 0; j < n; j++) {
            int block_nr = j / 8;
            int bit_nr = j % 8;
            uint8_t del = 0x01;
            del = ~(del << (8 - bit_nr - 1));

            uint8_t set_bit = 0x01 & (count >> (31 - j));
            set_bit = set_bit << (8 - bit_nr - 1);
            buf[block_nr] = buf[block_nr] & del;
            buf[block_nr] = buf[block_nr] | set_bit;
        }
        // Push generated secret to secret_list
        secret_list.push_back(buf);

    }

//    root_elem = root_getHashTreeValue(0, secret_list.size()-1);
//    printf("root_elem:0x");
//    for (int n = 0; n < SHA256_DIGEST_LENGTH; n++)
//        printf("%02x", root_elem[n]);
//    putchar('\n');

// Compute authentication tree
    calculateTree();
    CRYTO_ROOT_TIME_END
    return true;
}

void PASER_root::calculateTree() {
    for (std::list<uint8_t *>::iterator it = secret_list.begin(); it != secret_list.end(); it++) {
        uint8_t *data = getOneHash((uint8_t *) *it, PASER_SECRET_LEN);
        tree.push_back(data);
    }

    for (int i = param; i > 0; i--) {
        int steps = 1 << (i - 1);
        std::list<uint8_t *>::iterator it = tree.begin();
        std::list<uint8_t *> temp;
        for (int k = 0; k < steps; k++) {
            uint8_t *data1 = (uint8_t *) *it;
            it++;
            uint8_t *data2 = (uint8_t *) *it;
            it++;
            temp.push_back(getHash(data1, data2));
        }
        tree.insert(tree.begin(), temp.begin(), temp.end());
    }

    root_elem = tree.front();
}

uint8_t* PASER_root::getRoot() {
    uint8_t *buf = (uint8_t *) malloc((sizeof(uint8_t) * PASER_SECRET_HASH_LEN));
    memcpy(buf, root_elem, (sizeof(uint8_t) * PASER_SECRET_HASH_LEN));
    return buf;
}

std::list<uint8_t *> PASER_root::getNextSecret(int *nr, uint8_t *secret) {
    std::list<uint8_t *> iv;
    std::list<uint8_t *>::iterator it;
    if (iv_nr >= secret_list.size()) {
        //generate new authentication tree and send root message
        regenerate();
        iv_nr = 0;
        //set timeout and send root
        struct timeval now;
        pGlobal->getPASERtimeofday(&now);

        for(u_int32_t i = 0; i<pGlobal->getPaser_configuration()->getRootRepetitions(); i++){
            PASER_timer_packet *timer = new PASER_timer_packet();
            timer->handler = PASER_ROOT;
            timer->data = NULL;
            timer->destAddr.s_addr = PASER_BROADCAST;
            timer->timeout = timeval_add(now, pGlobal->getPaser_configuration()->getRootRepetitionsTimeout()*(i+1));
            pGlobal->getTimer_queue()->timer_add(timer);
            pGlobal->getTimer_queue()->timer_sort();
        }
        pGlobal->getPacketSender()->send_root();
        pGlobal->incSeqNr();
    }
    it = tree.end();
    it--;
    int point = iv_nr;
    for (int i = param; i > 0; i--) {
        int steps = 1 << i;
        for (int k = steps - 1; k >= 0; k--) {
            if (k == point) {
                if (point % 2 == 0) {
                    it++;
                    uint8_t *buf = (uint8_t *) malloc((sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
                    uint8_t *buf2 = (uint8_t *) *it;
                    memcpy(buf, buf2, (sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
                    iv.push_back(buf);
                    it--;
                } else {
                    it--;
                    uint8_t *buf = (uint8_t *) malloc((sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
                    uint8_t *buf2 = (uint8_t *) *it;
                    memcpy(buf, buf2, (sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
                    iv.push_back(buf);
                    it++;
                }
            }
            it--;
        }
        point = point / 2;
    }
    uint32_t count = 0;
    for (std::list<uint8_t *>::iterator IT = secret_list.begin(); IT != secret_list.end(); IT++) {
        if (count == iv_nr) {
            uint8_t *temp = (uint8_t *) *IT;
            memcpy(secret, temp, (sizeof(uint8_t) * PASER_SECRET_LEN));
            break;
        }
        count++;
    }
    *nr = iv_nr;
    iv_nr++;
//    if(iv_nr >= secret_list.size()){
//        regenerate();
//        iv_nr = 0;
//    }

    return iv;
}

int PASER_root::getIV() {
    return iv_nr;
}

uint8_t *PASER_root::getOneHash(uint8_t* h1, int len) {
    SHA256_CTX ctx;
    uint8_t *results = (uint8_t *) malloc(sizeof(uint8_t) * SHA256_DIGEST_LENGTH);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (uint8_t *) h1, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
    SHA256_Final(results, &ctx);
    return results;
}

uint8_t *PASER_root::getHash(uint8_t* h1, uint8_t* h2) {
    SHA256_CTX ctx;
    uint8_t *results = (uint8_t *) malloc(sizeof(uint8_t) * SHA256_DIGEST_LENGTH);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (uint8_t *) h1, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
    SHA256_Update(&ctx, (uint8_t *) h2, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
    SHA256_Final(results, &ctx);
    return results;
}

int PASER_root::checkRoot(uint8_t* root, uint8_t* secret, std::list<uint8_t *> iv_list, uint32_t iv, uint32_t *newIV) {
    CRYTO_ROOT_TIME_BEGIN
    uint32_t new_iv = 0;
    uint8_t temp[4] = { 0x00, 0x00, 0x00, 0x00 };
    uint8_t * temp1 = secret;
    for (int i = 0; i < 4; i++) {
        memcpy(&temp[3 - i], temp1, 1);
        temp1++;
    }
    memcpy(&new_iv, temp, 4);
    new_iv = new_iv >> (SHA256_DIGEST_LENGTH - param);
    if (iv > 0 && iv > new_iv) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Old IV\n");
        return 0;
    }

    *newIV = new_iv + 1;

    uint8_t *buf;
    buf = getOneHash(secret, PASER_SECRET_LEN);
    for (std::list<uint8_t *>::iterator it = iv_list.begin(); it != iv_list.end(); it++) {
        if (new_iv % 2 == 1) {
            uint8_t * temp = getHash((uint8_t *) *it, buf);
            free(buf);
            buf = temp;
        } else {
            uint8_t * temp = getHash(buf, (uint8_t *) *it);
            free(buf);
            buf = temp;
        }
        new_iv = new_iv / 2;
    }

    if (memcmp(root, buf, (sizeof(uint8_t) * SHA256_DIGEST_LENGTH)) == 0) {
        free(buf);
        CRYTO_ROOT_TIME_END
        return 1;
    }

    free(buf);
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Wrong hash value\n");
    return 0;
}
