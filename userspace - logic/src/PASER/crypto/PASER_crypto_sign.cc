/**
 *\class  		PASER_crypto_sign
 *@brief       	Class provides function to compute and check signatures of PASER messages.
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

#include "PASER_crypto_sign.h"

#include <stdio.h>
#include <list>

#include <openssl/pem.h>

#ifndef __unix__
extern"C"
{
#include<openssl/applink.c>
}
#endif

//#define CRYPTOTIMEMEASUREMENT

#ifdef CRYPTOTIMEMEASUREMENT
#include <sys/time.h>
#define CRYTO_TIME_BEGIN \
    struct timeval a;\
    struct timeval b;\
    gettimeofday(&a, NULL);
#define CRYTO_TIME_END \
    gettimeofday(&b, NULL);\
    PASER_LOG_WRITE_LOG(0,"cryptoStats: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#else
#define CRYTO_TIME_BEGIN
#define CRYTO_TIME_END
#endif

PASER_crypto_sign::PASER_crypto_sign(char *certPath, char *keyPath, char *CAcertPath, PASER_global * paser_global) {
    pGlobal = paser_global;

    PASER_LOG_WRITE_LOG(PASER_LOG_INIT_MODULES, "Initialize \"crypto sing\" module\n");
    FILE *fp;

    fp = fopen(keyPath, "r");
    if (fp == NULL) {
        PASER_LOG_WRITE_LOG(0, "Cann't load private key file: %s\n", keyPath);
        std::cout << "Cann't load private key file: " << keyPath << std::endl;
        exit(1);
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (pkey == NULL) {
        PASER_LOG_WRITE_LOG(0, "Cann't load private key from file: %s\n", keyPath);
        std::cout << "Cann't load private key from file: " << keyPath << std::endl;
        exit(1);
    }
    fclose(fp);

    /* Read cert */
    fp = fopen(certPath, "r");
    if (fp == NULL) {
        PASER_LOG_WRITE_LOG(0, "Cann't load certificate file: %s\n", certPath);
        std::cout << "Cann't load certificate file: " << certPath << std::endl;
        exit(1);
    }

    x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (x509 == NULL) {
        PASER_LOG_WRITE_LOG(0, "Cann't load certificate from file: %s\n", certPath);
        std::cout << "Cann't load certificate from file: " << certPath << std::endl;
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        exit(1);
    }

    //read CA_file
    fp = fopen(CAcertPath, "r");
    if (fp == NULL) {
        PASER_LOG_WRITE_LOG(0, "Cann't load CA certificate file: %s\n", CAcertPath);
        std::cout << "Cann't load CA certificate file: " << CAcertPath << std::endl;
        exit(1);
    }
    ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (ca_cert == NULL) {
        PASER_LOG_WRITE_LOG(0, "Cann't load CA certificate from file: %s\n", CAcertPath);
        std::cout << "Cann't load CA certificate from file: " << CAcertPath << std::endl;
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        exit(1);
    }

    crl = NULL;
}

PASER_crypto_sign::~PASER_crypto_sign() {
    if (x509) {
        X509_free(x509);
    }
    x509 = NULL;
    if (ca_cert) {
        X509_free(ca_cert);
    }
    ca_cert = NULL;
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (crl) {
        X509_CRL_free(crl);
    }
}

int PASER_crypto_sign::getCert(lv_block *cert) {
    int len;
    unsigned char *buf;
    buf = NULL;
    len = i2d_X509(x509, &buf);
    if (len < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't convert certificate from x509 to DER format\n");
        return 0;
    }
    u_int8_t *buf_cert = (u_int8_t *) malloc(sizeof(u_int8_t) * len);
    memcpy(buf_cert, buf, (sizeof(u_int8_t) * len));
    cert->buf = buf_cert;
    cert->len = len;
#ifdef __unix__
    free(buf);
#endif
    return 1;
}

int PASER_crypto_sign::setCRL(lv_block in) {
    if (in.buf == NULL) {
        return 0;
    }
    X509_CRL *x;
    const u_int8_t *buf, *p;
    int len;
    buf = in.buf;
    len = in.len;
    p = buf;
    x = d2i_X509_CRL(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't convert CRL from DER to x509 format\n");
        return 0;
    }
    crl = x;
    return 1;
}

int PASER_crypto_sign::signUBRREQ(PASER_UB_RREQ * packet) {
    CRYTO_TIME_BEGIN
    u_int32_t sig_len = PASER_sign_len;
    u_int8_t *sign = (u_int8_t *) malloc(sizeof(u_int8_t) * sig_len);
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_SignInit(md_ctx, EVP_sha1());

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    EVP_SignUpdate(md_ctx, data, len);
    free(data);

    int err = EVP_SignFinal(md_ctx, sign, &sig_len, pkey);
    EVP_MD_CTX_destroy(md_ctx);
    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't sign an UBRREQ packet\n");
        return 0;
    }
    if (packet->sign.buf != NULL) {
        free(packet->sign.buf);
    }
    packet->sign.buf = sign;
    packet->sign.len = sig_len;
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::checkSignUBRREQ(PASER_UB_RREQ * packet) {
    CRYTO_TIME_BEGIN
    X509 *x;
    const u_int8_t *buf, *p;
    int len;
    buf = packet->certForw.buf;
    len = packet->certForw.len;
    p = buf;
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't read a certificate from UBRREQ packet\n");
        return 0;
    }
    if (checkOneCert(x) != 1) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "UBRREQ packet contains invalid certificate\n");
        X509_free(x);
        return 0;
    }
    EVP_PKEY *pubKey = X509_get_pubkey(x);
    X509_free(x);
    u_int32_t sig_len = packet->sign.len;
    u_int8_t *sign = packet->sign.buf;
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_VerifyInit(md_ctx, EVP_sha1());

    int packet_len = 0;
    u_int8_t *data = packet->toByteArray(&packet_len);
    EVP_VerifyUpdate(md_ctx, data, packet_len);
    free(data);

    int err = EVP_VerifyFinal(md_ctx, sign, sig_len, pubKey);
    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_destroy(md_ctx);

    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "UBRREQ packet contains invalid signature\n");
        return 0;
    }
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::signUURREP(PASER_UU_RREP * packet) {
    CRYTO_TIME_BEGIN
    u_int32_t sig_len = PASER_sign_len;
    u_int8_t *sign = (u_int8_t *) malloc(sizeof(u_int8_t) * sig_len);
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_SignInit(md_ctx, EVP_sha1());

    int packet_len = 0;
    u_int8_t *data = packet->toByteArray(&packet_len);
    EVP_SignUpdate(md_ctx, data, packet_len);

    int err = EVP_SignFinal(md_ctx, sign, &sig_len, pkey);
    EVP_MD_CTX_destroy(md_ctx);
    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't sign an UURREP packet\n");
        return 0;
    }
    if (packet->sign.buf != NULL) {
        free(packet->sign.buf);
    }
    packet->sign.buf = sign;
    packet->sign.len = sig_len;

    free(data);
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::checkSignUURREP(PASER_UU_RREP * packet) {
    CRYTO_TIME_BEGIN
    X509 *x;
    const u_int8_t *buf, *p;
    int len;
    buf = packet->certForw.buf;
    len = packet->certForw.len;
    p = buf;
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't read a certificate from UURREP packet\n");
        return 0;
    }
    if (checkOneCert(x) != 1) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "UURREP packet contains invalid certificate\n");
        X509_free(x);
        return 0;
    }
    EVP_PKEY *pubKey = X509_get_pubkey(x);
    X509_free(x);
    u_int32_t sig_len = packet->sign.len;
    u_int8_t *sign = packet->sign.buf;
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_VerifyInit(md_ctx, EVP_sha1());

    int packet_len = 0;
    u_int8_t *data = packet->toByteArray(&packet_len);
    EVP_VerifyUpdate(md_ctx, data, packet_len);

    free(data);
    int err = EVP_VerifyFinal(md_ctx, sign, sig_len, pubKey);
    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_destroy(md_ctx);

    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "UURREP packet contains invalid signature\n");
        return 0;
    }
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::signB_ROOT(PASER_B_ROOT * packet) {
    CRYTO_TIME_BEGIN
    u_int32_t sig_len = PASER_sign_len;
    u_int8_t *sign = (u_int8_t *) malloc(sizeof(u_int8_t) * sig_len);
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_SignInit(md_ctx, EVP_sha1());

    int packet_len = 0;
    u_int8_t *data = packet->toByteArray(&packet_len);
    EVP_SignUpdate(md_ctx, data, packet_len);

    int err = EVP_SignFinal(md_ctx, sign, &sig_len, pkey);
    EVP_MD_CTX_destroy(md_ctx);
    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't sign an B_ROOT packet\n");
        return 0;
    }
    if (packet->sign.buf != NULL) {
        free(packet->sign.buf);
    }
    packet->sign.buf = sign;
    packet->sign.len = sig_len;
    free(data);
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::checkSignB_ROOT(PASER_B_ROOT * packet) {
    CRYTO_TIME_BEGIN
    X509 *x;
    const u_int8_t *buf, *p;
    int len;
    buf = packet->cert.buf;
    len = packet->cert.len;
    p = buf;
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't read a certificate from B_ROOT packet\n");
        return 0;
    }
    if (checkOneCert(x) != 1) {
        X509_free(x);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "B_ROOT packet contains invalid certificate\n");
        return 0;
    }
    EVP_PKEY *pubKey = X509_get_pubkey(x);
    X509_free(x);
    u_int32_t sig_len = packet->sign.len;
    u_int8_t *sign = packet->sign.buf;
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_VerifyInit(md_ctx, EVP_sha1());

    int packet_len = 0;
    u_int8_t *data = packet->toByteArray(&packet_len);
    EVP_VerifyUpdate(md_ctx, data, packet_len);
    free(data);
    int err = EVP_VerifyFinal(md_ctx, sign, sig_len, pubKey);
    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_destroy(md_ctx);

    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "B_ROOT packet contains invalid signature\n");
        return 0;
    }
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::checkSignRESET(PASER_RESET * packet) {
    CRYTO_TIME_BEGIN
    X509 *x;
    const u_int8_t *buf, *p;
    int len;
    buf = packet->cert.buf;
    len = packet->cert.len;
    p = buf;
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't read a certificate from RESET packet\n");
        return 0;
    }
    if (checkOneCert(x) != 1) {
        X509_free(x);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "RESET packet contains invalid certificate\n");
        return 0;
    }
    if (isKdcCert(x) != 1) {
        X509_free(x);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "RESET certificate is NOT a KDC certificate\n");
        return 0;
    }
    EVP_PKEY *pubKey = X509_get_pubkey(x);
    X509_free(x);
    u_int32_t sig_len = packet->sign.len;
    u_int8_t *sign = packet->sign.buf;
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_VerifyInit(md_ctx, EVP_sha1());

    int packet_len = 0;
    u_int8_t *data = packet->toByteArray(&packet_len);
    EVP_VerifyUpdate(md_ctx, data, packet_len);
    free(data);
    int err = EVP_VerifyFinal(md_ctx, sign, sig_len, pubKey);
    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_destroy(md_ctx);

    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "RESET packet contains invalid signature\n");
        return 0;
    }
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::checkSignGTKResponse(PASER_GTKREP * packet) {
    CRYTO_TIME_BEGIN
    X509 *x;
    const u_int8_t *buf, *p;
    int len;
    buf = packet->kdc_cert.buf;
    len = packet->kdc_cert.len;
    p = buf;
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't read a certificate from GTKResponse packet\n");
        return 0;
    }
    if (checkOneCert(x) != 1) {
        X509_free(x);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "GTKResponse packet contains invalid certificate\n");
        return 0;
    }
    if (isKdcCert(x) != 1) {
        X509_free(x);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "GTKResponse certificate is NOT a KDC certificate\n");
        return 0;
    }
    EVP_PKEY *pubKey = X509_get_pubkey(x);
    X509_free(x);
    u_int32_t sig_len = packet->sign.len;
    u_int8_t *sign = packet->sign.buf;
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_VerifyInit(md_ctx, EVP_sha1());

    int packet_len = 0;
    u_int8_t *data = packet->toByteArray(&packet_len);
    EVP_VerifyUpdate(md_ctx, data, packet_len);
    free(data);
    int err = EVP_VerifyFinal(md_ctx, sign, sig_len, pubKey);
    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_destroy(md_ctx);

    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "GTKResponse packet contains invalid signature\n");
        return 0;
    }
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::checkSignKDC(kdc_block data) {
    CRYTO_TIME_BEGIN
    if (data.CRL.buf == NULL) {
        return 0;
    }
    X509_CRL *crl_x;
    const u_int8_t *buf, *p;
    int len;
    buf = data.CRL.buf;
    len = data.CRL.len;
    p = buf;
    crl_x = d2i_X509_CRL(NULL, &p, len);
    if (crl_x == NULL) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't read a CRL from KDC block packet\n");
        return 0;
    }

    //read KDC cert
    X509* kdc_cert = extractCert(data.cert_kdc);
    if (kdc_cert == NULL) {
        X509_CRL_free(crl_x);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't read a certificate from KDC block packet\n");
        return 0;
    }
    if (checkOneCert(kdc_cert) != 1) {
        X509_CRL_free(crl_x);
        X509_free(kdc_cert);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "KDC block contains invalid certificate\n");
        return 0;
    }
    if (isKdcCert(kdc_cert) != 1) {
        X509_CRL_free(crl_x);
        X509_free(kdc_cert);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "KDC block certificate is NOT a KDC certificate\n");
        return 0;
    }

    //check KDC cert
    X509_STORE *ca_store;
    ca_store = X509_STORE_new();
    if (X509_STORE_add_cert(ca_store, ca_cert) != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        X509_CRL_free(crl_x);
        X509_free(kdc_cert);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't add certificate to X509_STORE\n");
        return 0;
    }
    if (X509_STORE_set_default_paths(ca_store) != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        X509_CRL_free(crl_x);
        X509_free(kdc_cert);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't set default path in X509_STORE\n");
        return 0;
    }
    if (crl_x) {
        if (X509_STORE_add_crl(ca_store, crl_x) != 1) {
            ERR_print_errors_fp(PASER_LOG_GET_FD);
            X509_CRL_free(crl_x);
            X509_free(kdc_cert);
            PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't add CRL to X509_STORE\n");
            return 0;
        }
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
        //set the flag of the store so that CRLs are consulted
        X509_STORE_set_flags(ca_store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif
    }

    X509_STORE_CTX *verify_ctx;
    //create a verification context and initialize it
    if (!(verify_ctx = X509_STORE_CTX_new())) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        X509_CRL_free(crl_x);
        X509_free(kdc_cert);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't create verification context\n");
        return 0;
    }
    //X509_STORE_CTX_init did not return an error condition in prior versions
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
    if (X509_STORE_CTX_init(verify_ctx, ca_store, kdc_cert, NULL) != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        X509_CRL_free(crl_x);
        X509_free(kdc_cert);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't initialize verification context\n");
        return 0;
    }
#else
    X509_STORE_CTX_init(verify_ctx, ca_store, kdc_cert, NULL);
#endif

    //verify the certificate
    if (X509_verify_cert(verify_ctx) != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        X509_STORE_free(ca_store);
        X509_STORE_CTX_free(verify_ctx);
        X509_CRL_free(crl_x);
        X509_free(kdc_cert);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't verify the certificate\n");
        return 0;
    } else {
        X509_STORE_free(ca_store);
        X509_STORE_CTX_free(verify_ctx);
    }

    //check KDC Sign
    EVP_PKEY *pubKey = X509_get_pubkey(kdc_cert);
    X509_free(kdc_cert);
    u_int32_t sig_len = data.sign.len;
    u_int8_t *sign = data.sign.buf;
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_VerifyInit(md_ctx, EVP_sha1());

    int kdc_data_len = data.GTK.len + sizeof(data.nonce) + sizeof(data.key_nr) + data.CRL.len + data.cert_kdc.len;
    u_int8_t *temp = (u_int8_t*) malloc(kdc_data_len);
    u_int8_t *tempData = temp;
    memcpy(temp, (u_int8_t *) data.GTK.buf, data.GTK.len);
    temp += data.GTK.len;
    memcpy(temp, (u_int8_t *) &data.nonce, sizeof(data.nonce));
    temp += sizeof(data.nonce);
    memcpy(temp, (u_int8_t *) &data.key_nr, sizeof(data.key_nr));
    temp += sizeof(data.key_nr);
    memcpy(temp, (u_int8_t *) data.CRL.buf, data.CRL.len);
    temp += data.CRL.len;
    memcpy(temp, (u_int8_t *) data.cert_kdc.buf, data.cert_kdc.len);
    temp += data.cert_kdc.len;
    EVP_SignUpdate(md_ctx, tempData, kdc_data_len);
    free(tempData);

    int err = EVP_VerifyFinal(md_ctx, sign, sig_len, pubKey);
    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_destroy(md_ctx);

    if (err != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        X509_CRL_free(crl_x);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "KDC block contains invalid signature\n");
        return 0;
    }
    //aktualisiere CRL
    if (crl) {
        X509_CRL_free(crl);
    }
    crl = crl_x;
    CRYTO_TIME_END
    return 1;
}

X509* PASER_crypto_sign::extractCert(lv_block cert) {
    if (cert.buf == NULL) {
        return NULL;
    }
    X509 *x;
    const u_int8_t *buf, *p;
    int len;
    buf = cert.buf;
    len = cert.len;
    p = buf;
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't extract certificate from DER format\n");
        return NULL;
    }

    return x;
}

bool PASER_crypto_sign::isGwCert(X509 *cert) {
    if (cert == NULL) {
        return 0x00;
    }
    ASN1_IA5STRING *nscomment;
    nscomment = (ASN1_IA5STRING *) X509_get_ext_d2i(cert, NID_netscape_comment, NULL, NULL);
    if (nscomment == NULL) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Certificate contains not a NSCOMMENT field\n");
        return 0x00;
    }
    if (memcmp(nscomment, "gateway:true", 13)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Certificate contains wrong NSCOMMENT field\n");
        ASN1_IA5STRING_free(nscomment);
        return 0x01;
    }
    ASN1_IA5STRING_free(nscomment);
    PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Certificate contains wrong NSCOMMENT field\n");
    return 0x00;
}

bool PASER_crypto_sign::isKdcCert(X509 *cert) {
    if (cert == NULL) {
        return 0x00;
    }
    ASN1_IA5STRING *nscomment;
    nscomment = (ASN1_IA5STRING *) X509_get_ext_d2i(cert, NID_netscape_comment, NULL, NULL);
    if (nscomment == NULL) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Certificate contains not a NSCOMMENT field\n");
        return 0x00;
    }
    if (memcmp(nscomment, "kdc:true", 9)) {
        ASN1_IA5STRING_free(nscomment);
        return 0x01;
    }
    ASN1_IA5STRING_free(nscomment);
    PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Certificate contains wrong NSCOMMENT field\n");
    return 0x00;
}

int PASER_crypto_sign::rsa_encrypt(lv_block in, lv_block *out, X509 *cert) {
    CRYTO_TIME_BEGIN
    EVP_PKEY *pubKey;
    if (cert != NULL) {
        pubKey = X509_get_pubkey(cert);
    } else {
        pubKey = X509_get_pubkey(x509);
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pubKey);
    out->buf = (u_int8_t *) malloc(RSA_size(rsa));
    int i = RSA_public_encrypt(in.len, in.buf, out->buf, rsa, RSA_PKCS1_PADDING);
    out->len = i;
    EVP_PKEY_free(pubKey);
    RSA_free(rsa);
    if (i < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't encrypt lv_block\n");
        return 0;
    }
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::rsa_dencrypt(lv_block in, lv_block *out) {
    CRYTO_TIME_BEGIN
    if (out->buf != NULL && out->len > 0) {
        free(out->buf);
        out->len = 0;
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    u_int8_t *buf = (u_int8_t *) malloc(RSA_size(rsa));
    int i = RSA_private_decrypt(in.len, in.buf, buf, rsa, RSA_PKCS1_PADDING);
    if (i < 0) {
        free(buf);
        RSA_free(rsa);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't dencrypt lv_block\n");
        return 0;
    }
    out->len = i;
    out->buf = (u_int8_t *) malloc(i);
    memcpy(out->buf, buf, i);
    free(buf);
    RSA_free(rsa);
    CRYTO_TIME_END
    return 1;
}

int PASER_crypto_sign::checkOneCert(X509 *cert) {
    CRYTO_TIME_BEGIN
    if (!cert) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Certificate == NULL\n");
        return 0;
    }
    X509_STORE *ca_store;
    ca_store = X509_STORE_new();
    if (X509_STORE_add_cert(ca_store, ca_cert) != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't add certificate to X509_STORE\n");
        return 0;
    }
    if (X509_STORE_set_default_paths(ca_store) != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't set default path in X509_STORE\n");
        return 0;
    }
    if (crl) {
        if (X509_STORE_add_crl(ca_store, crl) != 1) {
            ERR_print_errors_fp(PASER_LOG_GET_FD);
            PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't add CRL to X509_STORE\n");
            return 0;
        }
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
        //set the flag of the store so that CRLs are consulted
        X509_STORE_set_flags(ca_store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif
    }

    X509_STORE_CTX *verify_ctx;
    //create a verification context and initialize it
    if (!(verify_ctx = X509_STORE_CTX_new())) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't create verification context\n");
        return 0;
    }
    //X509_STORE_CTX_init did not return an error condition in prior versions
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
    if (X509_STORE_CTX_init(verify_ctx, ca_store, cert, NULL) != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Cann't initialize verification context\n");
        return 0;
    }
#else
    X509_STORE_CTX_init(verify_ctx, ca_store, cert, NULL);
#endif

    //verify the certificate
    if (X509_verify_cert(verify_ctx) != 1) {
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        X509_STORE_free(ca_store);
        X509_STORE_CTX_free(verify_ctx);
        PASER_LOG_WRITE_LOG(PASER_LOG_CRYPTO_ERROR, "Certificate is invalid\n");
        return 0;
    } else {
        X509_STORE_free(ca_store);
        X509_STORE_CTX_free(verify_ctx);
        CRYTO_TIME_END
        return 1;
    }

    return 0;
}

