/**
 *\class  		KDC_crypto_sign
 *@brief		Class provides functions to handle with GTK messages
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

#include "KDCcryptosign.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

KDC_crypto_sign::KDC_crypto_sign(KDC_config *conf) {
    FILE *fp;

    // load CRL
    fp = fopen(conf->getCrlfile(), "r");
    if (fp == NULL) {
        printf("Cann't open CRL file: %s", conf->getCrlfile());
        exit(1);
    }
    crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
    fclose(fp);
    if (crl == NULL) {
        printf("Cann't read CRL from file: %s", conf->getCrlfile());
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if ((convertCRLtoDER()) != 1) {
        printf("cann't convert CRL to DER format\n");
        exit(1);
    }

    // Set GTK
    key_nr = 0;

    resetGTK();

    // read certificate
    fp = fopen(conf->getCertfile(), "r");
    if (fp == NULL) {
        printf("Cann't open KDC certificate file: %s", conf->getCertfile());
        exit(1);
    }
    x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (x509 == NULL) {
        printf("Cann't read KDC certificate from file: %s", conf->getCertfile());
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if ((convertCertToDER()) != 1) {
        printf("cann't convert KDC certificate to DER format\n");
        exit(1);
    }

    // read private key
    fp = fopen(conf->getKeyfile(), "r");
    if (fp == NULL) {
        printf("Cann't open private key file: %s", conf->getKeyfile());
        exit(1);
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if(pkey == NULL){
        printf("Cann't read private key from file: %s", conf->getCertfile());
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    fclose(fp);

    // read CA_file
    fp = fopen(conf->getCafile(), "r");
    if (fp == NULL) {
        printf("Cann't open CA certificate file: %s", conf->getCafile());
        exit(1);
    }
    ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (ca_cert == NULL) {
        printf("Cann't read CA certificate from file: %s", conf->getCafile());
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if(computeRESETSign() != 1){
        printf("Cann't compute signature of RESET message.");
        exit(1);
    }
}

KDC_crypto_sign::~KDC_crypto_sign() {
    EVP_PKEY_free(pkey);
    X509_free(x509);
    free(x509_DER.buf);
    X509_free(ca_cert);
    X509_CRL_free(crl);
    free(crl_DER.buf);
    free(sign_key.buf);
    free(GTK.buf);
}

int KDC_crypto_sign::convertCRLtoDER(){
    int len;
    unsigned char *buf;
    buf = NULL;
    len = i2d_X509_CRL(crl, &buf);
    if (len < 0){
        return 0;
    }
    u_int8_t *buf_cert = (u_int8_t *)malloc(sizeof(u_int8_t) * len);
    memcpy(buf_cert, buf, (sizeof(u_int8_t) * len));
    crl_DER.buf = buf_cert;
    crl_DER.len = len;
#ifdef __unix__
    free(buf);
#endif
    return 1;
}

int KDC_crypto_sign::convertCertToDER(){
    int len;
    unsigned char *buf;
    buf = NULL;
    len = i2d_X509(x509, &buf);
    if (len < 0){
        return 0;
    }
    u_int8_t *buf_cert = (u_int8_t *)malloc(sizeof(u_int8_t) * len);
    memcpy(buf_cert, buf, (sizeof(u_int8_t) * len));
    x509_DER.buf = buf_cert;
    x509_DER.len = len;
#ifdef __unix__
    free(buf);
#endif
    return 1;
}

void KDC_crypto_sign::resetGTK(){
    key_nr++;
    int GTK_length = 80;
    uint8_t *gtkKey = (uint8_t *) malloc(GTK_length);
    RAND_bytes(gtkKey, GTK_length);
    GTK.buf = gtkKey;
    GTK.len = GTK_length;
}

int KDC_crypto_sign::computeRESETSign(){
    u_int32_t sig_len = PASER_sign_len;
    u_int8_t *sign = (u_int8_t *)malloc(sizeof(u_int8_t) * sig_len);
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_SignInit   (md_ctx, EVP_sha1());

    EVP_SignUpdate(md_ctx, &key_nr, sizeof(key_nr));

    EVP_SignUpdate(md_ctx, &x509_DER.len, sizeof(x509_DER.len));
    EVP_SignUpdate(md_ctx, x509_DER.buf, x509_DER.len);

    int err = EVP_SignFinal (md_ctx, sign, &sig_len, pkey);
    EVP_MD_CTX_destroy(md_ctx);
    if (err != 1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    sign_key.buf = sign;
    sign_key.len = sig_len;
    return 1;
}

lv_block KDC_crypto_sign::getRESETSignCopy(){
    lv_block temp;
    temp.len = sign_key.len;
    temp.buf = (uint8_t *)malloc(sign_key.len);
    memcpy(temp.buf, sign_key.buf, sign_key.len);
    return temp;
}

lv_block KDC_crypto_sign::getKDCCert(){
    lv_block temp;
    temp.len = x509_DER.len;
    temp.buf = (uint8_t *)malloc(x509_DER.len);
    memcpy(temp.buf, x509_DER.buf, x509_DER.len);
    return temp;
}

lv_block KDC_crypto_sign::getGTK(){
    return GTK;
}

int KDC_crypto_sign::getGTKnumber(){
    return key_nr;
}

int KDC_crypto_sign::checkSignRequest(PASER_GTKREQ * packet){
    X509 *x;
    const u_int8_t *buf, *p;
    int len;
    buf = packet->cert.buf;
    len = packet->cert.len;
    p = buf;
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (checkOneCert(x) != 1) {
        X509_free(x);
        return 0;
    }
//    EVP_PKEY *pubKey = X509_get_pubkey(x);
    X509_free(x);
//    u_int32_t sig_len = packet->sign.len;
//    u_int8_t *sign = packet->sign.buf;
//    EVP_MD_CTX *md_ctx;
//    md_ctx = EVP_MD_CTX_create();
//    EVP_VerifyInit(md_ctx, EVP_sha1());
//
//    int packet_len = 0;
//    u_int8_t *data = packet->toByteArray(&packet_len);
//    EVP_VerifyUpdate(md_ctx, data, packet_len);
//    free(data);
//
//    int err = EVP_VerifyFinal(md_ctx, sign, sig_len, pubKey);
//    EVP_PKEY_free(pubKey);
//    EVP_MD_CTX_destroy(md_ctx);
//
//    if (err != 1) {
//        ERR_print_errors_fp(stderr);
//        return 0;
//    }
    return 1;
}

PASER_GTKREP* KDC_crypto_sign::generateGTKReasponse(PASER_GTKREQ * packet){
    PASER_GTKREP* pack = new PASER_GTKREP();
    pack->srcAddress_var.s_addr = packet->srcAddress_var.s_addr;
    pack->gwAddr.s_addr = packet->gwAddr.s_addr;
    pack->nextHopAddr.s_addr = packet->nextHopAddr.s_addr;

    X509 *x;
    const u_int8_t *buf, *p;
    int len;
    buf = packet->cert.buf;
    len = packet->cert.len;
    p = buf;
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    rsa_encrypt(GTK, &pack->gtk, x);
    X509_free(x);
    pack->nonce = packet->nonce;

    pack->crl.len = crl_DER.len;
    pack->crl.buf = (uint8_t *)malloc(crl_DER.len);
    memcpy(pack->crl.buf, crl_DER.buf, crl_DER.len);

    pack->kdc_cert.len = x509_DER.len;
    pack->kdc_cert.buf = (uint8_t *)malloc(x509_DER.len);
    memcpy(pack->kdc_cert.buf, x509_DER.buf, x509_DER.len);

    pack->kdc_key_nr = key_nr;

    pack->sign_key = getRESETSignCopy();

    computeSignOfKDCBlock(pack);
    signResponse(pack);

    return pack;
}

int KDC_crypto_sign::rsa_encrypt(lv_block in, lv_block *out, X509 *cert){
    if(!cert){
        return 0;
    }
    EVP_PKEY *pubKey;
    pubKey = X509_get_pubkey(cert);

    RSA *rsa = EVP_PKEY_get1_RSA(pubKey);
    out->buf = (u_int8_t *)malloc( RSA_size(rsa) );
    int i = RSA_public_encrypt(in.len, in.buf, out->buf, rsa, RSA_PKCS1_PADDING);
    out->len = i;
    EVP_PKEY_free (pubKey);
    RSA_free(rsa);
    if(i<0){
        return 0;
    }
    return 1;
}

int KDC_crypto_sign::signResponse(PASER_GTKREP * packet){
    u_int32_t sig_len = PASER_sign_len;
    u_int8_t *sign = (u_int8_t *)malloc(sizeof(u_int8_t) * sig_len);
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_SignInit   (md_ctx, EVP_sha1());

    int len = 0;
    u_int8_t *data = packet->toByteArray(&len);
    EVP_SignUpdate (md_ctx, data, len);
    free(data);

    int err = EVP_SignFinal (md_ctx, sign, &sig_len, pkey);
    EVP_MD_CTX_destroy(md_ctx);
    if (err != 1) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if(packet->sign.len != 0){
        free(packet->sign.buf);
    }
    packet->sign.buf = sign;
    packet->sign.len = sig_len;

    return 1;
}

int KDC_crypto_sign::checkOneCert(X509 *cert){
    X509_STORE *ca_store;
    ca_store = X509_STORE_new();
    if(X509_STORE_add_cert(ca_store, ca_cert)!=1){
        ERR_print_errors_fp (stderr);
        return 0;
    }
    if (X509_STORE_set_default_paths(ca_store) != 1) {
        ERR_print_errors_fp (stderr);
        return 0;
    }
    if(crl){
        if(X509_STORE_add_crl(ca_store, crl)!=1){
            ERR_print_errors_fp (stderr);
            return 0;
        }
    #if (OPENSSL_VERSION_NUMBER > 0x00907000L)
        //set the flag of the store so that CRLs are consulted
        X509_STORE_set_flags(ca_store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL );
    #endif
    }

    X509_STORE_CTX  *verify_ctx;
    // create a verification context and initialize it
    if(!(verify_ctx = X509_STORE_CTX_new())){
        ERR_print_errors_fp (stderr);
        return 0;
    }
    //X509_STORE_CTX_init did not return an error condition in prior versions
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
    if(X509_STORE_CTX_init(verify_ctx, ca_store, cert, NULL) != 1){
        ERR_print_errors_fp (stderr);
        return 0;
    }
#else
    X509_STORE_CTX_init(verify_ctx, ca_store, cert, NULL);
#endif

    //verify the certificate
    if(X509_verify_cert(verify_ctx)!=1){
        ERR_print_errors_fp (stderr);
        X509_STORE_free(ca_store);
        X509_STORE_CTX_free(verify_ctx);
        return 0;
    }
    else{
        X509_STORE_free(ca_store);
        X509_STORE_CTX_free(verify_ctx);
        return 1;
    }

    return 0;
}

int KDC_crypto_sign::computeSignOfKDCBlock(PASER_GTKREP* packet){
    //sign
    u_int32_t sig_len = PASER_sign_len;
    u_int8_t *sign = (u_int8_t *)malloc(sizeof(u_int8_t) * sig_len);
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();
    EVP_SignInit   (md_ctx, EVP_sha1());
    int kdc_data_len = packet->gtk.len + sizeof(packet->nonce) + sizeof(packet->kdc_key_nr)
            + packet->crl.len + packet->kdc_cert.len;
    u_int8_t *temp = (u_int8_t*)malloc(kdc_data_len);
    u_int8_t *tempData = temp;
    memcpy(temp, (u_int8_t *)packet->gtk.buf, packet->gtk.len);
    temp += packet->gtk.len;
    memcpy(temp, (u_int8_t *)&packet->nonce, sizeof(packet->nonce));
    temp += sizeof(packet->nonce);
    memcpy(temp, (u_int8_t *)&packet->kdc_key_nr, sizeof(packet->kdc_key_nr));
    temp += sizeof(packet->kdc_key_nr);
    memcpy(temp, (u_int8_t *)packet->crl.buf, packet->crl.len);
    temp += packet->crl.len;
    memcpy(temp, (u_int8_t *)packet->kdc_cert.buf, packet->kdc_cert.len);
    temp += packet->kdc_cert.len;
    EVP_SignUpdate(md_ctx, tempData, kdc_data_len);
    free(tempData);
    int err = EVP_SignFinal (md_ctx, sign, &sig_len, pkey);
    EVP_MD_CTX_destroy(md_ctx);
    if (err != 1) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    packet->sign_kdc_block.buf = sign;
    packet->sign_kdc_block.len = sig_len;
    return 1;
}
