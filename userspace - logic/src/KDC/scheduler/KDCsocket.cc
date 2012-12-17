/**
 *\class  		KDC_socket
 *@brief		Class implements the KDC's socket
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "KDCsocket.h"

KDC_socket::KDC_socket(PASER_syslog *_sysLog, KDC_crypto_sign *_crypto) {
    int err;
    log = _sysLog;
    crypto = _crypto;
    struct sockaddr_in sa_serv;

    /* SSL preliminaries. We keep the certificate and key with the context. */

    meth = SSLv3_server_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, PASER_kdc_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, PASER_kdc_cert_key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        exit(1);
    }

    if (!SSL_CTX_load_verify_locations(ctx, PASER_kdc_CA_cert_file, NULL)) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't load CA file\n");
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        exit(1);
    }

    STACK_OF(X509_NAME) *cert_names;

    cert_names = SSL_load_client_CA_file(PASER_kdc_CA_cert_file);
    if (cert_names != NULL)
        SSL_CTX_set_client_CA_list(ctx, cert_names);
    else {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_load_client_CA_file failed\n");
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "Private key does not match the certificate public key\n");
        exit(1);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    /* Set the verification depth to 1 */
    SSL_CTX_set_verify_depth(ctx, 1);

    /* Prepare TCP socket for receiving connections */

    serverSocketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocketFD == -1) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "socket() failed\nError: (%d)%s", errno, strerror(errno));
        exit(1);
    }

    memset(&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons(PASER_PORT_KDC); /* KDC Port number */

    err = bind(serverSocketFD, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
    if (err == -1) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "bind() failed\nError: (%d)%s", errno, strerror(errno));
        exit(1);
    }

    err = listen(serverSocketFD, 5);
    if (err == -1) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "listen() failed\nError: (%d)%s", errno, strerror(errno));
        exit(1);
    }

}

KDC_socket::~KDC_socket() {
    /* Clean up. */
    SSL_CTX_free(ctx);
    close(serverSocketFD);
    for (std::map<int, SSL*>::iterator it = socketMap.begin(); it != socketMap.end(); it++) {
        if (!SSL_get_shutdown(it->second))
            SSL_shutdown(it->second);
        close(it->first);
        SSL_free(it->second);
    }
}

lv_block KDC_socket::readData(int fd) {
    lv_block temp;
    temp.len = 0;
    temp.buf = NULL;
    SSL* ssl;
    std::map<int, SSL*>::iterator it;
    it = socketMap.find(fd);
    if (it == socketMap.end()) {
        return temp;
    }
    ssl = it->second;
    temp.buf = (uint8_t *) malloc(1024 * 5);
    int length = SSL_read(ssl, temp.buf, 1024 * 2 - 1);
    if (length == -1) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_read() failed\n");
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        temp.len = -1;
        free(temp.buf);
        temp.buf = NULL;
        return temp;
    }
    if (length == 0) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_read() failed - Client closed socket\n");
        temp.len = 0;
        free(temp.buf);
        temp.buf = NULL;
        return temp;
    }
    temp.len = length;
    temp.buf[temp.len] = '\0';
    return temp;
}

bool KDC_socket::writeData(int fd, lv_block data) {
    if (!data.buf) {
        return false;
    }
    SSL* ssl;
    std::map<int, SSL*>::iterator it;
    it = socketMap.find(fd);
    if (it == socketMap.end()) {
        free(data.buf);
        return false;
    }
    ssl = it->second;
    int err = SSL_write(ssl, data.buf, data.len);
    if (err == -1) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_write() failed\n");
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        free(data.buf);
        return false;
    }
    free(data.buf);
    return true;
}

int KDC_socket::acceptConnection(int fd) {
    SSL* ssl;
    size_t client_len;
    struct sockaddr_in sa_cli;
    int tempSocket;
    int err;
    X509* client_cert;
    char* str;

    client_len = sizeof(sa_cli);
    tempSocket = accept(fd, (struct sockaddr*) &sa_cli, &client_len);
    if (tempSocket == -1) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "accept() failed\nError: (%d)%s", errno, strerror(errno));
        return -1;
    }
    KDC_LOG_WRITE_LOG(PASER_LOG_CONNECTION, "Connection from %s, port %d\n", inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));
    printf("Connection from %s, port %d\n", inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));

    /* ----------------------------------------------- */
    /* TCP connection is ready. Do server side SSL. */

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL_new() failed\n");
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_new() failed\n");
        close(tempSocket);
        return -1;
    }

    SSL_set_fd(ssl, tempSocket);
    err = SSL_accept(ssl);
    if (err == -1) {
        printf("SSL_accept() failed\n");
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_accept() failed\n");
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        close(tempSocket);
        SSL_free(ssl);
        return -1;
    }

    /* Get the cipher - opt */

    printf("SSL connection using %s, err = %d\n", SSL_get_cipher(ssl), err);
    KDC_LOG_WRITE_LOG(PASER_LOG_CONNECTION, "SSL connection using %s\n", SSL_get_cipher(ssl));

    /* Get client's certificate (note: beware of dynamic allocation) - opt */

    client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert == NULL) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_get_peer_certificate() failed\n");
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        SSL_free(ssl);
        return -1;
    }

    if (!crypto->checkOneCert(client_cert)) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "checkOneCert() failed\n");
        ERR_print_errors_fp(KDC_LOG_GET_FD);
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        X509_free(client_cert);
        SSL_free(ssl);
        return -1;
    }

    err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_get_verify_result() failed: %s(%d)\n", crt_strerror(err), err);
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        X509_free(client_cert);
        SSL_free(ssl);
        return -1;
    }

    str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
    if (str == NULL) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "X509_get_subject_name() failed\n");
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        X509_free(client_cert);
        SSL_free(ssl);
        return -1;
    }
    KDC_LOG_WRITE_LOG(PASER_LOG_CONNECTION, "\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
    if (str == NULL) {
        KDC_LOG_WRITE_LOG(PASER_LOG_ERROR, "X509_get_issuer_name() failed\n");
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        X509_free(client_cert);
        SSL_free(ssl);
        return -1;
    }
    KDC_LOG_WRITE_LOG(PASER_LOG_CONNECTION, "\t issuer: %s\n", str);
    OPENSSL_free(str);
    KDC_LOG_WRITE_LOG(PASER_LOG_CONNECTION, "OPENSSL_free(str)\n");

    /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

    X509_free(client_cert);
    KDC_LOG_WRITE_LOG(PASER_LOG_CONNECTION, "X509_free(client_cert)\n");

    socketMap.insert(std::make_pair(tempSocket, ssl));
    return tempSocket;
}

bool KDC_socket::closeConnection(int fd) {
    KDC_LOG_WRITE_LOG(PASER_LOG_CONNECTION, "Close Socket %d.\n", fd);
    SSL* ssl;
    std::map<int, SSL*>::iterator it;
    it = socketMap.find(fd);
    if (it == socketMap.end()) {
        return false;
    }
    ssl = it->second;
    if (!SSL_get_shutdown(ssl))
        SSL_shutdown(ssl);
    close(fd);
    SSL_free(ssl);
    socketMap.erase(it);
    return true;
}

int KDC_socket::getServerSocketFD() {
    return serverSocketFD;
}

char const* KDC_socket::crt_strerror(int err) {
    switch (err) {
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        return "UNABLE_TO_DECRYPT_CERT_SIGNATURE";

    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        return "UNABLE_TO_DECRYPT_CRL_SIGNATURE";

    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        return "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";

    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        return "CERT_SIGNATURE_FAILURE";

    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        return "CRL_SIGNATURE_FAILURE";

    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        return "ERROR_IN_CERT_NOT_BEFORE_FIELD";

    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        return "ERROR_IN_CERT_NOT_AFTER_FIELD";

    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
        return "ERROR_IN_CRL_LAST_UPDATE_FIELD";

    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
        return "ERROR_IN_CRL_NEXT_UPDATE_FIELD";

    case X509_V_ERR_CERT_NOT_YET_VALID:
        return "CERT_NOT_YET_VALID";

    case X509_V_ERR_CERT_HAS_EXPIRED:
        return "CERT_HAS_EXPIRED";

    case X509_V_ERR_OUT_OF_MEM:
        return "OUT_OF_MEM";

    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        return "UNABLE_TO_GET_ISSUER_CERT";

    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        return "UNABLE_TO_GET_ISSUER_CERT_LOCALLY";

    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        return "UNABLE_TO_VERIFY_LEAF_SIGNATURE";

    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        return "DEPTH_ZERO_SELF_SIGNED_CERT";

    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        return "SELF_SIGNED_CERT_IN_CHAIN";

    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
        return "CERT_CHAIN_TOO_LONG";

    case X509_V_ERR_CERT_REVOKED:
        return "CERT_REVOKED";

    case X509_V_ERR_INVALID_CA:
        return "INVALID_CA";

    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        return "PATH_LENGTH_EXCEEDED";

    case X509_V_ERR_INVALID_PURPOSE:
        return "INVALID_PURPOSE";

    case X509_V_ERR_CERT_UNTRUSTED:
        return "CERT_UNTRUSTED";

    case X509_V_ERR_CERT_REJECTED:
        return "CERT_REJECTED";

    case X509_V_ERR_UNABLE_TO_GET_CRL:
        return "UNABLE_TO_GET_CRL";

    case X509_V_ERR_CRL_NOT_YET_VALID:
        return "CRL_NOT_YET_VALID";

    case X509_V_ERR_CRL_HAS_EXPIRED:
        return "CRL_HAS_EXPIRED";
    }

    return "Unknown verify error";
}
