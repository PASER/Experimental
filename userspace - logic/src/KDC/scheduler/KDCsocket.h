/**
 *\class  		KDC_socket
 *@brief		Class implements the KDC's socket
 *@ingroup		KDC
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

class KDC_socket;

#ifndef KDCSOCKET_H_
#define KDCSOCKET_H_

#include "../../PASER/config/PASER_defs.h"
#include "../../PASER/syslog/PASER_syslog.h"
#include "../config/KDCdefs.h"
#include "../config/KDCconfig.h"
#include "../crypto/KDCcryptosign.h"

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <map>

class KDC_socket {
private:
    PASER_syslog *log;
    KDC_crypto_sign *crypto;
    int serverSocketFD;

    SSL_CTX* ctx;
    const SSL_METHOD *meth;

    std::map<int, SSL*> socketMap;
public:
    KDC_socket(PASER_syslog *_sysLog,KDC_crypto_sign *_crypto);
    virtual ~KDC_socket();

    int getServerSocketFD();

    lv_block readData(int fd);
    bool writeData(int fd, lv_block data);

    int acceptConnection(int fd);
    bool closeConnection(int fd);

    std::map<int, SSL*> getSocketMap(){return socketMap;}

private:
    char const* crt_strerror(int err);
};

#endif /* KDCSOCKET_H_ */
