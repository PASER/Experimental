/**
 *\class  		KDC_crypto_sign
 *@brief 		Class provides functions to handle with GTK messages
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

#ifndef CRYPTOSIGN_H_
#define CRYPTOSIGN_H_

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "../../PASER/config/PASER_defs.h"
#include "../config/KDCdefs.h"
#include "../config/KDCconfig.h"
#include "../../PASER/packet_structure/PASER_GTKREQ.h"
#include "../../PASER/packet_structure/PASER_GTKREP.h"

class KDC_crypto_sign {
private:
    EVP_PKEY *pkey;         ///< asymmetric private key
    X509 *x509;             ///< own certificate
    lv_block x509_DER;      ///< own certificate (DER format)
    X509 *ca_cert;          ///< CA certificate
    X509_CRL *crl;          ///< Certificate Revocation List
    lv_block crl_DER;       ///< Certificate Revocation List (DER format)
    lv_block sign_key;      ///< Signature of RESET message
    int key_nr;             ///< Number of GTK
    lv_block GTK;           ///< GTK

public:
    KDC_crypto_sign(KDC_config *conf);
    virtual ~KDC_crypto_sign();

    void resetGTK(); ///< Generate a new GTK
    lv_block getRESETSignCopy(); ///< Get copy of RESET Message's signature
    lv_block getKDCCert(); ///< Get copy of certificate (DER format)
    lv_block getGTK(); ///< Get GTK
    int getGTKnumber(); ///< Get GTK number
    lv_block getCRL(); ///< Get CRL as DER format.
    lv_block getsign_key(); ///< Get signature of RESET message as DER format

    /**
     * Check a signature from PASER_GTKREQ packet
     *
     *@param packet pointer to the PASER_GTKREQ packet
     *
     *@return 1 on successful or 0 on error
     */
    int checkSignRequest(PASER_GTKREQ * packet);

    /**
     * Compute a signature from PASER_GTKREP packet and
     * write the signature to the packet
     *
     *@param packet pointer to the PASER_GTKREP packet
     *
     *@return 1 on successful or 0 on error
     */
    int signResponse(PASER_GTKREP * packet);

    /**
     * Generate PASER_GTKREP packet from PASER_GTKREQ packet.
     * @warning PASER_GTKREQ packet will not be checked for authenticity.
     * To check for authenticity use checkSignRequest function.
     *
     * @param packet
     * @return
     */
    PASER_GTKREP* generateGTKReasponse(PASER_GTKREQ * packet);

    /**
     * Encrypt the char array with a public key of given certificate
     *
     *@param in char array that is to be encrypted
     *@param out pointer to char array which will contain encrypted array
     *@param cert pointer to the certificate
     *
     *@return 1 on successful or 0 on error
     */
    int rsa_encrypt(lv_block in, lv_block *out, X509 *cert);

    /**
     * Convert a X509 certificate from char array (DER format)
     *
     *@param cert lv_block which contains certificate as char array
     *
     *@return certificate on successful or NULL on error
     */
    X509* extractCert(lv_block cert);

    /**
     * The function checks whether the certificate is valid
     *
     *@param cert pointer to the certificate
     *
     *@return 1 on successful or 0 on error
     */
    int checkOneCert(X509 *cert);

private:

    /**
     * Convert CRL/Certificate to DER format
     *
     *@return 1 on successful or 0 on error
     */
    int convertCRLtoDER();
    int convertCertToDER();

    /**
     * Compute RESET signature
     *
     *@return 1 on successful or 0 on error
     */
    int computeRESETSign();

    int computeSignOfKDCBlock(PASER_GTKREP* packet);
};

#endif /* CRYPTOSIGN_H_ */
