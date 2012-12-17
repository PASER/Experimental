/**
 *\class  		PASER_crypto_sign
 *@brief       	Class provides function to compute and check signatures of PASER messages.
 *@ingroup		Cryptography
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

class PASER_crypto_sign;

#ifndef PASER_CRYPTO_SIGN_H_
#define PASER_CRYPTO_SIGN_H_

#include "../config/PASER_defs.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "../packet_structure/PASER_UB_RREQ.h"
#include "../packet_structure/PASER_UU_RREP.h"
#include "../packet_structure/PASER_B_ROOT.h"
#include "../packet_structure/PASER_RESET.h"
#include "../packet_structure/PASER_GTKREP.h"

#include "../config/PASER_global.h"

#include <map>

/**
 * Implementation of PASER_crypto_sign classes.
 */
class PASER_crypto_sign {
private:
    PASER_global* pGlobal; // Pointer to global object

    EVP_PKEY *pkey; 	///< asymmetric private key
    X509 *x509; 		///< own certificate
    X509 *ca_cert; 		///< CA certificate
    X509_CRL *crl; 		///< Certificate Revocation List

public:
    /**
     * Constructor of PASER_crypto_sign Object. Loads own
     * certificate, asymmetric private key and CA certificate.
     *
     *@param certPath Path to the own certificate
     *@param keyPath Path to the asymmetric private key
     *@param CAcertPath Path to the CA certificate
     *@param paser_global Pointer to global object
     *
     *@return nada
     */
    PASER_crypto_sign(char *certPath, char *keyPath, char *CAcertPath, PASER_global * paser_global);
    ~PASER_crypto_sign();

    /**
     * Get own certificate as char array (DER format)
     *
     *@param cert pointer to the lv_block which will be written
     *
     *@return 1 on successful or 0 on error
     */
    int getCert(lv_block *cert);

    /**
     * Convert a X509 certificate from char array (DER format)
     *
     *@param cert lv_block which contains certificate as char array
     *
     *@return certificate on successful or NULL on error
     */
    X509* extractCert(lv_block cert);

    /**
     * Compute a signature from PASER_UB_RREQ packet and
     * write the signature to the packet
     *
     *@param packet pointer to the PASER_TU_RREQ packet
     *
     *@return 1 on successful or 0 on error
     */
    int signUBRREQ(PASER_UB_RREQ * packet);

    /**
     * Check a signature from PASER_UB_RREQ packet
     *
     *@param packet pointer to the PASER_TU_RREQ packet
     *
     *@return 1 on successful or 0 on error
     */
    int checkSignUBRREQ(PASER_UB_RREQ * packet);

    /**
     * Check a signature from kdc_block packet
     *
     *@param data kdc_block
     *
     *@return 1 on successful or 0 on error
     */
    int checkSignKDC(kdc_block data);

    /**
     * Compute a signature from PASER_UU_RREP packet and
     * write the signature to the packet
     *
     *@param packet pointer to the PASER_UU_RREP packet
     *
     *@return 1 on successful or 0 on error
     */
    int signUURREP(PASER_UU_RREP * packet);
    /**
     * Check a signature from PASER_UU_RREP packet
     *
     *@param packet pointer to the PASER_UU_RREP packet
     *
     *@return 1 on successful or 0 on error
     */
    int checkSignUURREP(PASER_UU_RREP * packet);

    /**
     * Compute a signature from PASER_B_ROOT packet and
     * write the signature to the packet
     *
     *@param packet pointer to the PASER_B_ROOT packet
     *
     *@return 1 on successful or 0 on error
     */
    int signB_ROOT(PASER_B_ROOT * packet);
    /**
     * Check a signature from PASER_B_ROOT packet
     *
     *@param packet pointer to the PASER_B_ROOT packet
     *
     *@return 1 on successful or 0 on error
     */
    int checkSignB_ROOT(PASER_B_ROOT * packet);

    /**
     * Check a signature from PASER_RESET packet
     *
     *@param packet pointer to the PASER_RESET packet
     *
     *@return 1 on successful or 0 on error
     */
    int checkSignRESET(PASER_RESET * packet);

    /**
     * Check a signature from PASER_GTKREP packet
     *
     *@param packet pointer to the PASER_GTKREP packet
     *
     *@return 1 on successful or 0 on error
     */
    int checkSignGTKResponse(PASER_GTKREP * packet);

    /**
     * Check if the certificate a Gateway's certificate is
     *
     *@param cert pointer to the certificate
     *
     *@return true on successful or false on error
     */
    bool isGwCert(X509 *cert);

    /**
     * Check if the certificate a KDC's certificate is
     *
     *@param cert pointer to the certificate
     *
     *@return true on successful or false on error
     */
    bool isKdcCert(X509 *cert);

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
     * Decrypt the char array with a own asymmetric private key
     *
     *@param in char array that is to be decrypted
     *@param out pointer to char array which will contain decrypted array
     *
     *@return 1 on successful or 0 on error
     */
    int rsa_dencrypt(lv_block in, lv_block *out);

    /**
     * Set Function to set CRL from char array (DER format)
     *
     *@param in char array which contains CRL (DER format)
     *
     *@return 1 on successful or 0 on error
     */
    int setCRL(lv_block in);

    /**
     * The function checks whether the certificate is valid
     *
     *@param cert pointer to the certificate
     *
     *@return 1 on successful or 0 on error
     */
    int checkOneCert(X509 *cert);

};

#endif /* PASER_CRYPTO_SIGN_H_ */
