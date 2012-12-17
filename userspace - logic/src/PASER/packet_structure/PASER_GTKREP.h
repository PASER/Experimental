/**
 *\class  		PASER_GTKREP
 *@brief       	Class implements GTK-response messages
 *@ingroup		PS
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

#ifndef GTKRESPONSE_H_
#define GTKRESPONSE_H_

#include <arpa/inet.h>

#include "PASER_MSG.h"
#include "../config/PASER_defs.h"

class PASER_GTKREP: public PASER_MSG {
public:
    struct in_addr gwAddr;
    struct in_addr nextHopAddr;

    lv_block gtk; ///< GTK
    int nonce; ///< Nonce of registered nodes
    lv_block crl; ///< CRL
    lv_block kdc_cert; ///< Certificate of KDC
    int kdc_key_nr; ///< GTK number
    lv_block sign_key; ///< Signature of RESET message
    lv_block sign_kdc_block; ///< Signature of KDC Block
    lv_block sign;

public:
    PASER_GTKREP(const PASER_GTKREP &m);
    PASER_GTKREP();
    virtual ~PASER_GTKREP();

    static PASER_GTKREP* create(uint8_t *packet, u_int32_t l);

    PASER_GTKREP& operator=(const PASER_GTKREP &m);
    virtual PASER_GTKREP *dup() const {
        return new PASER_GTKREP(*this);
    }
    std::string detailedInfo() const;

    /**
     * Creates and return an array of all fields that must be secured with signature
     *
     *@param l length of created array
     *@return packet array
     */
    uint8_t * toByteArray(int *l);

    /**
     * Creates and return an array of all fields of the package
     *
     *@param l length of created array
     *@return packet array
     */
    uint8_t * getCompleteByteArray(int *l);
};

#endif /* GTKRESPONSE_H_ */
