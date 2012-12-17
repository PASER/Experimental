/**
 *\class  		PASER_GTKREQ
 *@brief       	Class implements GTK-request messages
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

#ifndef GTKREQUEST_H_
#define GTKREQUEST_H_

#include "PASER_MSG.h"
#include "../config/PASER_defs.h"

#include <arpa/inet.h>

/**
 * The Class provides functions for GTK-requests
 */
class PASER_GTKREQ: public PASER_MSG {

public:
    struct in_addr gwAddr;
    struct in_addr nextHopAddr;

    lv_block cert; ///< Certificate of registered nodes
    int nonce; ///< Nonce of registered nodes

public:
    PASER_GTKREQ(const PASER_GTKREQ &m);
    PASER_GTKREQ();
    virtual ~PASER_GTKREQ();

    /**
     * Get a packet object from incoming data
     *
     *@param packet Pointer to incoming data char array
     *@param l Length of the char array
     *
     *@return true if packet is valid. Else return false.
     */
    static PASER_GTKREQ* create(uint8_t *packet, u_int32_t l);

    PASER_GTKREQ& operator= (const PASER_GTKREQ &m);
    virtual PASER_GTKREQ *dup() const {return new PASER_GTKREQ(*this);}
    std::string detailedInfo() const;

    uint8_t * toByteArray(int *l);
    uint8_t * getCompleteByteArray(int *l);
};

#endif /* GTKREQUEST_H_ */
