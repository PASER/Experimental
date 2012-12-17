/**
 *\class  		PASER_TU_RREQ
 *@brief       	Class implements PASER_TU_RREQ messages
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

#ifndef PASER_TU_RREQ_H_
#define PASER_TU_RREQ_H_

#include "../config/PASER_defs.h"

#include <list>

#include "PASER_MSG.h"

/**
 * Implementation of PASER_TU_RREQ classes
 */
class PASER_TU_RREQ : public PASER_MSG
{
public:
    u_int32_t keyNr;                            ///< Current number of GTK

    u_int32_t seqForw;                          ///< Sequence number of forwarding node

    uint8_t searchGW;                           ///< search for the gateway
    uint8_t GFlag;                             ///< Gateway flag
    std::list<address_list> AddressRangeList;   ///< Route list from querying node to forwarding node
    uint8_t metricBetweenQueryingAndForw;      ///< Metric for the route between querying node and forwarding node

    lv_block cert;                              ///< Certificate of forwarding node
    u_int32_t nonce;                            ///< Register nonce of sending node
    geo_pos geoQuerying;                        ///< Geographical position of sending node
    geo_pos geoForwarding;                      ///< Geographical position of forwarding node

    uint8_t *secret;                           ///< Secret of forwarding node
    std::list<uint8_t *> auth;                 ///< Authentication path of forwarding node
    uint8_t *hash;                             ///< Hash of the packet

    PASER_TU_RREQ(const PASER_TU_RREQ &m);
    PASER_TU_RREQ(struct in_addr src, struct in_addr dest, u_int32_t seqNr);

    static PASER_TU_RREQ* create(uint8_t *packet, u_int32_t l);

    ~PASER_TU_RREQ();

    PASER_TU_RREQ& operator= (const PASER_TU_RREQ &m);
    virtual PASER_TU_RREQ *dup() const {return new PASER_TU_RREQ(*this);}
    std::string detailedInfo() const;

    uint8_t * toByteArray(int *l);
    uint8_t * getCompleteByteArray(int *l);
private:
    PASER_TU_RREQ();
};

#endif /* PASER_TU_RREQ_H_ */
