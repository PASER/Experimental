/**
 *\class  		PASER_TU_RREP
 *@brief       	Class implements PASER_TU_RREP messages
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

#ifndef PASER_TU_RREP_H_
#define PASER_TU_RREP_H_

#include "../config/PASER_defs.h"
#include "PASER_MSG.h"

#include <list>
#include <stdlib.h>
#include <string.h>


/**
 * Implementation of PASER_TU_RREP classes
 */
class PASER_TU_RREP : public PASER_MSG
{
public:
    u_int32_t keyNr;                            ///</ Current number of GTK

    uint8_t searchGW;                           ///</ search for the gateway
    uint8_t GFlag;                             	///</ Gateway flag
    std::list<address_list> AddressRangeList;   ///</ Route list from querying node to forwarding node

    uint8_t metricBetweenQueryingAndForw;      	///< Metric for the route between querying node and forwarding node
    uint8_t metricBetweenDestAndForw;          ///< Metric for the route between destination node and forwarding node

    kdc_block kdc_data;                         ///< KDC Block

    geo_pos geoDestination;                     ///< Geographical position of destination node
    geo_pos geoForwarding;                      ///< Geographical position of forwarding node

    uint8_t *secret;                           ///< Secret of forwarding node
    std::list<uint8_t *> auth;                 ///< Authentication path of forwarding node
    uint8_t *hash;                             ///< Hash of the packet

    PASER_TU_RREP(const PASER_TU_RREP &m);
    PASER_TU_RREP(struct in_addr src, struct in_addr dest, int seqNr);

    static PASER_TU_RREP* create(uint8_t *packet, u_int32_t l);

    ~PASER_TU_RREP();

    PASER_TU_RREP& operator= (const PASER_TU_RREP &m);
    virtual PASER_TU_RREP *dup() const {return new PASER_TU_RREP(*this);}
    std::string detailedInfo() const;

    uint8_t * toByteArray(int *l);

    uint8_t * getCompleteByteArray(int *l);
private:
    PASER_TU_RREP();
};

#endif /* PASER_TU_RREP_H_ */
